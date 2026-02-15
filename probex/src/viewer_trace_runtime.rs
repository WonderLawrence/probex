use crate::{TraceCommandConfig, run_trace_command, viewer_backend};
use probex_common::viewer_api::{
    CustomProbeFieldRef, CustomProbeFilter, CustomProbeFilterOp, CustomProbeSpec, ProbeSchema,
    ProbeSchemaKind, StartTraceRequest, TraceRunStatus, TraceRunStatusResponse,
};
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, watch};

use anyhow::Result as AnyhowResult;

type RuntimeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

static RUNTIME_STATE: OnceLock<Mutex<TraceRuntimeState>> = OnceLock::new();

struct ActiveTraceRun {
    run_id: u64,
    command: Vec<String>,
    output_parquet: String,
    started_at_unix_ms: u64,
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<AnyhowResult<crate::TraceCommandOutcome>>,
}

#[derive(Debug, Clone)]
struct FinishedTraceRun {
    run_id: u64,
    command: Vec<String>,
    output_parquet: String,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    exit_code: i32,
    success: bool,
    error: Option<String>,
}

#[derive(Default)]
struct TraceRuntimeState {
    next_run_id: u64,
    sequence: u64,
    active: Option<ActiveTraceRun>,
    finished: Option<FinishedTraceRun>,
}

fn state() -> &'static Mutex<TraceRuntimeState> {
    RUNTIME_STATE.get_or_init(|| Mutex::new(TraceRuntimeState::default()))
}

fn now_unix_ms() -> RuntimeResult<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| IoError::other(format!("system clock before unix epoch: {error}")))?;
    Ok(now.as_millis() as u64)
}

fn to_status(
    active: Option<&ActiveTraceRun>,
    finished: Option<&FinishedTraceRun>,
) -> TraceRunStatus {
    if let Some(active) = active {
        return TraceRunStatus::Running {
            run_id: active.run_id,
            command: active.command.clone(),
            output_parquet: active.output_parquet.clone(),
            started_at_unix_ms: active.started_at_unix_ms,
        };
    }
    if let Some(finished) = finished {
        return TraceRunStatus::Finished {
            run_id: finished.run_id,
            command: finished.command.clone(),
            output_parquet: finished.output_parquet.clone(),
            started_at_unix_ms: finished.started_at_unix_ms,
            finished_at_unix_ms: finished.finished_at_unix_ms,
            exit_code: finished.exit_code,
            success: finished.success,
            error: finished.error.clone(),
        };
    }
    TraceRunStatus::Idle
}

fn to_status_response(state: &TraceRuntimeState) -> TraceRunStatusResponse {
    TraceRunStatusResponse {
        sequence: state.sequence,
        status: to_status(state.active.as_ref(), state.finished.as_ref()),
    }
}

fn mark_state_changed(state: &mut TraceRuntimeState) {
    state.sequence = state.sequence.saturating_add(1);
}

#[derive(Clone, Copy)]
enum FilterValueKind {
    Integer,
    Boolean,
    StringLike,
    Address,
}

fn infer_filter_kind(ty: &str) -> FilterValueKind {
    let lowered = ty.to_ascii_lowercase();
    if lowered.contains("bool") {
        return FilterValueKind::Boolean;
    }
    if lowered.contains("char") && lowered.contains('*') {
        return FilterValueKind::StringLike;
    }
    if lowered.contains("string") {
        return FilterValueKind::StringLike;
    }
    if lowered.contains('*')
        || lowered.contains("ptr")
        || lowered.contains("addr")
        || lowered.contains("void *")
    {
        return FilterValueKind::Address;
    }
    FilterValueKind::Integer
}

fn filter_op_requires_value(op: &CustomProbeFilterOp) -> bool {
    !matches!(
        op,
        CustomProbeFilterOp::IsNull | CustomProbeFilterOp::IsNotNull
    )
}

fn validate_filter_op_for_kind(op: &CustomProbeFilterOp, kind: FilterValueKind) -> bool {
    match kind {
        FilterValueKind::Integer => matches!(
            op,
            CustomProbeFilterOp::Eq
                | CustomProbeFilterOp::Ne
                | CustomProbeFilterOp::Gt
                | CustomProbeFilterOp::Ge
                | CustomProbeFilterOp::Lt
                | CustomProbeFilterOp::Le
        ),
        FilterValueKind::Boolean => matches!(op, CustomProbeFilterOp::Eq | CustomProbeFilterOp::Ne),
        FilterValueKind::StringLike => matches!(
            op,
            CustomProbeFilterOp::Eq
                | CustomProbeFilterOp::Ne
                | CustomProbeFilterOp::Contains
                | CustomProbeFilterOp::StartsWith
                | CustomProbeFilterOp::EndsWith
        ),
        FilterValueKind::Address => matches!(
            op,
            CustomProbeFilterOp::Eq
                | CustomProbeFilterOp::Ne
                | CustomProbeFilterOp::IsNull
                | CustomProbeFilterOp::IsNotNull
        ),
    }
}

fn resolve_field_type<'a>(
    schema: &'a ProbeSchema,
    field_ref: &CustomProbeFieldRef,
) -> Option<&'a str> {
    match field_ref {
        CustomProbeFieldRef::Field { name } => schema
            .fields
            .iter()
            .find(|field| &field.name == name)
            .map(|field| field.field_type.as_str()),
        CustomProbeFieldRef::Arg { name } => schema
            .args
            .iter()
            .find(|arg| &arg.name == name)
            .map(|arg| arg.arg_type.as_str()),
        CustomProbeFieldRef::Return => schema.return_type.as_deref(),
    }
}

fn describe_field_ref(field_ref: &CustomProbeFieldRef) -> String {
    match field_ref {
        CustomProbeFieldRef::Field { name } => format!("field:{name}"),
        CustomProbeFieldRef::Arg { name } => format!("arg:{name}"),
        CustomProbeFieldRef::Return => "ret".to_string(),
    }
}

fn validate_filter(
    schema: &ProbeSchema,
    probe_display_name: &str,
    filter: &CustomProbeFilter,
) -> RuntimeResult<()> {
    let ty = resolve_field_type(schema, &filter.field).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "custom probe '{probe_display_name}' references unknown filter field '{}'",
                describe_field_ref(&filter.field)
            ),
        )
    })?;
    let kind = infer_filter_kind(ty);
    if !validate_filter_op_for_kind(&filter.op, kind) {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "custom probe '{probe_display_name}' uses incompatible operator '{:?}' for filter field '{}'",
                filter.op,
                describe_field_ref(&filter.field)
            ),
        )
        .into());
    }
    if filter_op_requires_value(&filter.op) {
        let value = filter.value.as_deref().ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!(
                    "custom probe '{probe_display_name}' filter '{}' requires a value",
                    describe_field_ref(&filter.field)
                ),
            )
        })?;
        if value.trim().is_empty() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!(
                    "custom probe '{probe_display_name}' filter '{}' requires a non-empty value",
                    describe_field_ref(&filter.field)
                ),
            )
            .into());
        }
    } else if filter.value.is_some() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "custom probe '{probe_display_name}' filter '{}' must not set a value for operator '{:?}'",
                describe_field_ref(&filter.field),
                filter.op
            ),
        )
        .into());
    }
    Ok(())
}

async fn validate_custom_probes(specs: &[CustomProbeSpec]) -> RuntimeResult<()> {
    let mut seen_display_names = HashSet::new();
    for spec in specs {
        if spec.probe_display_name.trim().is_empty() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "custom probe display_name must not be empty",
            )
            .into());
        }
        if !seen_display_names.insert(spec.probe_display_name.clone()) {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!(
                    "duplicate custom probe in trace request: '{}'",
                    spec.probe_display_name
                ),
            )
            .into());
        }

        let schema = viewer_backend::query_probe_schema_detail(spec.probe_display_name.clone())
            .await
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "failed to resolve custom probe '{}': {error}",
                        spec.probe_display_name
                    ),
                )
            })?;

        for field_ref in &spec.record_fields {
            if schema.kind == ProbeSchemaKind::Fentry
                && matches!(field_ref, CustomProbeFieldRef::Return)
            {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "custom probe '{}' cannot record 'ret' for fentry probes",
                        spec.probe_display_name
                    ),
                )
                .into());
            }
            if resolve_field_type(&schema, field_ref).is_none() {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "custom probe '{}' references unknown record field '{}'",
                        spec.probe_display_name,
                        describe_field_ref(field_ref)
                    ),
                )
                .into());
            }
        }

        for filter in &spec.filters {
            if schema.kind == ProbeSchemaKind::Fentry
                && matches!(filter.field, CustomProbeFieldRef::Return)
            {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "custom probe '{}' cannot filter on 'ret' for fentry probes",
                        spec.probe_display_name
                    ),
                )
                .into());
            }
            validate_filter(&schema, &spec.probe_display_name, filter)?;
        }
    }
    Ok(())
}

async fn refresh_active_run(state: &mut TraceRuntimeState) -> RuntimeResult<()> {
    let is_finished = state
        .active
        .as_ref()
        .is_some_and(|active| active.task.is_finished());
    if !is_finished {
        return Ok(());
    }

    let active = state
        .active
        .take()
        .ok_or_else(|| IoError::other("active trace run missing while refreshing"))?;
    let finished_at_unix_ms = now_unix_ms()?;

    let finished = match active.task.await {
        Ok(Ok(outcome)) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: outcome.output_path,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 0,
            success: true,
            error: None,
        },
        Ok(Err(error)) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: active.output_parquet,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 1,
            success: false,
            error: Some(error.to_string()),
        },
        Err(error) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: active.output_parquet,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 1,
            success: false,
            error: Some(format!("trace task failed: {error}")),
        },
    };

    state.finished = Some(finished);
    mark_state_changed(state);
    Ok(())
}

pub fn initialize() -> RuntimeResult<()> {
    let _ = state();
    Ok(())
}

pub async fn status_wait(
    last_sequence: Option<u64>,
    wait_ms: Option<u64>,
) -> RuntimeResult<TraceRunStatusResponse> {
    let max_wait_ms = wait_ms.unwrap_or(0).min(10_000);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_wait_ms);

    loop {
        {
            let mut state = state().lock().await;
            refresh_active_run(&mut state).await?;
            let response = to_status_response(&state);
            if last_sequence.is_none_or(|seq| seq != response.sequence) {
                return Ok(response);
            }
            if max_wait_ms == 0 || std::time::Instant::now() >= deadline {
                return Ok(response);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

pub async fn start(request: StartTraceRequest) -> RuntimeResult<TraceRunStatusResponse> {
    if request.program.trim().is_empty() {
        return Err(IoError::new(ErrorKind::InvalidInput, "program must not be empty").into());
    }
    if request.output_parquet.trim().is_empty() {
        return Err(
            IoError::new(ErrorKind::InvalidInput, "output_parquet must not be empty").into(),
        );
    }
    if request.sample_freq_hz == 0 {
        return Err(IoError::new(ErrorKind::InvalidInput, "sample_freq_hz must be > 0").into());
    }
    validate_custom_probes(&request.custom_probes).await?;

    let mut state = state().lock().await;
    refresh_active_run(&mut state).await?;
    if state.active.is_some() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            "a trace run is already in progress",
        )
        .into());
    }

    let run_id = state.next_run_id;
    state.next_run_id = state.next_run_id.saturating_add(1);
    let started_at_unix_ms = now_unix_ms()?;

    let mut traced_command = Vec::with_capacity(request.args.len() + 1);
    traced_command.push(request.program.clone());
    traced_command.extend(request.args.clone());

    let (stop_tx, stop_rx) = watch::channel(false);
    let config = TraceCommandConfig {
        output: request.output_parquet.clone(),
        sample_freq_hz: request.sample_freq_hz,
        program: request.program,
        args: request.args,
        custom_probes: request.custom_probes,
    };
    let task = tokio::spawn(async move { run_trace_command(config, Some(stop_rx), false).await });

    state.finished = None;
    state.active = Some(ActiveTraceRun {
        run_id,
        command: traced_command,
        output_parquet: request.output_parquet,
        started_at_unix_ms,
        stop_tx,
        task,
    });
    mark_state_changed(&mut state);
    Ok(to_status_response(&state))
}

pub async fn stop() -> RuntimeResult<TraceRunStatusResponse> {
    let mut state = state().lock().await;
    refresh_active_run(&mut state).await?;
    let Some(active) = state.active.as_ref() else {
        return Ok(to_status_response(&state));
    };
    let _ = active.stop_tx.send(true);
    mark_state_changed(&mut state);
    Ok(to_status_response(&state))
}

pub async fn load_trace(parquet_path: &Path) -> RuntimeResult<()> {
    viewer_backend::load_trace_file(parquet_path.to_path_buf()).await
}
