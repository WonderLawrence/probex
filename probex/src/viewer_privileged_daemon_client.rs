use crate::{TraceCommandConfig, TraceCommandOutcome};
use anyhow::{Context as _, Result, anyhow};
use probex_common::viewer_api::{
    PrivilegedDaemonRequest, PrivilegedDaemonResponse, StartTraceRequest, TraceRunStatus,
};
use std::env;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::{Mutex, OnceCell, watch};

static DAEMON_START_LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();

fn daemon_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/probex-privileged-{uid}.sock"))
}

fn to_start_request(config: TraceCommandConfig) -> StartTraceRequest {
    StartTraceRequest {
        program: config.program,
        args: config.args,
        output_parquet: config.output,
        sample_freq_hz: config.sample_freq_hz,
        custom_probes: config.custom_probes,
    }
}

async fn send_request(request: PrivilegedDaemonRequest) -> Result<PrivilegedDaemonResponse> {
    let socket = daemon_socket_path();
    let mut stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("failed to connect privileged daemon socket {:?}", socket))?;
    let payload = serde_json::to_vec(&request).with_context(|| "failed to encode daemon request")?;
    stream
        .write_all(&payload)
        .await
        .with_context(|| "failed to write daemon request")?;
    stream
        .shutdown()
        .await
        .with_context(|| "failed to shutdown daemon request stream")?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .with_context(|| "failed to read daemon response")?;
    if buf.is_empty() {
        return Err(anyhow!("privileged daemon returned empty response"));
    }
    let response: PrivilegedDaemonResponse =
        serde_json::from_slice(&buf).with_context(|| "failed to parse daemon response")?;
    Ok(response)
}

async fn ensure_daemon_running() -> Result<()> {
    if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
        return Ok(());
    }
    let lock = DAEMON_START_LOCK.get_or_init(|| async { Mutex::new(()) }).await;
    let _guard = lock.lock().await;
    if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
        return Ok(());
    }

    let socket = daemon_socket_path();
    let exe = env::current_exe().with_context(|| "failed to resolve current executable path")?;
    let mut child = Command::new("pkexec")
        .arg(exe)
        .arg("--privileged-daemon")
        .arg("--privileged-daemon-socket")
        .arg(socket.as_os_str())
        .arg("--privileged-daemon-owner-uid")
        .arg(format!("{}", unsafe { libc::geteuid() }))
        .spawn()
        .with_context(|| {
            "failed to spawn privileged daemon via pkexec (is pkexec installed and authorized?)"
        })?;

    // Wait briefly for daemon socket readiness. Keep pkexec process running in background.
    for _ in 0..50u32 {
        if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Some(status) = child.try_wait().with_context(|| "failed waiting pkexec process")?
            && !status.success()
        {
            break;
        }
    }
    Err(anyhow!(
        "privileged daemon did not become ready; ensure pkexec auth succeeded"
    ))
}

fn status_to_outcome(status: TraceRunStatus) -> Option<Result<TraceCommandOutcome>> {
    match status {
        TraceRunStatus::Finished {
            success,
            error,
            output_parquet,
            ..
        } => {
            if success {
                Some(Ok(TraceCommandOutcome {
                    total_events: 0,
                    output_path: output_parquet,
                }))
            } else {
                Some(Err(anyhow!(
                    "{}",
                    error.unwrap_or_else(|| "privileged trace failed".to_string())
                )))
            }
        }
        _ => None,
    }
}

pub(crate) async fn run_trace_via_daemon(
    config: TraceCommandConfig,
    mut stop_signal: Option<watch::Receiver<bool>>,
) -> Result<TraceCommandOutcome> {
    ensure_daemon_running().await?;
    let start_resp = send_request(PrivilegedDaemonRequest::StartTrace {
        request: to_start_request(config),
    })
    .await?;
    if !start_resp.ok {
        return Err(anyhow!(
            "{}",
            start_resp
                .error
                .unwrap_or_else(|| "privileged daemon rejected start request".to_string())
        ));
    }
    if let Some(status) = start_resp.status.and_then(|s| status_to_outcome(s.status)) {
        return status;
    }

    loop {
        if let Some(stop_rx) = stop_signal.as_mut()
            && stop_rx.has_changed().unwrap_or(false)
        {
            let _ = send_request(PrivilegedDaemonRequest::StopTrace).await;
            return Err(anyhow!("trace stopped by request"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let response = send_request(PrivilegedDaemonRequest::Status).await?;
        if !response.ok {
            return Err(anyhow!(
                "{}",
                response
                    .error
                    .unwrap_or_else(|| "privileged daemon status query failed".to_string())
            ));
        }
        if let Some(status) = response.status.and_then(|s| status_to_outcome(s.status)) {
            return status;
        }
    }
}
