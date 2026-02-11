//! UI components for snitch-viewer.
//!
//! Provides a timeline-based visualization with time range selection,
//! event type filters, process lifetimes, and paginated event table.

use dioxus::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::server::{
    EventFilters, EventMarker, EventTypeCounts, EventsResponse, HistogramResponse, ProcessEventsResponse,
    ProcessLifetime, ProcessLifetimesResponse, SyscallLatencyStats, TraceEvent, TraceSummary,
    get_events, get_histogram, get_pid_event_type_counts, get_process_events, get_process_lifetimes,
    get_summary, get_syscall_latency_stats,
};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

const RESULTS_PER_PAGE: usize = 50;
const HISTOGRAM_BUCKETS: usize = 80;

#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        main { class: "min-h-screen bg-gray-50 text-gray-900",
            TraceViewer {}
        }
    }
}

#[component]
fn TraceViewer() -> Element {
    // Core data
    let mut summary = use_signal(|| Option::<TraceSummary>::None);
    let mut events_response = use_signal(|| Option::<EventsResponse>::None);
    let mut histogram = use_signal(|| Option::<HistogramResponse>::None);
    let mut selected_pid_event_counts = use_signal(|| Option::<EventTypeCounts>::None);
    let mut syscall_latency_stats = use_signal(|| Option::<SyscallLatencyStats>::None);
    let mut process_lifetimes = use_signal(|| Option::<ProcessLifetimesResponse>::None);
    let mut process_events = use_signal(|| Option::<ProcessEventsResponse>::None);

    // Loading/error state
    let mut loading = use_signal(|| true);
    let mut error_msg = use_signal(|| Option::<String>::None);

    // Time range state
    let mut view_start_ns = use_signal(|| 0u64);
    let mut view_end_ns = use_signal(|| 0u64);
    let mut is_dragging_range = use_signal(|| false);

    // Filter state
    let mut enabled_event_types = use_signal(|| HashSet::<String>::new());
    let mut selected_pid = use_signal(|| String::new());
    let mut current_page = use_signal(|| 0usize);

    // Load summary on mount
    let _ = use_resource(move || async move {
        match get_summary().await {
            Ok(s) => {
                view_start_ns.set(s.min_ts_ns);
                view_end_ns.set(s.max_ts_ns);
                let all_types: HashSet<String> = s.event_types.iter().cloned().collect();
                enabled_event_types.set(all_types);
                summary.set(Some(s));
            }
            Err(e) => error_msg.set(Some(format!("Failed to load summary: {}", e))),
        }
    });

    // Load process lifetimes on mount
    let _ = use_resource(move || async move {
        match get_process_lifetimes().await {
            Ok(p) => process_lifetimes.set(Some(p)),
            Err(e) => log::error!("Process lifetimes error: {}", e),
        }
    });

    // Load histogram when summary is ready
    let _ = use_resource(move || async move {
        if let Some(ref s) = summary() {
            match get_histogram(s.min_ts_ns, s.max_ts_ns, HISTOGRAM_BUCKETS).await {
                Ok(h) => histogram.set(Some(h)),
                Err(e) => log::error!("Histogram error: {}", e),
            }
        }
    });

    // Load process events when view range changes
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() {
            return;
        }
        if start == 0 && end == 0 {
            return;
        }
        // Limit to 100 events per PID for performance
        match get_process_events(start, end, 100).await {
            Ok(pe) => process_events.set(Some(pe)),
            Err(e) => log::error!("Process events error: {}", e),
        }
    });

    // Load selected PID event counts (for summary panel) when PID or view range changes
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() {
            return;
        }
        if start == 0 && end == 0 {
            return;
        }

        let pid = selected_pid().parse::<u32>().ok();
        if let Some(pid) = pid {
            match get_pid_event_type_counts(pid, Some(start), Some(end)).await {
                Ok(counts) => selected_pid_event_counts.set(Some(counts)),
                Err(e) => log::error!("Selected PID event counts error: {}", e),
            }
        } else {
            selected_pid_event_counts.set(None);
        }
    });

    // Load read/write syscall latency stats in current range for selected PID
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() {
            return;
        }
        if start == 0 && end == 0 {
            return;
        }
        let pid = selected_pid().parse::<u32>().ok();
        if pid.is_none() {
            syscall_latency_stats.set(None);
            return;
        }

        match get_syscall_latency_stats(start, end, pid).await {
            Ok(stats) => syscall_latency_stats.set(Some(stats)),
            Err(e) => log::error!("Syscall latency stats error: {}", e),
        }
    });

    // Load events when filters change
    let do_search = move |reset_page: bool| {
        let types: Vec<String> = enabled_event_types().into_iter().collect();
        let pid_str = selected_pid();
        let page = if reset_page { 0 } else { current_page() };
        let start = view_start_ns();
        let end = view_end_ns();

        spawn(async move {
            loading.set(true);
            error_msg.set(None);
            if reset_page {
                current_page.set(0);
            }

            let filters = EventFilters {
                event_type: None,
                event_types: types,
                pid: pid_str.parse::<u32>().ok(),
                start_ns: Some(start),
                end_ns: Some(end),
                limit: RESULTS_PER_PAGE,
                offset: page * RESULTS_PER_PAGE,
            };

            match get_events(filters).await {
                Ok(response) => events_response.set(Some(response)),
                Err(e) => {
                    error_msg.set(Some(format!("Failed to load events: {}", e)));
                    events_response.set(None);
                }
            }
            loading.set(false);
        });
    };

    // Initial load
    let _ = use_resource(move || {
        let do_search = do_search.clone();
        async move {
            if summary().is_some() {
                do_search(true);
            }
        }
    });

    let summary_data = summary();
    let response = events_response();
    let hist_data = histogram();
    let selected_pid_counts = selected_pid_event_counts();
    let io_latency_stats = syscall_latency_stats();
    let proc_lifetimes = process_lifetimes();
    let proc_events = process_events();

    let (events, total_count) = match &response {
        Some(r) => (r.events.clone(), r.total_count),
        None => (Vec::new(), 0),
    };

    let total_pages = (total_count + RESULTS_PER_PAGE - 1) / RESULTS_PER_PAGE;
    let selected_pid_value = selected_pid().parse::<u32>().ok();
    let mut selected_pid_breakdown: Vec<(String, usize)> = selected_pid_counts
        .as_ref()
        .map(|counts| {
            counts
                .counts
                .iter()
                .map(|(event_type, count)| (event_type.clone(), *count))
                .collect()
        })
        .unwrap_or_default();
    selected_pid_breakdown.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let selected_pid_total: usize = selected_pid_breakdown.iter().map(|(_, c)| *c).sum();
    let selected_pid_memory_event_total: usize = [
        "syscall_mmap_enter",
        "syscall_mmap_exit",
        "syscall_munmap_enter",
        "syscall_munmap_exit",
        "syscall_brk_enter",
        "syscall_brk_exit",
    ]
    .iter()
    .map(|event_type| {
        selected_pid_counts
            .as_ref()
            .and_then(|counts| counts.counts.get(*event_type).copied())
            .unwrap_or(0)
    })
    .sum();
    let selected_pid_mmap_enter = selected_pid_counts
        .as_ref()
        .and_then(|counts| counts.counts.get("syscall_mmap_enter").copied())
        .unwrap_or(0);
    let selected_pid_munmap_enter = selected_pid_counts
        .as_ref()
        .and_then(|counts| counts.counts.get("syscall_munmap_enter").copied())
        .unwrap_or(0);
    let selected_pid_brk_enter = selected_pid_counts
        .as_ref()
        .and_then(|counts| counts.counts.get("syscall_brk_enter").copied())
        .unwrap_or(0);

    // Time navigation helpers
    let full_start = summary_data.as_ref().map(|s| s.min_ts_ns).unwrap_or(0);
    let full_end = summary_data.as_ref().map(|s| s.max_ts_ns).unwrap_or(0);
    let full_duration = full_end.saturating_sub(full_start);

    rsx! {
        // Header
        header { class: "bg-white border-b border-gray-200 px-3 sm:px-4 lg:px-6 py-3",
            div { class: "w-full flex items-center justify-between",
                h1 { class: "text-lg font-semibold text-gray-900", "Snitch Trace Viewer" }
                if let Some(ref s) = summary_data {
                    div { class: "flex gap-6 text-sm",
                        StatBadge { label: "Events", value: format!("{}", s.total_events) }
                        StatBadge { label: "Duration", value: format_duration(full_duration) }
                        StatBadge { label: "PIDs", value: format!("{}", s.unique_pids.len()) }
                    }
                }
            }
        }

        div { class: "w-full px-3 sm:px-4 lg:px-6 py-4 space-y-3",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // PID Filter + Results count + selected PID summary
            div { class: "bg-white border border-gray-200 rounded-lg px-3 py-3 space-y-3",
                div { class: "flex items-center gap-4",
                    div { class: "flex items-center gap-2",
                        label { class: "text-sm text-gray-600", "PID:" }
                        select {
                            class: "px-2 py-1 border border-gray-200 rounded text-sm bg-white",
                            value: "{selected_pid}",
                            onchange: move |evt| {
                                selected_pid.set(evt.value());
                                do_search(true);
                            },
                            option { value: "", "All" }
                            {summary_data.as_ref().map(|s| s.unique_pids.iter().map(|p| rsx! {
                                option { key: "{p}", value: "{p}", "{p}" }
                            })).into_iter().flatten()}
                        }
                    }
                    div { class: "ml-auto text-sm text-gray-500",
                        "{total_count} events"
                        if total_pages > 1 {
                            " · Page {current_page() + 1}/{total_pages}"
                        }
                    }
                }

                if let Some(pid) = selected_pid_value {
                    div { class: "border-t border-gray-100 pt-2 space-y-2",
                        div { class: "flex items-baseline justify-between",
                            span { class: "text-sm font-medium text-gray-700", "PID {pid} Event Aggregation (current range)" }
                            span { class: "text-xs text-gray-500", "{selected_pid_total} total" }
                        }
                        if selected_pid_breakdown.is_empty() {
                            div { class: "text-xs text-gray-400", "No events for this PID in current range" }
                        } else {
                            div { class: "flex flex-wrap gap-2",
                                {selected_pid_breakdown.iter().map(|(event_type, count)| {
                                    let color = get_event_color(event_type);
                                    let enabled = enabled_event_types().contains(event_type);
                                    let event_type_clone = event_type.clone();
                                    rsx! {
                                        button {
                                            key: "{event_type}",
                                            class: if enabled {
                                                format!("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium {} text-white", color)
                                            } else {
                                                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-500 hover:bg-gray-200".to_string()
                                            },
                                            onclick: move |_| {
                                                let mut types = enabled_event_types();
                                                if types.contains(&event_type_clone) {
                                                    types.remove(&event_type_clone);
                                                } else {
                                                    types.insert(event_type_clone.clone());
                                                }
                                                enabled_event_types.set(types);
                                                do_search(true);
                                            },
                                            "{event_type}"
                                            span { class: if enabled { "opacity-80" } else { "text-gray-400" },
                                                "{count}"
                                            }
                                        }
                                    }
                                })}
                            }
                        }

                        if let Some(ref stats) = io_latency_stats {
                            div { class: "border-t border-gray-100 pt-2",
                                div { class: "text-xs uppercase tracking-wide text-gray-500 mb-1", "I/O + Memory Stats (current range)" }
                                div { class: "grid grid-cols-1 lg:grid-cols-3 gap-2",
                                    div { class: "border border-gray-100 rounded p-2 space-y-1",
                                        div { class: "text-[11px] uppercase tracking-wide text-gray-500", "read latency" }
                                        if stats.read.count == 0 {
                                            div { class: "text-xs text-gray-400", "No complete pairs" }
                                        } else {
                                            div { class: "flex flex-wrap gap-1 text-[11px]",
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "cnt {stats.read.count}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "avg {format_duration(stats.read.avg_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "p50 {format_duration(stats.read.p50_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "p95 {format_duration(stats.read.p95_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "max {format_duration(stats.read.max_ns)}" }
                                            }
                                        }
                                    }
                                    div { class: "border border-gray-100 rounded p-2 space-y-1",
                                        div { class: "text-[11px] uppercase tracking-wide text-gray-500", "write latency" }
                                        if stats.write.count == 0 {
                                            div { class: "text-xs text-gray-400", "No complete pairs" }
                                        } else {
                                            div { class: "flex flex-wrap gap-1 text-[11px]",
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "cnt {stats.write.count}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "avg {format_duration(stats.write.avg_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "p50 {format_duration(stats.write.p50_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "p95 {format_duration(stats.write.p95_ns)}" }
                                                span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "max {format_duration(stats.write.max_ns)}" }
                                            }
                                        }
                                    }
                                    div { class: "border border-gray-100 rounded p-2 space-y-1",
                                        div { class: "text-[11px] uppercase tracking-wide text-gray-500", "memory syscall stats" }
                                        div { class: "flex flex-wrap gap-1 text-[11px]",
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "events {selected_pid_memory_event_total}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "mmap {selected_pid_mmap_enter}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "munmap {selected_pid_munmap_enter}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "brk {selected_pid_brk_enter}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "alloc {format_bytes(stats.mmap_alloc_bytes)}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "free {format_bytes(stats.munmap_free_bytes)}" }
                                            span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "net {format_net_bytes_signed(stats.mmap_alloc_bytes, stats.munmap_free_bytes)}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Process Timeline
            if let (Some(s), Some(p)) = (&summary_data, &proc_lifetimes) {
                ProcessTimeline {
                    processes: p.processes.clone(),
                    process_events: proc_events.clone(),
                    enabled_event_types: enabled_event_types(),
                    selected_pid: selected_pid_value,
                    full_start_ns: s.min_ts_ns,
                    full_end_ns: s.max_ts_ns,
                    view_start_ns: view_start_ns(),
                    view_end_ns: view_end_ns(),
                    histogram: hist_data.clone(),
                    on_select_pid: move |pid: u32| {
                        selected_pid.set(pid.to_string());
                        do_search(true);
                    },
                    on_focus_process: move |(pid, start, end): (u32, u64, u64)| {
                        selected_pid.set(pid.to_string());
                        view_start_ns.set(start);
                        view_end_ns.set(end);
                        do_search(true);
                    },
                    on_change_range: move |(start, end, commit): (u64, u64, bool)| {
                        let drag_step_ns = (full_duration / 2000).max(1);
                        if !commit {
                            let start_delta = start.abs_diff(view_start_ns());
                            let end_delta = end.abs_diff(view_end_ns());
                            if start_delta < drag_step_ns && end_delta < drag_step_ns {
                                return;
                            }
                            is_dragging_range.set(true);
                        } else {
                            is_dragging_range.set(false);
                        }
                        view_start_ns.set(start);
                        view_end_ns.set(end);
                        if commit {
                            do_search(true);
                        }
                    },
                }
            }

            // Event Table
            div { class: "bg-white border border-gray-200 rounded-lg overflow-hidden",
                if loading() {
                    div { class: "p-8 text-center text-gray-400", "Loading..." }
                } else if events.is_empty() {
                    div { class: "p-8 text-center text-gray-400", "No events in this range" }
                } else {
                    table { class: "w-full text-sm",
                        thead {
                            tr { class: "bg-gray-50 border-b border-gray-200 text-left text-xs font-medium text-gray-500 uppercase",
                                th { class: "px-3 py-2", "Time" }
                                th { class: "px-3 py-2", "Type" }
                                th { class: "px-3 py-2", "PID" }
                                th { class: "px-3 py-2", "CPU" }
                                th { class: "px-3 py-2", "Details" }
                            }
                        }
                        tbody {
                            {events.iter().enumerate().map(|(idx, event)| {
                                let relative_ns = event.ts_ns.saturating_sub(full_start);
                                let ts_str = format_duration(relative_ns);
                                let details = format_event_details(event);
                                let color = get_event_text_color(&event.event_type);

                                rsx! {
                                    tr {
                                        key: "{idx}",
                                        class: "border-b border-gray-100 hover:bg-gray-50",
                                        td { class: "px-3 py-1.5 font-mono text-xs text-gray-500", "{ts_str}" }
                                        td { class: "px-3 py-1.5 text-xs font-medium {color}", "{event.event_type}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs", "{event.pid}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs", "{event.cpu}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs text-gray-600 truncate max-w-xs", "{details}" }
                                    }
                                }
                            })}
                        }
                    }
                }
            }

            // Pagination
            if total_pages > 1 {
                div { class: "flex justify-center gap-2",
                    button {
                        class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                        disabled: current_page() == 0,
                        onclick: move |_| {
                            current_page.set(current_page().saturating_sub(1));
                            do_search(false);
                        },
                        "← Prev"
                    }
                    button {
                        class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                        disabled: current_page() + 1 >= total_pages,
                        onclick: move |_| {
                            current_page.set(current_page() + 1);
                            do_search(false);
                        },
                        "Next →"
                    }
                }
            }
        }
    }
}

#[component]
fn StatBadge(label: String, value: String) -> Element {
    rsx! {
        div { class: "flex items-center gap-1.5",
            span { class: "text-gray-400", "{label}" }
            span { class: "font-medium text-gray-900", "{value}" }
        }
    }
}

/// Process Timeline visualization showing process lifetimes as horizontal bars
#[component]
fn ProcessTimeline(
    processes: Vec<ProcessLifetime>,
    process_events: Option<ProcessEventsResponse>,
    enabled_event_types: HashSet<String>,
    selected_pid: Option<u32>,
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    histogram: Option<HistogramResponse>,
    on_select_pid: EventHandler<u32>,
    on_focus_process: EventHandler<(u32, u64, u64)>,
    on_change_range: EventHandler<(u64, u64, bool)>,
) -> Element {
    let mut collapsed_nodes = use_signal(|| HashSet::<u32>::new());

    let full_duration_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_duration = full_duration_ns as f64;
    let view_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    if full_duration == 0.0 || processes.is_empty() {
        return rsx! {};
    }

    // Sort processes: by start time
    let mut sorted_processes = processes.clone();
    sorted_processes.sort_by_key(|p| p.start_ns);

    let process_by_pid: HashMap<u32, &ProcessLifetime> =
        sorted_processes.iter().map(|p| (p.pid, p)).collect();

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut root_pids: Vec<u32> = Vec::new();

    for proc in &sorted_processes {
        if let Some(parent_pid) = proc.parent_pid {
            if process_by_pid.contains_key(&parent_pid) {
                children_map.entry(parent_pid).or_default().push(proc.pid);
            } else {
                root_pids.push(proc.pid);
            }
        } else {
            root_pids.push(proc.pid);
        }
    }

    for children in children_map.values_mut() {
        children.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));
    }
    root_pids.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));

    fn append_visible_rows(
        pid: u32,
        depth: usize,
        children_map: &HashMap<u32, Vec<u32>>,
        collapsed_nodes: &HashSet<u32>,
        out: &mut Vec<(u32, usize)>,
    ) {
        out.push((pid, depth));
        if collapsed_nodes.contains(&pid) {
            return;
        }
        if let Some(children) = children_map.get(&pid) {
            for child in children {
                append_visible_rows(*child, depth + 1, children_map, collapsed_nodes, out);
            }
        }
    }

    let collapsed_set = collapsed_nodes();
    let mut ordered_pid_rows: Vec<(u32, usize)> = Vec::with_capacity(sorted_processes.len());
    for root_pid in &root_pids {
        append_visible_rows(
            *root_pid,
            0,
            &children_map,
            &collapsed_set,
            &mut ordered_pid_rows,
        );
    }

    // Keep process row ordering stable across range changes, but honor collapsed subtrees.
    let all_process_rows: Vec<(&ProcessLifetime, usize)> = ordered_pid_rows
        .iter()
        .filter_map(|(pid, depth)| process_by_pid.get(pid).map(|proc| (*proc, *depth)))
        .collect();

    let visible_in_range_count = sorted_processes
        .iter()
        .filter(|p| {
            let p_end = p.end_ns.unwrap_or(full_end_ns);
            p.start_ns <= view_end_ns && p_end >= view_start_ns
        })
        .count();

    let visible_process_rows = all_process_rows.clone();
    let collapsible_nodes: Vec<u32> = children_map
        .iter()
        .filter_map(|(pid, children)| (!children.is_empty()).then_some(*pid))
        .collect();
    let has_collapsible_nodes = !collapsible_nodes.is_empty();
    let all_tree_expanded = collapsible_nodes.iter().all(|pid| !collapsed_set.contains(pid));
    let all_tree_collapsed = collapsible_nodes.iter().all(|pid| collapsed_set.contains(pid));

    if visible_process_rows.is_empty() {
        return rsx! {};
    }

    // Get events map
    let events_map = process_events
        .as_ref()
        .map(|pe| &pe.events_by_pid)
        .cloned()
        .unwrap_or_default();

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg p-3",
            div { class: "flex items-center justify-between mb-2",
                span { class: "text-sm font-medium text-gray-700", "Process Lifetimes" }
                div { class: "flex items-center gap-3",
                    span { class: "text-xs text-gray-400", "{visible_in_range_count} active in view · {sorted_processes.len()} total" }
                    if has_collapsible_nodes {
                        button {
                            class: "text-xs text-gray-600 hover:text-gray-800 underline disabled:opacity-40 disabled:no-underline",
                            disabled: all_tree_expanded,
                            onclick: move |_| collapsed_nodes.set(HashSet::new()),
                            "Expand all"
                        }
                        button {
                            class: "text-xs text-gray-600 hover:text-gray-800 underline disabled:opacity-40 disabled:no-underline",
                            disabled: all_tree_collapsed,
                            onclick: {
                                let collapse_targets = collapsible_nodes.clone();
                                move |_| {
                                    let mut all_collapsed = HashSet::new();
                                    for pid in &collapse_targets {
                                        all_collapsed.insert(*pid);
                                    }
                                    collapsed_nodes.set(all_collapsed);
                                }
                            },
                            "Collapse all"
                        }
                    }
                }
            }

            // Overview bar + time controls
            div { class: "space-y-1 mb-2",
                div { class: "flex justify-between text-xs text-gray-400",
                    span { "0" }
                    span { "{format_duration(full_duration_ns)}" }
                }
                TimelineOverview {
                    histogram: histogram.clone(),
                    full_start_ns: full_start_ns,
                    full_end_ns: full_end_ns,
                    view_start_ns: view_start_ns,
                    view_end_ns: view_end_ns,
                    enabled_types: enabled_event_types.clone(),
                    on_change_range: on_change_range.clone(),
                }
            }

            div { class: "flex items-center justify-between mb-2",
                div { class: "text-sm text-gray-700",
                    span { class: "font-mono", "{format_duration(view_start_ns - full_start_ns)}" }
                    span { class: "text-gray-400 mx-2", "→" }
                    span { class: "font-mono", "{format_duration(view_end_ns - full_start_ns)}" }
                    span { class: "text-gray-400 ml-2", "({format_duration(view_duration_ns)})" }
                }

                div { class: "flex items-center gap-1",
                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_start_ns <= full_start_ns,
                        onclick: move |_| {
                            let shift = view_duration_ns / 4;
                            let new_start = view_start_ns.saturating_sub(shift).max(full_start_ns);
                            let new_end = (new_start + view_duration_ns).min(full_end_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "◀"
                    }
                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_end_ns >= full_end_ns,
                        onclick: move |_| {
                            let shift = view_duration_ns / 4;
                            let new_end = (view_end_ns + shift).min(full_end_ns);
                            let new_start = new_end.saturating_sub(view_duration_ns).max(full_start_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "▶"
                    }

                    div { class: "w-px h-5 bg-gray-200 mx-1" }

                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns < 1000,
                        onclick: move |_| {
                            let center = view_start_ns + view_duration_ns / 2;
                            let new_duration = view_duration_ns / 2;
                            let new_start = center.saturating_sub(new_duration / 2).max(full_start_ns);
                            let new_end = (new_start + new_duration).min(full_end_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "+"
                    }
                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns >= full_duration_ns,
                        onclick: move |_| {
                            let center = view_start_ns + view_duration_ns / 2;
                            let new_duration = (view_duration_ns * 2).min(full_duration_ns);
                            let new_start = center.saturating_sub(new_duration / 2).max(full_start_ns);
                            let new_end = (new_start + new_duration).min(full_end_ns);
                            let new_start = new_end.saturating_sub(new_duration).max(full_start_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "−"
                    }

                    div { class: "w-px h-5 bg-gray-200 mx-1" }

                    button {
                        class: "px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded",
                        onclick: move |_| on_change_range.call((full_start_ns, full_end_ns, true)),
                        "Reset"
                    }
                }
            }

            // Time axis labels
            div { class: "flex items-center mb-1",
                div { class: "w-52 shrink-0" }
                div { class: "flex-1 flex justify-between text-xs text-gray-400",
                    span { "{format_duration(view_start_ns - full_start_ns)}" }
                    span { "{format_duration(view_end_ns - full_start_ns)}" }
                }
                div { class: "w-24 shrink-0" }
            }

            // Process rows
            div { class: if all_process_rows.len() > 15 { "space-y-1 max-h-[72vh] overflow-y-auto" } else { "space-y-1" },
                {visible_process_rows.iter().map(|(proc, depth)| {
                    let indent = (*depth).min(6);

                    let view_duration_ns = view_end_ns.saturating_sub(view_start_ns).max(1);
                    let view_duration = view_duration_ns as f64;
                    let bar_start = proc.start_ns.max(view_start_ns);
                    let bar_end = proc.end_ns.unwrap_or(full_end_ns).min(view_end_ns);
                    let in_view = bar_start < bar_end;
                    let visible_duration_ns = if in_view { bar_end - bar_start } else { 0 };

                    let left_pct = if in_view {
                        ((bar_start - view_start_ns) as f64 / view_duration * 100.0)
                            .max(0.0)
                            .min(100.0)
                    } else {
                        0.0
                    };
                    let width_pct = if in_view {
                        (visible_duration_ns as f64 / view_duration * 100.0)
                            .max(0.5)
                            .min(100.0 - left_pct)
                    } else {
                        0.0
                    };

                    let bar_color = if proc.did_exit {
                        if proc.exit_code == Some(0) {
                            "bg-green-200"
                        } else {
                            "bg-red-200"
                        }
                    } else {
                        "bg-blue-200"
                    };

                    let has_parent = proc.parent_pid.is_some();
                    let has_children = children_map
                        .get(&proc.pid)
                        .map(|children| !children.is_empty())
                        .unwrap_or(false);
                    let is_collapsed = collapsed_set.contains(&proc.pid);
                    let pid = proc.pid;
                    let process_name = proc.process_name.as_deref().unwrap_or("unknown");
                    let is_selected = selected_pid == Some(proc.pid);
                    let process_start_ns = proc.start_ns;
                    let process_end_ns = proc.end_ns.unwrap_or(full_end_ns);
                    let focus_end_ns = if process_end_ns > process_start_ns {
                        process_end_ns
                    } else {
                        (process_start_ns + 1).min(full_end_ns)
                    };

                    // Get events for this PID
                    let pid_events: Vec<&EventMarker> = events_map
                        .get(&proc.pid)
                        .map(|events| {
                            events
                                .iter()
                                .filter(|e| {
                                    enabled_event_types.contains(&e.event_type)
                                        && e.ts_ns >= view_start_ns
                                        && e.ts_ns <= view_end_ns
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    rsx! {
                        div {
                            key: "{proc.pid}",
                            class: "flex items-center gap-3 h-10 group",

                            div {
                                class: "w-52 shrink-0 overflow-hidden",
                                style: "padding-left: {indent * 8}px; font-variant-numeric: tabular-nums;",
                                title: "{process_name} (PID {proc.pid})",
                                div { class: "flex items-start justify-end gap-1.5",
                                    if has_children {
                                        button {
                                            class: "inline-flex items-center justify-center w-5 h-5 text-base leading-none font-semibold text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded",
                                            title: if is_collapsed { "Expand children" } else { "Collapse children" },
                                            onclick: move |_| {
                                                let mut collapsed = collapsed_nodes();
                                                if collapsed.contains(&pid) {
                                                    collapsed.remove(&pid);
                                                } else {
                                                    collapsed.insert(pid);
                                                }
                                                collapsed_nodes.set(collapsed);
                                            },
                                            if is_collapsed { "▸" } else { "▾" }
                                        }
                                    } else {
                                        span { class: "inline-flex w-5 h-5" }
                                    }
                                    div {
                                        class: if is_selected {
                                            "cursor-pointer overflow-hidden bg-blue-50 border border-blue-200 rounded px-1.5 py-0.5"
                                        } else {
                                            "cursor-pointer hover:text-blue-600 overflow-hidden"
                                        },
                                        onclick: move |_| on_select_pid.call(pid),
                                        div { class: "text-sm text-gray-700 text-right truncate leading-tight",
                                            if is_selected {
                                                span { class: "inline-block w-1.5 h-1.5 rounded-full bg-blue-600 mr-1 align-middle" }
                                            }
                                            if has_parent { "└ " }
                                            "{process_name}"
                                        }
                                        div { class: "text-xs font-mono text-gray-500 text-right whitespace-nowrap leading-tight",
                                            "PID {proc.pid}"
                                        }
                                    }
                                }
                            }

                            div { class: "flex-1 relative h-8 bg-gray-100 rounded overflow-hidden",
                                // Process lifetime bar (lighter color as background)
                                if in_view {
                                    div {
                                        class: "absolute top-0 bottom-0 {bar_color} rounded",
                                        style: "left: {left_pct}%; width: {width_pct}%;",
                                    }
                                }

                                // Event markers
                                {pid_events.iter().map(|event| {
                                    let event_pct = ((event.ts_ns - view_start_ns) as f64 / view_duration * 100.0).max(0.0).min(100.0);
                                    let event_color = get_event_marker_color(&event.event_type);

                                    rsx! {
                                        div {
                                            key: "{event.ts_ns}",
                                            class: "absolute top-0 bottom-0 w-px {event_color}",
                                            style: "left: {event_pct}%;",
                                            title: "{event.event_type} @ {format_duration(event.ts_ns - full_start_ns)}",
                                        }
                                    }
                                })}

                                // Fork marker
                                if proc.was_forked && proc.start_ns >= view_start_ns && proc.start_ns <= view_end_ns {
                                    div {
                                        class: "absolute top-0 bottom-0 w-1 bg-green-600",
                                        style: "left: {left_pct}%;",
                                        title: "Fork from PID {proc.parent_pid.unwrap_or(0)}",
                                    }
                                }

                                // Exit marker
                                if proc.did_exit {
                                    if let Some(end) = proc.end_ns {
                                        if end >= view_start_ns && end <= view_end_ns {
                                            {
                                                let exit_pct = ((end - view_start_ns) as f64 / view_duration * 100.0).max(0.0);
                                                let exit_color = if proc.exit_code == Some(0) { "bg-green-600" } else { "bg-red-600" };
                                                rsx! {
                                                    div {
                                                        class: "absolute top-0 bottom-0 w-1 {exit_color}",
                                                        style: "left: {exit_pct}%;",
                                                        title: "Exit code: {proc.exit_code.unwrap_or(0)}",
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Clickable overlay
                                div {
                                    class: "absolute inset-0 cursor-pointer",
                                    onclick: move |_| on_select_pid.call(pid),
                                    ondoubleclick: move |_| on_focus_process.call((pid, process_start_ns, focus_end_ns)),
                                }
                            }

                            div { class: "w-24 text-sm text-gray-400 shrink-0 truncate",
                                if !in_view {
                                    "—"
                                } else if proc.did_exit {
                                    if proc.exit_code == Some(0) {
                                        "✓ {format_duration_short(visible_duration_ns)}"
                                    } else {
                                        "✗ {format_duration_short(visible_duration_ns)}"
                                    }
                                } else {
                                    "{format_duration_short(visible_duration_ns)}"
                                }
                            }
                        }
                    }
                })}
            }
        }
    }
}

fn get_event_marker_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "bg-blue-600",
        "process_fork" => "bg-green-600",
        "process_exit" => "bg-red-600",
        "page_fault" => "bg-orange-500",
        _ if event_type.contains("syscall") => "bg-purple-600",
        _ => "bg-gray-600",
    }
}

#[component]
fn TimelineOverview(
    histogram: Option<HistogramResponse>,
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    enabled_types: HashSet<String>,
    on_change_range: EventHandler<(u64, u64, bool)>,
) -> Element {
    let full_range_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_range = full_range_ns as f64;
    if full_range == 0.0 {
        return rsx! {};
    }

    let min_window_ns = (full_range_ns / 200).max(1);
    let drag_step_ns = (full_range_ns / 2500).max(1);
    let window_ns = view_end_ns.saturating_sub(view_start_ns).max(min_window_ns);
    let max_window_start_offset = full_range_ns.saturating_sub(window_ns);
    let view_left_pct = ((view_start_ns - full_start_ns) as f64 / full_range * 100.0).max(0.0);
    let view_width_pct = ((view_end_ns - view_start_ns) as f64 / full_range * 100.0).max(0.5);

    let max_count = histogram
        .as_ref()
        .map(|h| {
            h.buckets
                .iter()
                .map(|b| {
                    b.counts_by_type
                        .iter()
                        .filter(|(t, _)| enabled_types.contains(*t))
                        .map(|(_, c)| *c)
                        .sum::<usize>()
                })
                .max()
                .unwrap_or(1)
        })
        .unwrap_or(1)
        .max(1);

    rsx! {
        div { class: "relative h-10 bg-gray-100 rounded overflow-hidden",
            // Histogram bars
            if let Some(ref h) = histogram {
                div { class: "absolute inset-0 flex items-end",
                    {h.buckets.iter().map(|bucket| {
                        let count: usize = bucket.counts_by_type
                            .iter()
                            .filter(|(t, _)| enabled_types.contains(*t))
                            .map(|(_, c)| *c)
                            .sum();
                        let height_pct = (count as f64 / max_count as f64 * 100.0).max(1.0);

                        rsx! {
                            div {
                                key: "{bucket.bucket_start_ns}",
                                class: "flex-1 bg-gray-300",
                                style: "height: {height_pct}%;",
                            }
                        }
                    })}
                }
            }

            // Current view window
            div {
                class: "absolute top-0 bottom-0 bg-blue-500 opacity-25 border-x-2 border-blue-600",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }

            // Draggable selected window (shift left/right while keeping width)
            input {
                r#type: "range",
                class: "timeline-window-slider",
                style: "--window-thumb-width: {view_width_pct}%;",
                min: "0",
                max: "{max_window_start_offset}",
                step: "{drag_step_ns}",
                value: "{view_start_ns.saturating_sub(full_start_ns)}",
                disabled: max_window_start_offset == 0,
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let start = (full_start_ns + offset).min(full_end_ns.saturating_sub(window_ns));
                        let end = start.saturating_add(window_ns).min(full_end_ns);
                        on_change_range.call((start, end, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let start = (full_start_ns + offset).min(full_end_ns.saturating_sub(window_ns));
                        let end = start.saturating_add(window_ns).min(full_end_ns);
                        on_change_range.call((start, end, true));
                    }
                },
            }

            // Draggable range handles (preview on input, commit on change)
            input {
                r#type: "range",
                class: "timeline-range-slider",
                min: "0",
                max: "{full_range_ns}",
                step: "{drag_step_ns}",
                value: "{view_start_ns.saturating_sub(full_start_ns)}",
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let max_start = view_end_ns.saturating_sub(min_window_ns).max(full_start_ns);
                        let start = (full_start_ns + offset).min(max_start);
                        on_change_range.call((start, view_end_ns, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let max_start = view_end_ns.saturating_sub(min_window_ns).max(full_start_ns);
                        let start = (full_start_ns + offset).min(max_start);
                        on_change_range.call((start, view_end_ns, true));
                    }
                },
            }
            input {
                r#type: "range",
                class: "timeline-range-slider",
                min: "0",
                max: "{full_range_ns}",
                step: "{drag_step_ns}",
                value: "{view_end_ns.saturating_sub(full_start_ns)}",
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let min_end = (view_start_ns + min_window_ns).min(full_end_ns);
                        let end = (full_start_ns + offset).max(min_end).min(full_end_ns);
                        on_change_range.call((view_start_ns, end, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let min_end = (view_start_ns + min_window_ns).min(full_end_ns);
                        let end = (full_start_ns + offset).max(min_end).min(full_end_ns);
                        on_change_range.call((view_start_ns, end, true));
                    }
                },
            }
        }
    }
}

fn get_event_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "bg-blue-500",
        "process_fork" => "bg-green-500",
        "process_exit" => "bg-red-500",
        "page_fault" => "bg-orange-500",
        _ if event_type.contains("syscall") => "bg-purple-500",
        _ => "bg-gray-500",
    }
}

fn get_event_text_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "text-blue-600",
        "process_fork" => "text-green-600",
        "process_exit" => "text-red-600",
        "page_fault" => "text-orange-600",
        _ if event_type.contains("syscall") => "text-purple-600",
        _ => "text-gray-600",
    }
}

fn format_duration(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.2}s", s)
    } else if ms >= 1.0 {
        format!("{:.2}ms", ms)
    } else if us >= 1.0 {
        format!("{:.1}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

fn format_net_bytes_signed(allocated: u64, freed: u64) -> String {
    if allocated >= freed {
        format!("+{}", format_bytes(allocated - freed))
    } else {
        format!("-{}", format_bytes(freed - allocated))
    }
}

fn format_duration_short(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.1}s", s)
    } else if ms >= 1.0 {
        format!("{:.0}ms", ms)
    } else if us >= 1.0 {
        format!("{:.0}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

fn format_event_details(event: &TraceEvent) -> String {
    match event.event_type.as_str() {
        "sched_switch" => {
            let prev = event.prev_pid.map(|p| p.to_string()).unwrap_or_default();
            let next = event.next_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", prev, next)
        }
        "process_fork" => {
            let parent = event.parent_pid.map(|p| p.to_string()).unwrap_or_default();
            let child = event.child_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", parent, child)
        }
        "process_exit" => {
            format!("exit: {}", event.exit_code.unwrap_or(0))
        }
        "page_fault" => {
            let addr = event.address.map(|a| format!("0x{:x}", a)).unwrap_or_default();
            format!("@ {}", addr)
        }
        "syscall_read_enter" | "syscall_write_enter" => {
            format!("fd:{} len:{}", event.fd.unwrap_or(-1), event.count.unwrap_or(0))
        }
        "syscall_read_exit" | "syscall_write_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_mmap_enter" => {
            let addr = event.address.map(|a| format!("0x{:x}", a)).unwrap_or_default();
            format!("addr:{} len:{}", addr, event.count.unwrap_or(0))
        }
        "syscall_mmap_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_munmap_enter" => {
            let addr = event.address.map(|a| format!("0x{:x}", a)).unwrap_or_default();
            format!("addr:{} len:{}", addr, event.count.unwrap_or(0))
        }
        "syscall_munmap_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_brk_enter" => {
            let addr = event.address.map(|a| format!("0x{:x}", a)).unwrap_or_default();
            format!("brk:{}", addr)
        }
        "syscall_brk_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        _ => String::new(),
    }
}
