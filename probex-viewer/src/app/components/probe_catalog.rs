use dioxus::prelude::*;
use std::collections::HashSet;

use crate::api::{ProbeSchema, ProbeSchemaKind, get_probe_schema_detail, get_probe_schemas_page};

const PAGE_SIZE: usize = 400;
const DEFAULT_KIND_FILTERS: &[&str] = &["tracepoint", "fentry", "fexit"];

#[component]
pub fn ProbeCatalog() -> Element {
    let mut search_query = use_signal(String::new);
    let mut selected_kinds = use_signal(|| {
        DEFAULT_KIND_FILTERS
            .iter()
            .map(|v| (*v).to_string())
            .collect::<HashSet<String>>()
    });

    let mut selected_probes = use_signal(Vec::<String>::new);
    let mut expanded_probes = use_signal(HashSet::<String>::new);
    let mut detail_loading = use_signal(HashSet::<String>::new);

    let mut probes = use_signal(Vec::<ProbeSchema>::new);
    let mut probes_total = use_signal(|| 0usize);
    let mut probes_loading = use_signal(|| false);
    let mut backend_loading = use_signal(|| false);
    let mut has_more_pages = use_signal(|| false);
    let mut page_offset = use_signal(|| 0usize);
    let mut page_request_in_flight = use_signal(|| false);
    let mut probe_error = use_signal(|| Option::<String>::None);
    let mut refresh_nonce = use_signal(|| 0u64);

    use_resource(move || async move {
        page_request_in_flight.set(true);
        probes_loading.set(true);
        probe_error.set(None);
        let offset = page_offset();
        if offset == 0 {
            probes.set(Vec::new());
            probes_total.set(0);
            has_more_pages.set(false);
            backend_loading.set(false);
        }

        let query = if search_query().trim().is_empty() {
            None
        } else {
            Some(search_query().trim().to_string())
        };
        let mut values = selected_kinds().into_iter().collect::<Vec<_>>();
        values.sort_unstable();
        if values.is_empty() {
            probes.set(Vec::new());
            probes_total.set(0);
            has_more_pages.set(false);
            backend_loading.set(false);
            probes_loading.set(false);
            page_request_in_flight.set(false);
            return;
        }
        let kinds = Some(values.join(","));
        let source = None;

        let page = get_probe_schemas_page(query, None, kinds, source, offset, PAGE_SIZE).await;

        let page = match page {
            Ok(page) => page,
            Err(error) => {
                probe_error.set(Some(error));
                probes_loading.set(false);
                page_request_in_flight.set(false);
                return;
            }
        };

        backend_loading.set(page.is_loading);
        probes_total.set(page.total);
        has_more_pages.set(page.has_more);

        if offset == 0 {
            probes.set(page.probes);
        } else if !page.probes.is_empty() {
            let mut merged = probes();
            merged.extend(page.probes);
            probes.set(merged);
        }

        probes_loading.set(false);
        page_request_in_flight.set(false);
        let _ = refresh_nonce();
    });

    let selected_probe_set: HashSet<String> = selected_probes().iter().cloned().collect();
    let probes_snapshot = probes();
    let selected_probes_snapshot = selected_probes();

    rsx! {
        details { class: "rounded border border-gray-200 bg-gray-50 px-2 py-1",
            summary { class: "cursor-pointer text-xs text-gray-700 select-none", "Probe Schemas" }

            div { class: "mt-1 grid grid-cols-1 lg:grid-cols-3 gap-2",
                div { class: "lg:col-span-2 rounded border border-gray-200 bg-white p-2 space-y-2",
                    div { class: "flex items-center justify-between gap-2 flex-wrap",
                        span { class: "text-xs font-medium text-gray-700", "All Probes" }
                        div { class: "flex items-center gap-2",
                            span { class: "text-[11px] text-gray-500", "{probes_snapshot.len()} loaded / {probes_total()} matched" }
                            if probes_loading() || backend_loading() {
                                span { class: "inline-block h-3 w-3 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                            }
                        }
                    }

                    div { class: "grid grid-cols-1 gap-2",
                        input {
                            class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                            r#type: "text",
                            value: "{search_query}",
                            placeholder: "Search (backend)",
                            oninput: move |evt| {
                                search_query.set(evt.value());
                                page_offset.set(0);
                            },
                        }
                    }

                    div { class: "flex items-center gap-1.5 flex-wrap",
                        FilterChip {
                            label: "tracepoint",
                            active: selected_kinds().contains("tracepoint"),
                            active_class: kind_filter_active_class("tracepoint"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "tracepoint");
                                page_offset.set(0);
                            }),
                        }
                        FilterChip {
                            label: "fentry",
                            active: selected_kinds().contains("fentry"),
                            active_class: kind_filter_active_class("fentry"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "fentry");
                                page_offset.set(0);
                            }),
                        }
                        FilterChip {
                            label: "fexit",
                            active: selected_kinds().contains("fexit"),
                            active_class: kind_filter_active_class("fexit"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "fexit");
                                page_offset.set(0);
                            }),
                        }
                    }

                    if let Some(err) = probe_error() {
                        div { class: "rounded border border-red-200 bg-red-50 px-2 py-1 text-[11px] text-red-700",
                            "Failed to load probes: {err}"
                        }
                    }

                    if backend_loading() && !probes_loading() {
                        div { class: "flex items-center justify-between rounded border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] text-blue-700",
                            span { "Backend is still indexing probes. Results are progressively loading." }
                            button {
                                class: "px-2 py-0.5 rounded border border-blue-200 bg-white text-blue-700",
                                onclick: move |_| refresh_nonce.set(refresh_nonce().wrapping_add(1)),
                                "Refresh"
                            }
                        }
                    }

                    div {
                        class: "max-h-64 overflow-y-auto space-y-1 pr-1",
                        onscroll: move |evt: Event<dioxus::html::ScrollData>| {
                            if !has_more_pages() || probes_loading() || page_request_in_flight() {
                                return;
                            }
                            let remaining_px = evt.data().scroll_height() as f64
                                - (evt.data().scroll_top() + evt.data().client_height() as f64);
                            if remaining_px <= 180.0 {
                                page_offset.set(page_offset().saturating_add(PAGE_SIZE));
                            }
                        },
                        if probes_snapshot.is_empty() && !probes_loading() {
                            div { class: "text-[11px] text-gray-500 px-1 py-2", "No probes match current backend filters." }
                        }
                        {probes_snapshot.iter().map(|probe| {
                            let is_selected = selected_probe_set.contains(&probe.display_name);
                            let is_expanded = expanded_probes().contains(&probe.display_name);
                            let detail_is_loading = detail_loading().contains(&probe.display_name);
                            rsx! {
                                div { key: "{probe.display_name}", class: "rounded border border-gray-200 bg-gray-50 p-1.5",
                                    div { class: "flex items-center justify-between gap-2",
                                        div { class: "min-w-0",
                                            div { class: "font-mono text-[11px] text-gray-800 truncate", "{probe.display_name}" }
                                            div { class: "text-[10px] text-gray-500 flex items-center gap-1.5",
                                                span { class: kind_badge_class(&probe.kind), "{kind_label(&probe.kind)}" }
                                                span { "{probe.target}" }
                                                if !probe.fields.is_empty() {
                                                    span { "{probe.fields.len()} fields" }
                                                } else if !probe.args.is_empty() {
                                                    span { "{probe.args.len()} args" }
                                                }
                                            }
                                        }
                                        div { class: "flex items-center gap-1",
                                            button {
                                                class: "px-1.5 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600",
                                                onclick: {
                                                    let id = probe.display_name.clone();
                                                    move |_| {
                                                        let will_expand = !expanded_probes().contains(&id);
                                                        let mut expanded = expanded_probes();
                                                        if expanded.contains(&id) {
                                                            expanded.remove(&id);
                                                        } else {
                                                            expanded.insert(id.clone());
                                                        }
                                                        expanded_probes.set(expanded);

                                                        if will_expand {
                                                            let needs_detail = probes()
                                                                .iter()
                                                                .find(|p| p.display_name == id)
                                                                .map(|p| p.fields.is_empty() && p.args.is_empty() && p.return_type.is_none())
                                                                .unwrap_or(false);
                                                            if needs_detail {
                                                                let mut loading = detail_loading();
                                                                loading.insert(id.clone());
                                                                detail_loading.set(loading);

                                                                let detail_id = id.clone();
                                                                spawn(async move {
                                                                    let result = get_probe_schema_detail(detail_id.clone()).await;
                                                                    let mut loading = detail_loading();
                                                                    loading.remove(&detail_id);
                                                                    detail_loading.set(loading);

                                                                    match result {
                                                                        Ok(detail) => {
                                                                            let mut items = probes();
                                                                            if let Some(slot) = items.iter_mut().find(|p| p.display_name == detail_id) {
                                                                                *slot = detail;
                                                                            }
                                                                            probes.set(items);
                                                                        }
                                                                        Err(error) => probe_error.set(Some(error)),
                                                                    }
                                                                });
                                                            }
                                                        }
                                                    }
                                                },
                                                if is_expanded { "Hide" } else { "Fields" }
                                            }
                                            button {
                                                class: if is_selected {
                                                    "px-1.5 py-0.5 text-[11px] rounded border border-green-200 bg-green-50 text-green-700"
                                                } else {
                                                    "px-1.5 py-0.5 text-[11px] rounded border border-blue-200 bg-blue-50 text-blue-700"
                                                },
                                                onclick: {
                                                    let id = probe.display_name.clone();
                                                    move |_| {
                                                        let mut selected = selected_probes();
                                                        if selected.iter().any(|item| item == &id) {
                                                            selected.retain(|item| item != &id);
                                                        } else {
                                                            selected.push(id.clone());
                                                        }
                                                        selected_probes.set(selected);
                                                    }
                                                },
                                                if is_selected { "Added" } else { "+ Add" }
                                            }
                                        }
                                    }
                                    if is_expanded {
                                        div { class: "mt-1 border-t border-gray-200 pt-1 space-y-0.5",
                                            if detail_is_loading {
                                                div { class: "text-[10px] text-blue-600 flex items-center gap-1",
                                                    span { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                                                    "Loading field details..."
                                                }
                                            } else if probe.kind == ProbeSchemaKind::Tracepoint {
                                                if probe.fields.is_empty() {
                                                    div { class: "text-[10px] text-gray-500", "No field payload for this tracepoint." }
                                                } else {
                                                    {probe.fields.iter().map(|field| rsx! {
                                                        div { key: "{probe.display_name}:{field.name}:{field.offset}", class: "font-mono text-[10px] text-gray-600",
                                                            "{field.field_type} {field.name}"
                                                            span { class: "text-gray-400", " @+{field.offset} ({field.size}B)" }
                                                        }
                                                    })}
                                                }
                                            } else if probe.return_type.is_none() && probe.args.is_empty() {
                                                div { class: "text-[10px] text-gray-500", "No BTF signature available for this probe." }
                                            } else {
                                                div { class: "font-mono text-[10px] text-gray-600",
                                                    "returns "
                                                    span { class: "text-gray-800", "{probe.return_type.clone().unwrap_or_else(|| \"unknown\".to_string())}" }
                                                }
                                                if probe.args.is_empty() {
                                                    div { class: "text-[10px] text-gray-500", "No arguments." }
                                                } else {
                                                    {probe.args.iter().enumerate().map(|(idx, arg)| rsx! {
                                                        div { key: "{probe.display_name}:{idx}:{arg.name}", class: "font-mono text-[10px] text-gray-600",
                                                            "{arg.arg_type} {arg.name}"
                                                        }
                                                    })}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        })}
                        if has_more_pages() && probes_loading() {
                            div { class: "py-1 text-[11px] text-blue-600 flex items-center gap-1",
                                span { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                                "Loading more probes..."
                            }
                        }
                    }
                }

                div { class: "rounded border border-gray-200 bg-white p-2 space-y-2",
                    div { class: "flex items-center justify-between",
                        span { class: "text-xs font-medium text-gray-700", "Selected Probes" }
                        span { class: "text-[11px] text-gray-500", "{selected_probes_snapshot.len()}" }
                    }
                    if selected_probes_snapshot.is_empty() {
                        div { class: "text-[11px] text-gray-500", "Click + Add on any probe to build a mock selection list." }
                    } else {
                        div { class: "max-h-64 overflow-y-auto space-y-1 pr-1",
                            {selected_probes_snapshot.iter().map(|id| rsx! {
                                div { key: "{id}", class: "flex items-center justify-between gap-2 rounded border border-gray-200 bg-gray-50 px-1.5 py-1",
                                    span { class: "font-mono text-[10px] text-gray-700 truncate", "{id}" }
                                    button {
                                        class: "px-1.5 py-0.5 text-[10px] rounded border border-gray-200 bg-white text-gray-600 shrink-0",
                                        onclick: {
                                            let id = id.clone();
                                            move |_| {
                                                let mut selected = selected_probes();
                                                selected.retain(|item| item != &id);
                                                selected_probes.set(selected);
                                            }
                                        },
                                        "Remove"
                                    }
                                }
                            })}
                        }
                        button {
                            class: "px-2 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600",
                            onclick: move |_| selected_probes.set(Vec::new()),
                            "Clear all"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FilterChip(
    label: &'static str,
    active: bool,
    active_class: &'static str,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        button {
            class: if active {
                format!("px-2 py-0.5 text-[11px] rounded border {active_class}")
            } else {
                "px-2 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600"
            },
            onclick,
            "{label}"
        }
    }
}

fn toggle_kind_filter(signal: &mut Signal<HashSet<String>>, kind: &str) {
    let mut current = signal();
    if current.contains(kind) {
        current.remove(kind);
    } else {
        current.insert(kind.to_string());
    }
    signal.set(current);
}

fn kind_filter_active_class(kind: &str) -> &'static str {
    match kind {
        "tracepoint" => "border-slate-200 bg-slate-100 text-slate-700",
        "fentry" => "border-sky-200 bg-sky-100 text-sky-700",
        "fexit" => "border-cyan-200 bg-cyan-100 text-cyan-700",
        _ => "border-blue-200 bg-blue-50 text-blue-700",
    }
}

fn kind_label(kind: &ProbeSchemaKind) -> &'static str {
    match kind {
        ProbeSchemaKind::Tracepoint => "tracepoint",
        ProbeSchemaKind::Fentry => "fentry",
        ProbeSchemaKind::Fexit => "fexit",
    }
}

fn kind_badge_class(kind: &ProbeSchemaKind) -> &'static str {
    match kind {
        ProbeSchemaKind::Tracepoint => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-slate-100 text-slate-700"
        }
        ProbeSchemaKind::Fentry => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-sky-100 text-sky-700"
        }
        ProbeSchemaKind::Fexit => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-cyan-100 text-cyan-700"
        }
    }
}
