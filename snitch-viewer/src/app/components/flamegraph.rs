use dioxus::prelude::*;

use crate::app::formatting::format_duration_short;
use crate::server::EventFlamegraphResponse;

#[component]
pub fn EventFlamegraphCard(
    selected_event_type: Option<String>,
    event_type_options: Vec<String>,
    selected_pid: Option<u32>,
    full_start_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    on_select_event_type: EventHandler<Option<String>>,
    flamegraph: Option<EventFlamegraphResponse>,
) -> Element {
    let event_type = selected_event_type.unwrap_or_default();
    let flamegraph_data = flamegraph.unwrap_or_default();
    let total = flamegraph_data.total_samples;
    let svg_doc = flamegraph_data.svg.unwrap_or_default();
    let framed_svg_doc = if svg_doc.is_empty() {
        String::new()
    } else {
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"/><style>\
             html,body{{margin:0;padding:0;width:100%;height:100%;overflow:auto;background:#fff;}}\
             svg{{display:block;width:100% !important;min-width:100%;height:auto !important;}}\
             </style></head><body>{svg}</body></html>",
            svg = svg_doc
        )
    };
    let range_width = view_end_ns.saturating_sub(view_start_ns);
    let start_offset = view_start_ns.saturating_sub(full_start_ns);
    let end_offset = view_end_ns.saturating_sub(full_start_ns);
    let pid_scope = selected_pid
        .map(|pid| format!("PID {pid}"))
        .unwrap_or_else(|| "All PIDs".to_string());

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg px-2.5 py-2 space-y-1.5",
            div { class: "flex flex-wrap items-center gap-2",
                label { class: "text-xs text-gray-600", "Flamegraph event:" }
                select {
                    class: "px-2 py-0.5 border border-gray-200 rounded text-xs bg-white min-w-[14rem]",
                    value: "{event_type}",
                    onchange: move |evt| {
                        let value = evt.value();
                        if value.is_empty() {
                            on_select_event_type.call(None);
                        } else {
                            on_select_event_type.call(Some(value));
                        }
                    },
                    option { value: "", "None" }
                    {event_type_options.into_iter().map(|event_name| rsx! {
                        option { key: "{event_name}", value: "{event_name}", "{event_name}" }
                    })}
                }
                if total > 0 {
                    span { class: "ml-auto text-xs text-gray-500", "{total} samples" }
                } else {
                    span { class: "ml-auto text-xs text-gray-400", "0 samples" }
                }
            }

            div { class: "text-[11px] text-gray-500",
                "Scope: {pid_scope} · T+{format_duration_short(start_offset)}..T+{format_duration_short(end_offset)} (width {format_duration_short(range_width)})"
            }

            if event_type.is_empty() {
                div { class: "text-xs text-gray-400", "Select an event type to build a flamegraph for the current scope" }
            } else {
                div { class: "text-xs text-gray-600",
                    "Event: "
                    span { class: "font-mono text-gray-800", "{event_type}" }
                }
            }

            if !event_type.is_empty() && total == 0 {
                div { class: "text-xs text-gray-400", "No stack samples in current scope" }
            } else if !event_type.is_empty() {
                if svg_doc.is_empty() {
                    div { class: "text-xs text-gray-400", "Flamegraph rendering returned empty SVG" }
                } else {
                    iframe {
                        class: "w-full h-[360px] border border-gray-100 rounded bg-white",
                        srcdoc: "{framed_svg_doc}",
                    }
                }
            }
        }
    }
}
