use charming::Chart;
use dioxus::prelude::*;

static CHART_ID_COUNTER: GlobalSignal<u64> = Signal::global(|| 0);

fn next_chart_id() -> String {
    let id = CHART_ID_COUNTER();
    *CHART_ID_COUNTER.write() = id + 1;
    format!("echart-{id}")
}

#[component]
pub fn EChart(chart: Chart, height: String) -> Element {
    let chart_id = use_hook(next_chart_id);
    let chart_json = chart.to_string();

    let init_js = format!(
        r#"
        (function() {{
            var el = document.getElementById("{chart_id}");
            if (!el) return;
            var instance = echarts.getInstanceByDom(el) || echarts.init(el);
            instance.setOption({chart_json}, true);
            new ResizeObserver(function() {{ instance.resize(); }}).observe(el);
        }})();
        "#
    );

    use_effect(move || {
        document::eval(&init_js);
    });

    rsx! {
        div {
            id: "{chart_id}",
            style: "width: 100%; height: {height};",
        }
    }
}
