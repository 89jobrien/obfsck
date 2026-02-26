use super::AnalysisPageView;
use serde_json::{Value, json};

pub(super) fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn render_analysis_html(view: &AnalysisPageView<'_>) -> String {
    let severity = view
        .analysis
        .pointer("/risk/severity")
        .and_then(Value::as_str)
        .unwrap_or("medium")
        .to_ascii_lowercase();
    let severity_class = if ["critical", "high", "medium", "low"].contains(&severity.as_str()) {
        severity
    } else {
        "medium".to_string()
    };

    let attack_vector = html_escape(
        view.analysis
            .get("attack_vector")
            .and_then(Value::as_str)
            .unwrap_or("N/A"),
    );
    let summary = html_escape(
        view.analysis
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("N/A"),
    );
    let mitre_tactic = html_escape(
        view.analysis
            .pointer("/mitre_attack/tactic")
            .and_then(Value::as_str)
            .unwrap_or("Unknown"),
    );
    let mitre_technique_id = html_escape(
        view.analysis
            .pointer("/mitre_attack/technique_id")
            .and_then(Value::as_str)
            .unwrap_or("Unknown"),
    );
    let mitre_technique_name = html_escape(
        view.analysis
            .pointer("/mitre_attack/technique_name")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let risk_severity = html_escape(
        view.analysis
            .pointer("/risk/severity")
            .and_then(Value::as_str)
            .unwrap_or("Unknown"),
    );
    let risk_confidence = html_escape(
        view.analysis
            .pointer("/risk/confidence")
            .and_then(Value::as_str)
            .unwrap_or("Unknown"),
    );
    let risk_impact = html_escape(
        view.analysis
            .pointer("/risk/impact")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let fp_likelihood = html_escape(
        view.analysis
            .pointer("/false_positive/likelihood")
            .and_then(Value::as_str)
            .unwrap_or("Unknown"),
    );

    let mut investigate_items = String::new();
    if let Some(items) = view.analysis.get("investigate").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str() {
                investigate_items.push_str(&format!("<li>{}</li>", html_escape(text)));
            }
        }
    }

    let mitigations = view
        .analysis
        .get("mitigations")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut mitigation_sections = String::new();
    for (label, key) in [
        ("Immediate Actions", "immediate"),
        ("Short-term", "short_term"),
        ("Long-term", "long_term"),
    ] {
        let mut items_html = String::new();
        if let Some(items) = mitigations.get(key).and_then(Value::as_array) {
            for item in items {
                if let Some(text) = item.as_str() {
                    items_html.push_str(&format!("<li>{}</li>", html_escape(text)));
                }
            }
        }
        if !items_html.is_empty() {
            mitigation_sections.push_str(&format!("<h3>{label}</h3><ul>{items_html}</ul>"));
        }
    }

    let mapping_block = if view.show_mapping {
        format!(
            "<h2>Obfuscation Mapping</h2><pre>{}</pre>",
            html_escape(
                &serde_json::to_string_pretty(view.obfuscation_mapping).unwrap_or_default()
            )
        )
    } else {
        String::new()
    };

    if let Some(err) = view.error.clone() {
        return format!(
            "<!DOCTYPE html><html><head><title>Alert Analysis</title><style>body{{font-family:-apple-system,sans-serif;background:#111217;color:#d8d9da;padding:20px;}}.container{{max-width:900px;margin:0 auto;}}.error{{background:#f2495c22;border:1px solid #f2495c;padding:20px;border-radius:8px;color:#f2495c;}}</style></head><body><div class='container'><p><a href='/'>← API Home</a> · <a href='/history'>History</a></p><h1>Alert Analysis</h1><div class='error'><strong>Analysis Error:</strong> {}</div><p style='margin-top:20px;color:#8e8e8e;'>{}</p></div></body></html>",
            html_escape(&err),
            html_escape(view.timestamp)
        );
    }

    let cached_badge = if view.cached {
        " <span style='background:#3274d9;color:white;padding:4px 10px;border-radius:4px;font-size:0.85em;'>Cached</span>"
    } else {
        ""
    };

    let obf_section = if !view.obfuscated_output.is_empty()
        && view.obfuscated_output != view.original_output
    {
        format!(
            "<h2>What Was Sent to AI (Obfuscated)</h2><pre style='border-left:3px solid #73bf69;padding-left:10px;'>{}</pre>",
            html_escape(view.obfuscated_output)
        )
    } else {
        String::new()
    };

    let investigate_section = if investigate_items.is_empty() {
        String::new()
    } else {
        format!("<h2>Investigation Steps</h2><ol>{investigate_items}</ol>")
    };

    format!(
        "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>Alert Analysis</title><style>body{{font-family:-apple-system,sans-serif;background:#111217;color:#d8d9da;padding:20px;line-height:1.6;}}.container{{max-width:900px;margin:0 auto;}}h1{{color:#ff9830;}}h2{{color:#73bf69;}}.card{{background:#1f2129;border-radius:8px;padding:20px;margin-bottom:20px;border-left:4px solid #3274d9;}}.card.critical{{border-left-color:#f2495c;}}.card.high{{border-left-color:#ff9830;}}.card.medium{{border-left-color:#fade2a;}}.card.low{{border-left-color:#73bf69;}}pre{{background:#181b1f;padding:15px;border-radius:4px;overflow-x:auto;border:1px solid #2c3235;}}.badge{{display:inline-block;background:#3274d9;color:white;padding:4px 10px;border-radius:4px;font-size:0.85em;margin-right:8px;}}.severity{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;background:#2a2d35;}}</style></head><body><div class='container'><p><a href='/'>← API Home</a> · <a href='/history'>History</a></p><h1>Alert Analysis{cached_badge}</h1><div class='card'><strong>Privacy Protected:</strong> Sensitive data was obfuscated before AI analysis. <em>{}</em></div><h2>Original Alert</h2><pre>{}</pre>{obf_section}<div class='card {severity_class}'><h2>Attack Vector</h2><p>{attack_vector}</p><h2>MITRE ATT&CK</h2><p><span class='badge'>{mitre_tactic}</span><span class='badge'>{mitre_technique_id} - {mitre_technique_name}</span></p><h2>Risk Assessment</h2><p><span class='severity'>{risk_severity}</span> Confidence: {risk_confidence}</p><p>{risk_impact}</p></div><h2>Mitigations</h2><div class='card'>{}</div><h2>False Positive Assessment</h2><div class='card'><p>Likelihood: {fp_likelihood}</p></div>{investigate_section}<h2>Summary</h2><div class='card'><p>{summary}</p></div>{mapping_block}<p style='margin-top:40px;color:#6e6e6e;'>Analyzed at {}</p></div></body></html>",
        html_escape(view.timestamp),
        html_escape(view.original_output),
        mitigation_sections,
        html_escape(view.timestamp)
    )
}
