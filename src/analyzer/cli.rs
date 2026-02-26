use super::{AlertAnalyzer, Result, load_config};
use clap::Parser;
use serde_json::Value;

#[derive(Debug, Parser, Clone)]
#[command(name = "alert-analyzer")]
#[command(about = "Alert Analyzer - LLM-powered security alert analysis")]
pub struct CliArgs {
    #[arg(short = 'c', long = "config")]
    pub config: Option<String>,
    #[arg(short = 'p', long = "priority")]
    pub priority: Option<String>,
    #[arg(short = 'l', long = "last", default_value = "1h")]
    pub last: String,
    #[arg(short = 'n', long = "limit", default_value_t = 5)]
    pub limit: usize,
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,
    #[arg(short = 's', long = "store", default_value_t = false)]
    pub store: bool,
    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    pub verbose: bool,
    #[arg(short = 'j', long = "json", default_value_t = false)]
    pub json: bool,
    #[arg(long = "loki-url")]
    pub loki_url: Option<String>,
    #[arg(long = "victorialogs-url")]
    pub victorialogs_url: Option<String>,
    #[arg(short = 'b', long = "backend")]
    pub backend: Option<String>,
}

pub fn run_from_args(args: CliArgs) -> Result<i32> {
    let mut config = load_config(args.config.as_deref())?;

    if let Some(backend) = args.backend {
        config.storage.backend = backend;
    }
    if let Some(url) = args.loki_url {
        config.loki.url = url;
        config.storage.backend = "loki".to_string();
    }
    if let Some(url) = args.victorialogs_url {
        config.victorialogs.url = url;
        config.storage.backend = "victorialogs".to_string();
    }

    if !config.analysis.enabled {
        eprintln!("analysis is disabled in config. set analysis.enabled=true to enable");
        return Ok(1);
    }

    let analyzer = AlertAnalyzer::from_config(&config)?;
    eprintln!("fetching alerts from last {}...", args.last);
    let alerts = analyzer.fetch_alerts(args.priority.as_deref(), &args.last, args.limit)?;

    if alerts.is_empty() {
        println!("no alerts found matching criteria");
        return Ok(0);
    }

    eprintln!("found {} alerts. analyzing...", alerts.len());
    let results = analyzer.analyze_batch(&alerts, args.dry_run, args.store);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for result in &results {
            print_analysis(result, args.verbose);
        }
    }

    Ok(0)
}

fn print_analysis(result: &Value, verbose: bool) {
    let analysis = result
        .get("analysis")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    if let Some(err) = analysis.get("error").and_then(Value::as_str) {
        println!("analysis error: {err}");
        if let Some(fallback) = analysis.get("fallback_mitre") {
            println!("fallback mitre: {fallback}");
        }
        return;
    }

    println!("======================================================================");
    println!("SECURITY ALERT ANALYSIS");
    println!("======================================================================");

    println!(
        "attack vector: {}",
        analysis
            .get("attack_vector")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );

    let mitre = analysis
        .get("mitre_attack")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    println!(
        "mitre tactic: {}",
        mitre.get("tactic").and_then(Value::as_str).unwrap_or("N/A")
    );
    println!(
        "mitre technique: {} - {}",
        mitre
            .get("technique_id")
            .and_then(Value::as_str)
            .unwrap_or("N/A"),
        mitre
            .get("technique_name")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );

    let risk = analysis
        .get("risk")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    println!(
        "risk severity: {}",
        risk.get("severity")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );
    println!(
        "risk confidence: {}",
        risk.get("confidence")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );
    println!(
        "risk impact: {}",
        risk.get("impact").and_then(Value::as_str).unwrap_or("N/A")
    );

    let summary = analysis
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("N/A");
    println!("summary: {summary}");

    if verbose {
        println!("obfuscation mapping:");
        if let Some(mapping) = result.get("obfuscation_mapping") {
            println!(
                "{}",
                serde_json::to_string_pretty(mapping).unwrap_or_else(|_| "{}".to_string())
            );
        }
    }

    println!("======================================================================");
}
