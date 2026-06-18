use clap::Parser;
use sccm_rc_diag::{checks, Severity};

#[derive(Parser)]
#[command(
    name = "sccm-rc-diag",
    about = "Pre-flight diagnostics for SCCM Remote Control targets.\n\
             Run this BEFORE CmRcViewer to see which prerequisite is missing.",
    version
)]
struct Cli {
    /// Target hostname or IP
    target: String,

    /// Viewer user account (defaults to current user)
    #[arg(long, short = 'u')]
    user: Option<String>,

    /// Output as JSON (for integration with the viewer UI)
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let viewer_user = cli
        .user
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_default();

    let results = checks::run_all(&cli.target, &viewer_user).await;

    if cli.json {
        // Minimal JSON encoder — avoids pulling in serde just for this.
        println!("[");
        for (i, r) in results.iter().enumerate() {
            let sev = match r.severity {
                Severity::Ok => "ok",
                Severity::Warning => "warning",
                Severity::Blocker => "blocker",
            };
            let msg = json_escape(&r.message);
            let rem = r
                .remediation
                .as_deref()
                .map(|s| format!(r#""{}""#, json_escape(s)))
                .unwrap_or_else(|| "null".to_string());
            let comma = if i + 1 < results.len() { "," } else { "" };
            println!(
                r#"  {{"name":"{}","severity":"{}","message":"{}","remediation":{},"duration_ms":{}}}{}"#,
                r.name,
                sev,
                msg,
                rem,
                r.duration.as_millis(),
                comma
            );
        }
        println!("]");
    } else {
        println!("SCCM RC pre-flight for {}\n", cli.target);
        let mut blockers = 0;
        for r in &results {
            let badge = match r.severity {
                Severity::Ok => "  OK   ",
                Severity::Warning => " WARN  ",
                Severity::Blocker => "BLOCKER",
            };
            println!("[{}] {}  ({:?})", badge, r.name, r.duration);
            for line in r.message.lines() {
                println!("        {line}");
            }
            if let Some(rem) = &r.remediation {
                println!("        → Remediation:");
                for line in rem.lines() {
                    println!("            {line}");
                }
            }
            println!();
            if r.severity == Severity::Blocker {
                blockers += 1;
            }
        }
        if blockers > 0 {
            std::process::exit(2);
        }
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
        .replace('\r', r"\r")
}
