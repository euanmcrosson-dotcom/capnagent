//! `capnagent` CLI — mint scoped, revocable capability tokens for AI agent
//! tool calls.
//!
//! Two modes:
//!   - Legacy flat flags (`--agent --tools --limit --ttl`), dispatched by the
//!     Capframe umbrella CLI (`capframe bind`). Mints a single token.
//!   - `capnagent issue --from-caveats <mcp-recon/v0.1/caveats>` — the Find →
//!     Bind handoff: read mcp-recon's caveats artifact and mint one capability
//!     token per `scope` plan, reporting the `deny` (code-execution) tools that
//!     were intentionally NOT granted.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use capnagent_core::Issuer;

#[derive(Parser, Debug)]
#[command(
    name = "capnagent",
    version,
    about = "Mint scoped, revocable capability tokens for AI agent tool calls"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    // ── Legacy flat flags: `capnagent --agent X --tools "a,b" --limit k=v` ──
    // Kept so `capframe bind` (which dispatches this shape) is unaffected.
    /// Logical agent name (becomes the capability identifier).
    #[arg(long)]
    agent: Option<String>,

    /// Comma-separated tool scopes (e.g. "order.read, refund.write").
    #[arg(long)]
    tools: Option<String>,

    /// Repeatable constraint, format `key=value` (e.g. --limit max_refund=50).
    #[arg(long = "limit", num_args = 0..)]
    limits: Vec<String>,

    /// Token TTL, e.g. 24h, 7d.
    #[arg(long, default_value = "24h")]
    ttl: String,

    /// Root secret key, base64-encoded. May also be supplied via CAPNAGENT_KEY.
    /// If unset, a public placeholder key is used and a warning is printed.
    #[arg(long, env = "CAPNAGENT_KEY")]
    key: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Issue capability tokens from an `mcp-recon/v0.1/caveats` artifact — the
    /// Find → Bind handoff. Mints one token per `scope` plan; reports `deny`
    /// (code-execution) tools that are intentionally NOT granted.
    Issue {
        /// Path to an `mcp-recon/v0.1/caveats` JSON file (`mcp-recon caveats`).
        #[arg(long)]
        from_caveats: PathBuf,
        /// Root secret key, base64-encoded (or via CAPNAGENT_KEY).
        #[arg(long, env = "CAPNAGENT_KEY")]
        key: Option<String>,
        /// Write the issued-tokens JSON here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Pretty-print the emitted JSON.
        #[arg(long)]
        pretty: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Issue {
            from_caveats,
            key,
            out,
            pretty,
        }) => run_issue(&from_caveats, key.as_deref(), out.as_deref(), pretty),
        None => run_legacy(&cli),
    }
}

// ── mcp-recon/v0.1/caveats artifact (only the fields we consume) ──────────────

#[derive(Debug, Deserialize)]
struct CaveatArtifact {
    schema: String,
    #[serde(default)]
    plans: Vec<CaveatPlan>,
}

#[derive(Debug, Deserialize)]
struct CaveatPlan {
    tool: String,
    recommend: String,
    #[serde(default)]
    caveats: Vec<String>,
    #[serde(default)]
    note: String,
}

/// One minted token in the issuance result.
#[derive(Debug, Serialize)]
struct IssuedToken {
    tool: String,
    token: String,
    caveats: Vec<String>,
}

/// One tool that was intentionally not granted.
#[derive(Debug, Serialize)]
struct DeniedTool {
    tool: String,
    reason: String,
}

/// Result of issuing from a caveats artifact.
#[derive(Debug, Serialize)]
struct IssueResult {
    issued: Vec<IssuedToken>,
    denied: Vec<DeniedTool>,
}

fn run_legacy(cli: &Cli) -> Result<()> {
    let agent = cli.agent.as_deref().ok_or_else(|| {
        anyhow!("--agent is required (or use `capnagent issue --from-caveats <file>`)")
    })?;
    let tools = cli
        .tools
        .as_deref()
        .ok_or_else(|| anyhow!("--tools is required"))?;
    let key = resolve_key(cli.key.as_deref())?;
    let token = mint(&key, agent, tools, &cli.limits, &cli.ttl)?;
    println!("{token}");
    Ok(())
}

fn run_issue(
    from_caveats: &Path,
    key: Option<&str>,
    out: Option<&Path>,
    pretty: bool,
) -> Result<()> {
    let key = resolve_key(key)?;
    let body = fs::read_to_string(from_caveats)
        .with_context(|| format!("read {}", from_caveats.display()))?;
    let result = issue_from_caveats(&key, &body)?;
    let json = if pretty {
        serde_json::to_string_pretty(&result)?
    } else {
        serde_json::to_string(&result)?
    };
    match out {
        Some(p) => fs::write(p, json).with_context(|| format!("write {}", p.display()))?,
        None => println!("{json}"),
    }
    eprintln!(
        "capnagent: issued {} token(s); {} tool(s) denied (not granted)",
        result.issued.len(),
        result.denied.len()
    );
    Ok(())
}

/// Mint a token per `scope` plan in an `mcp-recon/v0.1/caveats` artifact; record
/// `deny` plans as not-granted. Every caveat is validated against the caveat DSL
/// before issuance, so a malformed predicate fails closed rather than producing
/// a token nobody can evaluate.
fn issue_from_caveats(key: &[u8], artifact_json: &str) -> Result<IssueResult> {
    let artifact: CaveatArtifact =
        serde_json::from_str(artifact_json).context("parse mcp-recon/v0.1/caveats artifact")?;
    if artifact.schema != "mcp-recon/v0.1/caveats" {
        return Err(anyhow!(
            "unexpected schema `{}` (expected `mcp-recon/v0.1/caveats`)",
            artifact.schema
        ));
    }

    let issuer = Issuer::from_key(key);
    let mut issued = Vec::new();
    let mut denied = Vec::new();

    for plan in artifact.plans {
        if plan.recommend == "deny" {
            denied.push(DeniedTool {
                tool: plan.tool,
                reason: plan.note,
            });
            continue;
        }

        // Validate every caveat against the DSL before minting, so a malformed
        // predicate fails closed rather than producing an unevaluable token.
        for c in &plan.caveats {
            capnagent_core::caveat_dsl::parse(c).map_err(|e| {
                anyhow!(
                    "tool `{}`: caveat `{c}` is not valid caveat DSL: {e}",
                    plan.tool
                )
            })?;
        }

        let mut builder = issuer.issue(&plan.tool);
        for c in &plan.caveats {
            builder = builder.caveat(c.clone());
        }
        issued.push(IssuedToken {
            token: builder.build().serialize(),
            tool: plan.tool,
            caveats: plan.caveats,
        });
    }

    Ok(IssueResult { issued, denied })
}

fn resolve_key(supplied: Option<&str>) -> Result<Vec<u8>> {
    match supplied {
        Some(s) => B64
            .decode(s)
            .context("decode --key/CAPNAGENT_KEY as base64"),
        None => {
            eprintln!(
                "warning: no --key/CAPNAGENT_KEY supplied; using a public placeholder key.\n\
                 Tokens minted with this key MUST NOT be used in production."
            );
            Ok(b"capnagent-public-dev-placeholder-key".to_vec())
        }
    }
}

fn mint(key: &[u8], agent: &str, tools: &str, limits: &[String], ttl: &str) -> Result<String> {
    let issuer = Issuer::from_key(key);
    let mut builder = issuer.issue(agent);

    let tool_list = tools
        .split(',')
        .map(|s| format!("\"{}\"", s.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    builder = builder.caveat(format!("tool in [{tool_list}]"));

    for raw in limits {
        let (k, v) = raw
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid limit `{raw}` — expected key=value"))?;
        let predicate = if v.parse::<f64>().is_ok() || v.parse::<i64>().is_ok() {
            format!("{} <= {}", k.trim(), v.trim())
        } else {
            format!("{} == \"{}\"", k.trim(), v.trim())
        };
        builder = builder.caveat(predicate);
    }

    builder = builder.caveat(format!("ttl == \"{ttl}\""));

    Ok(builder.build().serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ARTIFACT: &str = r#"{
        "schema": "mcp-recon/v0.1/caveats",
        "plans": [
            { "tool": "order.refund", "recommend": "scope",
              "caveats": ["tool == \"order.refund\"", "arg.amount <= 100"],
              "provenance": ["r4"], "note": "cap the refund amount" },
            { "tool": "puppeteer_evaluate", "recommend": "deny",
              "caveats": ["tool != \"puppeteer_evaluate\""],
              "provenance": ["r7"], "note": "code execution surface" }
        ]
    }"#;

    #[test]
    fn issues_scope_plans_and_denies_exec_tools() {
        let r = issue_from_caveats(b"test-key", SAMPLE_ARTIFACT).unwrap();
        assert_eq!(r.issued.len(), 1, "one scope plan should mint one token");
        assert_eq!(r.issued[0].tool, "order.refund");
        let parsed =
            capnagent_core::Capability::parse(&r.issued[0].token).expect("token round-trips");
        let preds: Vec<&str> = parsed
            .caveats
            .iter()
            .map(|c| c.predicate.as_str())
            .collect();
        assert!(
            preds.iter().any(|p| p.contains("arg.amount <= 100")),
            "issued token should carry the cap caveat; got {preds:?}"
        );
        assert_eq!(r.denied.len(), 1, "the exec tool should be denied");
        assert_eq!(r.denied[0].tool, "puppeteer_evaluate");
    }

    #[test]
    fn rejects_wrong_schema() {
        let bad = r#"{ "schema": "something/else", "plans": [] }"#;
        assert!(issue_from_caveats(b"k", bad).is_err());
    }

    #[test]
    fn rejects_unparseable_caveat_fail_closed() {
        let bad = r#"{ "schema": "mcp-recon/v0.1/caveats", "plans": [
            { "tool": "x", "recommend": "scope", "caveats": ["%%% not a predicate %%%"],
              "provenance": [], "note": "" } ] }"#;
        assert!(
            issue_from_caveats(b"k", bad).is_err(),
            "a malformed caveat must fail closed, not mint an unevaluable token"
        );
    }

    #[test]
    fn mints_token_with_caveats() {
        let token = mint(
            b"test-key",
            "shopify-bot",
            "order.read, refund.write",
            &["max_refund=50".into(), "region=eu".into()],
            "24h",
        )
        .unwrap();
        assert!(!token.is_empty());
        let parsed = capnagent_core::Capability::parse(&token).expect("round-trip");
        let preds: Vec<&str> = parsed
            .caveats
            .iter()
            .map(|c| c.predicate.as_str())
            .collect();
        assert!(preds.iter().any(|p| p.contains("order.read")));
        assert!(preds.iter().any(|p| p.contains("max_refund <= 50")));
        assert!(preds.iter().any(|p| p.contains("region == \"eu\"")));
        assert!(preds.iter().any(|p| p.contains("ttl == \"24h\"")));
    }

    #[test]
    fn rejects_malformed_limit() {
        let err = mint(b"k", "a", "t", &["no_equals_sign".into()], "24h");
        assert!(err.is_err());
    }
}
