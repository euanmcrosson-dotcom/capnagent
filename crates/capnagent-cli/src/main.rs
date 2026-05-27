//! `capnagent` CLI — mint, issue, verify, and inspect capability tokens for
//! AI agent tool calls.
//!
//! - Legacy flat flags (`--agent --tools --limit --ttl`), dispatched by the
//!   Capframe umbrella CLI (`capframe bind`). Mints a single token.
//! - `issue --from-caveats <mcp-recon/v0.1/caveats>` — the Find → Bind handoff.
//! - `verify <token> --context <json>` — run the full pipeline; print the
//!   receipt; exit 0 (allowed) / 2 (denied) / 1 (chain or audit failure).
//! - `inspect <token>` — decode a token's caveats/identifier (no key, no
//!   verification).
//! - `keygen` — emit a fresh base64 CSPRNG root key.
//!
//! There is no default signing key: every key-using path requires an explicit
//! `--key` / `CAPNAGENT_KEY` and fails closed otherwise.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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
    /// Required — there is no default key. Generate one with `capnagent keygen`.
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

    /// Generate a fresh base64-encoded 32-byte root key from the OS CSPRNG.
    /// Use its output as `--key` / `CAPNAGENT_KEY`.
    Keygen,

    /// Decode and display a token's contents (identifier, caveats,
    /// holder-of-key) WITHOUT verifying. No key required — `parse` performs no
    /// signature check, so this never implies the token is authentic.
    Inspect {
        /// The serialized capability token.
        token: String,
        /// Pretty-print the emitted JSON.
        #[arg(long)]
        pretty: bool,
    },

    /// Verify a token against a context and print the receipt JSON. Exit code:
    /// 0 if the outcome is `allowed`, 2 if `denied`, 1 on chain/audit failure.
    Verify {
        /// The serialized capability token.
        token: String,
        /// Context as a JSON string, e.g.
        /// `{"caller":"a","tool":"t","args":{},"nowMs":1700000000000}`.
        #[arg(long)]
        context: String,
        /// Root signing key, base64-encoded (or via CAPNAGENT_KEY).
        #[arg(long, env = "CAPNAGENT_KEY")]
        key: Option<String>,
        /// Audit key, base64-encoded. If omitted, an ephemeral key is
        /// generated (the receipt's audit signature is then only locally
        /// meaningful — fine for a one-shot allow/deny check).
        #[arg(long)]
        audit_key: Option<String>,
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
        Some(Cmd::Keygen) => run_keygen(),
        Some(Cmd::Inspect { token, pretty }) => run_inspect(&token, pretty),
        Some(Cmd::Verify {
            token,
            context,
            key,
            audit_key,
            pretty,
        }) => run_verify(
            &token,
            &context,
            key.as_deref(),
            audit_key.as_deref(),
            pretty,
        ),
        None => run_legacy(&cli),
    }
}

/// 32 random bytes from the OS CSPRNG.
fn random_key() -> Result<[u8; 32]> {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| anyhow!("OS RNG failed: {e}"))?;
    Ok(k)
}

fn run_keygen() -> Result<()> {
    println!("{}", B64.encode(random_key()?));
    Ok(())
}

fn run_inspect(token: &str, pretty: bool) -> Result<()> {
    let cap = capnagent_core::Capability::parse(token).context("parse token")?;
    let hok = cap
        .holder_of_key
        .as_ref()
        .map(|k| k.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let out = json!({
        "identifier": cap.identifier,
        "holder_of_key": hok,
        "caveats": cap.caveats.iter().map(|c| &c.predicate).collect::<Vec<_>>(),
    });
    print_json(&out, pretty);
    Ok(())
}

fn run_verify(
    token: &str,
    context: &str,
    key: Option<&str>,
    audit_key: Option<&str>,
    pretty: bool,
) -> Result<()> {
    let key = resolve_key(key)?;
    let audit = match audit_key {
        Some(s) => {
            let k = B64.decode(s).context("decode --audit-key as base64")?;
            if k.len() < 16 {
                return Err(anyhow!(
                    "--audit-key too short ({} bytes); use >= 16 bytes",
                    k.len()
                ));
            }
            k
        }
        None => random_key()?.to_vec(),
    };

    let cap = capnagent_core::Capability::parse(token).context("parse token")?;
    let parsed: CtxIn = serde_json::from_str(context).context("parse --context as JSON")?;
    let ctx = ctx_in_to_core(parsed);

    let verifier = capnagent_core::Verifier::new(&key);
    let auditor = capnagent_core::Auditor::new(&audit);
    // Chain / audit failures raise; caveat denials come back on the receipt.
    let receipt = verifier
        .verify_with_context(&cap, &ctx, &auditor)
        .map_err(|e| anyhow!("verification failed: {e}"))?;
    let value: serde_json::Value = serde_json::to_value(&receipt).context("serialize receipt")?;
    let denied = value
        .get("outcome")
        .and_then(|o| o.get("kind"))
        .and_then(|k| k.as_str())
        == Some("denied");
    print_json(&value, pretty);
    if denied {
        std::process::exit(2);
    }
    Ok(())
}

fn print_json(v: &serde_json::Value, pretty: bool) {
    let s = if pretty {
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    } else {
        v.to_string()
    };
    println!("{s}");
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

/// Resolve the root signing key. Fails closed: there is **no** placeholder /
/// default key — minting or verifying with a silent public key is a footgun a
/// security tool should never ship. The caller must supply a key explicitly.
fn resolve_key(supplied: Option<&str>) -> Result<Vec<u8>> {
    let s = supplied.ok_or_else(|| {
        anyhow!(
            "no signing key. Set CAPNAGENT_KEY (base64) or pass --key. \
             Generate one with `capnagent keygen`."
        )
    })?;
    let key = B64
        .decode(s)
        .context("decode --key/CAPNAGENT_KEY as base64")?;
    if key.len() < 16 {
        return Err(anyhow!(
            "signing key too short ({} bytes); use >= 32 bytes from a CSPRNG (`capnagent keygen`)",
            key.len()
        ));
    }
    Ok(key)
}

// ── Context decode (matches the py/wasm crates' `CtxIn` / `ctx_in_to_core`) ──

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CtxIn {
    now_ms: Option<u64>,
    caller: String,
    tool: String,
    args: serde_json::Value,
    env: Option<std::collections::HashMap<String, String>>,
}

fn ctx_in_to_core(parsed: CtxIn) -> capnagent_core::Context {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = parsed
        .now_ms
        .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
        .unwrap_or_else(SystemTime::now);
    capnagent_core::Context {
        now,
        caller: parsed.caller,
        tool: parsed.tool,
        args: parsed.args,
        env: parsed.env.unwrap_or_default(),
    }
}

fn mint(key: &[u8], agent: &str, tools: &str, limits: &[String], ttl: &str) -> Result<String> {
    let issuer = Issuer::from_key(key);
    let mut builder = issuer.issue(agent);

    // Tool scope as a verifiable OR-chain of `tool == "..."`. (The caveat DSL
    // has no `in` operator — the old `tool in [...]` form never verified.)
    let tool_clause = tools
        .split(',')
        .map(|s| format!("tool == {:?}", s.trim()))
        .collect::<Vec<_>>()
        .join(" OR ");
    builder = builder.caveat(tool_clause);

    // Limits bind to call arguments, so they must be `arg.<key>` — a bare
    // ident is an unknown-ident denial at verify time.
    for raw in limits {
        let (k, v) = raw
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid limit `{raw}` — expected key=value"))?;
        let (k, v) = (k.trim(), v.trim());
        let predicate = if v.parse::<f64>().is_ok() {
            format!("arg.{k} <= {v}")
        } else {
            format!("arg.{k} == {v:?}")
        };
        builder = builder.caveat(predicate);
    }

    // TTL as an enforceable expiry: `now <= @<rfc3339>`. (The old
    // `ttl == "24h"` was an unverifiable label — `ttl` is not a context field.)
    let secs = parse_ttl(ttl)?;
    let expiry = OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(secs as i64))
        .ok_or_else(|| anyhow!("ttl `{ttl}` overflows the representable time range"))?;
    let expiry_str = expiry.format(&Rfc3339).context("format expiry timestamp")?;
    builder = builder.caveat(format!("now <= @{expiry_str}"));

    Ok(builder.build().serialize())
}

/// Parse a TTL like `30m`, `24h`, `7d`, `3600s` into seconds.
fn parse_ttl(ttl: &str) -> Result<u64> {
    let ttl = ttl.trim();
    let (num, unit) = ttl.split_at(
        ttl.char_indices()
            .find(|(_, c)| c.is_ascii_alphabetic())
            .map(|(i, _)| i)
            .ok_or_else(|| anyhow!("invalid --ttl `{ttl}` — expected e.g. 30m, 24h, 7d"))?,
    );
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("invalid --ttl `{ttl}` — expected e.g. 30m, 24h, 7d"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(anyhow!("invalid --ttl unit `{other}` — use s, m, h, or d")),
    };
    Ok(n * mult)
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
        // Tool scope is a verifiable OR-chain; limits bind to `arg.*`; the TTL
        // becomes an enforceable `now <= @<expiry>` (all parse as caveat DSL).
        assert!(preds.iter().any(|p| p.contains(r#"tool == "order.read""#)));
        assert!(preds
            .iter()
            .any(|p| p.contains(r#"tool == "refund.write""#)));
        assert!(preds.iter().any(|p| p.contains("arg.max_refund <= 50")));
        assert!(preds.iter().any(|p| p.contains(r#"arg.region == "eu""#)));
        assert!(preds.iter().any(|p| p.starts_with("now <= @")));
        // Every minted caveat must parse as caveat DSL (the old `tool in [...]`
        // and `ttl == "24h"` forms did not — tokens that could never verify).
        for p in &preds {
            assert!(
                capnagent_core::caveat_dsl::parse(p).is_ok(),
                "minted caveat must be valid DSL: {p}"
            );
        }
    }

    #[test]
    fn rejects_malformed_limit() {
        let err = mint(b"k", "a", "t", &["no_equals_sign".into()], "24h");
        assert!(err.is_err());
    }
}
