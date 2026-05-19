//! `capnagent` CLI — thin wrapper over `capnagent-core::Issuer` that mints a
//! serialized capability token from `--agent`, `--tools`, repeatable
//! `--limit key=value`, and a `--ttl` argument. Designed to be dispatched by
//! the Capframe umbrella CLI (`capframe bind`).

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;

use capnagent_core::Issuer;

#[derive(Parser, Debug)]
#[command(
    name = "capnagent",
    version,
    about = "Mint scoped, revocable capability tokens for AI agent tool calls"
)]
struct Cli {
    /// Logical agent name (becomes the capability identifier)
    #[arg(long)]
    agent: String,

    /// Comma-separated tool scopes (e.g. "order.read, refund.write")
    #[arg(long)]
    tools: String,

    /// Repeatable constraint, format `key=value` (e.g. --limit max_refund=50)
    #[arg(long = "limit", num_args = 0..)]
    limits: Vec<String>,

    /// Token TTL, e.g. 24h, 7d
    #[arg(long, default_value = "24h")]
    ttl: String,

    /// Root secret key, base64-encoded. May also be supplied via CAPNAGENT_KEY.
    /// If unset, a public placeholder key is used and a warning is printed.
    #[arg(long, env = "CAPNAGENT_KEY")]
    key: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = resolve_key(cli.key.as_deref())?;
    let token = mint(&key, &cli.agent, &cli.tools, &cli.limits, &cli.ttl)?;
    println!("{token}");
    Ok(())
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
