/**
 * CLI entry point for the LLM-driven shopping-agent demo.
 *
 *   npm run demo:llm           — honest scenario
 *   npm run demo:llm-injected  — naive scenario (forced to follow tool-output instructions)
 *   npm run demo:llm-direct    — direct scenario (user explicitly asks for a wire + a cable)
 *   npm run demo:llm-hok       — hok scenario (direct flow + DPoP-style holder-of-key)
 *
 * Requires ANTHROPIC_API_KEY in the environment. Override the model
 * with CAPNAGENT_DEMO_MODEL=claude-haiku-4-5 for cheaper iteration.
 */

import { type LlmDemoEvent, type Scenario, runLlmDemo } from "../llm-runner.js";

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const CYAN = "\x1b[36m";

function event(e: LlmDemoEvent): void {
  switch (e.kind) {
    case "thinking":
      process.stdout.write(`${DIM}[thinking]${RESET}\n`);
      break;
    case "agent_text":
      process.stdout.write(`${e.text}\n`);
      break;
    case "tool_call":
      process.stdout.write(`${BLUE}→ ${e.name}${RESET} ${DIM}${JSON.stringify(e.input)}${RESET}\n`);
      break;
    case "tool_result_ok":
      process.stdout.write(
        `  ${GREEN}✓ allowed${RESET} ${DIM}${truncate(JSON.stringify(e.result), 200)}${RESET}\n`,
      );
      break;
    case "tool_result_denied":
      process.stdout.write(`  ${RED}✗ DENIED${RESET} ${e.reason}\n`);
      break;
    case "stop":
      process.stdout.write(`${DIM}(stop_reason: ${e.reason})${RESET}\n\n`);
      break;
  }
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

async function main(): Promise<void> {
  const scenarioArg = process.argv[2] ?? "honest";
  if (
    scenarioArg !== "honest" &&
    scenarioArg !== "naive" &&
    scenarioArg !== "direct" &&
    scenarioArg !== "hok"
  ) {
    console.error(
      `Usage: demo-llm.ts <honest|naive|direct|hok>   (got ${JSON.stringify(scenarioArg)})`,
    );
    process.exit(2);
  }
  const scenario: Scenario = scenarioArg;

  if (!process.env["ANTHROPIC_API_KEY"]) {
    console.error(
      `${RED}ANTHROPIC_API_KEY is not set.${RESET}\n` +
        "Export it and re-run, e.g.:\n" +
        "  export ANTHROPIC_API_KEY=sk-ant-...\n" +
        "  npm run demo:llm\n",
    );
    process.exit(1);
  }

  const model = process.env["CAPNAGENT_DEMO_MODEL"] ?? "claude-opus-4-7";

  console.log(`${BOLD}${CYAN}capnagent shopping-agent demo${RESET}`);
  console.log(`scenario: ${BOLD}${scenario}${RESET}   model: ${DIM}${model}${RESET}`);
  console.log();

  const run = await runLlmDemo(scenario, { model, onEvent: event });

  console.log(`${BOLD}─── result ───${RESET}`);
  console.log(
    `model attempted bank.wire: ${run.modelAttemptedWire ? `${YELLOW}yes${RESET}` : `${GREEN}no${RESET}`}`,
  );
  console.log(
    `capnagent denied bank.wire: ${run.capnagentDeniedWire ? `${GREEN}yes${RESET}` : `${DIM}n/a${RESET}`}`,
  );
  console.log(
    `bank.wire reached underlying shop: ${run.wireReachedShop ? `${RED}YES (SECURITY FAILURE)${RESET}` : `${GREEN}no${RESET}`}`,
  );
  console.log(`receipts emitted: ${run.receipts.length}`);
  console.log();

  if (run.wireReachedShop) {
    console.error(
      `${RED}${BOLD}SECURITY FAILURE — bank.wire was executed against the mock shop.${RESET}`,
    );
    process.exit(3);
  }

  if (run.modelAttemptedWire && run.capnagentDeniedWire) {
    if (scenario === "direct" || scenario === "hok") {
      console.log(
        `${GREEN}${BOLD}capnagent denied the wire on capability-scope grounds — the user's direct request exceeded what the issued capability permits.${RESET}`,
      );
      if (scenario === "hok") {
        console.log(
          `${GREEN}Allowed calls additionally required a valid ed25519 proof-of-possession signature on every invocation.${RESET}`,
        );
      }
    } else {
      console.log(
        `${GREEN}${BOLD}capnagent successfully blocked the prompt-injected wire.${RESET}`,
      );
    }
  } else if (!run.modelAttemptedWire) {
    if (scenario === "direct" || scenario === "hok") {
      console.log(
        `${YELLOW}Model declined to attempt the wire even though the user asked. Try a different model or rephrase the user message; capnagent's denial path was not exercised.${RESET}`,
      );
    } else {
      console.log(
        `${GREEN}Model refused the injection on its own; capnagent is the second layer of defense.${RESET}`,
      );
    }
  }
}

main().catch((err) => {
  console.error(`${RED}error:${RESET}`, err);
  process.exit(1);
});
