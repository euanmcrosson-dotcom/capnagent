/**
 * `@capnagent/mcp` — MCP-client adapter for capnagent.
 *
 * Wrap an MCP TS-SDK client (or any object that structurally implements
 * `MCPClientLike`) so every `tools/call` is mediated by a capability + a
 * per-call context, and every decision is signed into an audit log.
 *
 * See `docs/WEEK3_SPEC.md` §3.3 for the locked public API.
 */

export { CapabilityDeniedError } from "./errors";
export {
  guardCall,
  type ContextProvider,
  type GuardedResult,
  type MCPClientLike,
  type WrapOptions,
} from "./guard";
export { wrapMCPClient } from "./wrap";
