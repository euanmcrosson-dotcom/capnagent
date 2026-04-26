import { CapabilityDeniedError } from "./errors";
import { type MCPClientLike, type WrapOptions, __decide } from "./guard";

/**
 * Wrap an MCP client so every `callTool()` is gated by a capability.
 *
 * Returns a new client of the same shape as the input — a Proxy whose
 * `callTool` runs the verifier first, then either:
 *
 *   - throws `CapabilityDeniedError` (carrying the {@link Receipt}) on
 *     deny, WITHOUT invoking the underlying client's `callTool`, or
 *   - calls through to the underlying `callTool` on allow and returns
 *     its result unchanged.
 *
 * `CapabilityChainError` and `CapabilityAuditError` from the verifier
 * propagate unchanged — they are NOT remapped to `CapabilityDeniedError`,
 * because they signal a different failure mode (cryptographic integrity vs
 * authorisation).
 *
 * Any other property access on the wrapped client is reflected to the
 * original; methods are bound to the original `client` so their `this`
 * remains stable.
 */
export function wrapMCPClient<C extends MCPClientLike>(client: C, options: WrapOptions): C {
  const guardedCallTool = async (name: string, args: unknown): Promise<unknown> => {
    const { receipt } = await __decide(options, name, args);
    if (receipt.outcome.kind === "denied") {
      throw new CapabilityDeniedError(receipt);
    }
    return await client.callTool(name, args);
  };

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "callTool") {
        return guardedCallTool;
      }
      const value = Reflect.get(target, prop, receiver);
      // Bind methods to the original target so `this` remains the underlying
      // client — otherwise a method that calls `this.callTool` would resolve
      // through the proxy and re-enter the gate, but a method that uses
      // `this` for any other reason would also be subtly broken if `this`
      // were the proxy.
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as C;
}
