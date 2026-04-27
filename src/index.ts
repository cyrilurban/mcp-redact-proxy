#!/usr/bin/env node
/**
 * mcp-redact-proxy — a transparent stdio proxy for MCP servers.
 *
 * Usage:
 *   mcp-redact-proxy -- <inner-mcp-cmd> [args...]
 *
 * Example: wrap mcp-grafana with Loki-log redaction enabled.
 *   mcp-redact-proxy -- uvx mcp-grafana
 *
 * The proxy:
 *   1. Spawns the inner MCP server as a child process.
 *   2. Forwards every JSON-RPC line from our stdin to the child's stdin
 *      unchanged (no redaction on requests — the LLM's queries are not PII).
 *   3. Intercepts `tools/call` responses from the child and runs the
 *      redaction pipeline on the `result` payload before writing it to our
 *      stdout, where the MCP client (Claude) reads it.
 *
 * All non-`tools/call` traffic (initialize, tools/list, resource ops, …) is
 * passed through untouched so the MCP handshake and tool schema are
 * preserved exactly.
 */
import { spawn } from "node:child_process";
import readline from "node:readline";
import { DEFAULT_RULES } from "./rules.js";
import { makeStats, redactMcpToolResult } from "./redact.js";

const argv = process.argv.slice(2);
const sepIdx = argv.indexOf("--");
if (sepIdx < 0 || sepIdx === argv.length - 1) {
  process.stderr.write(
    "usage: mcp-redact-proxy [options] -- <inner-mcp-cmd> [args...]\n",
  );
  process.exit(2);
}
const innerArgv = argv.slice(sepIdx + 1);
const [cmd, ...cmdArgs] = innerArgv;
if (!cmd) {
  process.stderr.write("error: no inner command specified after --\n");
  process.exit(2);
}

const rules = DEFAULT_RULES;

// Spawn the inner MCP server. stdin/stdout are piped, stderr inherited so the
// user sees the child's diagnostic output interleaved with ours.
const child = spawn(cmd, cmdArgs, {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
});

child.on("error", (err: Error) => {
  process.stderr.write(`[mcp-redact-proxy] spawn error: ${err.message}\n`);
  process.exit(127);
});
child.on("exit", (code) => {
  process.exit(code ?? 0);
});

/** JSON-RPC request IDs currently awaiting a `tools/call` response. */
const pendingToolCalls = new Map<string | number, string>();

// ── Client → Child ─────────────────────────────────────────────────────────
const stdinRl = readline.createInterface({ input: process.stdin });
stdinRl.on("line", (line: string) => {
  // Passthrough first: the child must never be blocked on parsing delays.
  child.stdin.write(line + "\n");

  // Best-effort sniff to remember which request ids are tool calls.
  try {
    const msg = JSON.parse(line) as {
      method?: string;
      id?: string | number;
      params?: { name?: string };
    };
    if (
      msg?.method === "tools/call" &&
      (typeof msg.id === "string" || typeof msg.id === "number") &&
      typeof msg.params?.name === "string"
    ) {
      pendingToolCalls.set(msg.id, msg.params.name);
    }
  } catch {
    // Non-JSON lines (shouldn't happen on MCP stdio, but be robust).
  }
});
stdinRl.on("close", () => {
  child.stdin.end();
});

// ── Child → Client ─────────────────────────────────────────────────────────
const stdoutRl = readline.createInterface({ input: child.stdout });
stdoutRl.on("line", (line: string) => {
  try {
    const msg = JSON.parse(line) as {
      id?: string | number;
      result?: unknown;
    };

    if (
      msg &&
      (typeof msg.id === "string" || typeof msg.id === "number") &&
      pendingToolCalls.has(msg.id)
    ) {
      const toolName = pendingToolCalls.get(msg.id)!;
      pendingToolCalls.delete(msg.id);

      const stats = makeStats();
      msg.result = redactMcpToolResult(msg.result, rules, stats);

      if (stats.totalMatches > 0) {
        process.stderr.write(
          `[mcp-redact-proxy] tool=${toolName} redacted=${
            stats.totalMatches
          } by=${JSON.stringify(stats.byRule)}\n`,
        );
      }
      process.stdout.write(JSON.stringify(msg) + "\n");
      return;
    }
    process.stdout.write(line + "\n");
  } catch {
    process.stdout.write(line + "\n");
  }
});
stdoutRl.on("close", () => {
  // Child closed stdout → we're done.
  process.stdout.end();
});
