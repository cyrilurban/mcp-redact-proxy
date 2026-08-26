#!/usr/bin/env node
import { spawn } from "node:child_process";
import readline from "node:readline";
import { createHttpProxyServer } from "./http-proxy.js";
import { DEFAULT_RULES } from "./rules.js";
import { makeStats, redactMcpToolResult } from "./redact.js";

function parseFlag(
  args: readonly string[],
  name: "--http-upstream" | "--http-host" | "--http-port",
): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === name) return args[i + 1];
    if (arg.startsWith(`${name}=`)) return arg.slice(name.length + 1);
  }
  return undefined;
}

function runHttpProxyMode(argv: readonly string[]) {
  const upstreamRaw = parseFlag(argv, "--http-upstream");
  if (!upstreamRaw) return false;

  const host = parseFlag(argv, "--http-host") ?? "0.0.0.0";
  const portRaw = parseFlag(argv, "--http-port") ?? "8080";
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    process.stderr.write(
      "error: --http-port must be an integer between 1 and 65535\n",
    );
    process.exit(2);
  }

  let upstream: URL;
  try {
    upstream = new URL(upstreamRaw);
    if (upstream.protocol !== "http:") {
      throw new Error("only http upstream is supported");
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : "invalid URL";
    process.stderr.write(`error: invalid --http-upstream: ${msg}\n`);
    process.exit(2);
  }

  const server = createHttpProxyServer({
    host,
    port,
    upstream: upstream.toString(),
  });
  server.listen(port, host, () => {
    process.stderr.write(
      `[mcp-redact-proxy] HTTP proxy listening on http://${host}:${port} -> ${upstream.toString()}\n`,
    );
  });
  server.on("error", (err: Error) => {
    process.stderr.write(`[mcp-redact-proxy] http server error: ${err.message}\n`);
    process.exit(1);
  });
  return true;
}

function runStdioProxyMode(argv: readonly string[]) {
  const sepIdx = argv.indexOf("--");
  if (sepIdx < 0 || sepIdx === argv.length - 1) {
    process.stderr.write(
      "usage: mcp-redact-proxy [--http-upstream <url> [--http-host <host>] [--http-port <port>]] -- <inner-mcp-cmd> [args...]\n",
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

  const pendingToolCalls = new Map<string | number, string>();

  const stdinRl = readline.createInterface({ input: process.stdin });
  stdinRl.on("line", (line: string) => {
    child.stdin.write(line + "\n");

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
      // keep passthrough behavior for malformed lines
    }
  });
  stdinRl.on("close", () => {
    child.stdin.end();
  });

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
    process.stdout.end();
  });
}

const argv = process.argv.slice(2);
if (!runHttpProxyMode(argv)) {
  runStdioProxyMode(argv);
}
