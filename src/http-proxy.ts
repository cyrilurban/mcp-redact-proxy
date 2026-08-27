import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { RedactionStats } from "./redact.js";
import { DEFAULT_RULES } from "./rules.js";
import { makeStats, redactMcpToolResult } from "./redact.js";
import { MetricsCollector } from "./metrics.js";

export type HttpProxyOptions = {
  host: string;
  port: number;
  upstream: string;
  unwrapJsonStrings?: boolean;
};

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function writeJsonError(
  res: ServerResponse,
  status: number,
  error: string,
  detail: string,
) {
  const payload = Buffer.from(JSON.stringify({ error, detail }), "utf8");
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-length", String(payload.length));
  res.end(payload);
}

function shouldRedactToolResponse(body: Buffer): boolean {
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.some(
        (entry) =>
          entry !== null &&
          typeof entry === "object" &&
          (entry as { method?: unknown }).method === "tools/call",
      );
    }
    return (
      parsed !== null &&
      typeof parsed === "object" &&
      (parsed as { method?: unknown }).method === "tools/call"
    );
  } catch {
    return false;
  }
}

function extractToolName(body: Buffer): string | undefined {
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (Array.isArray(parsed)) {
      for (const entry of parsed) {
        if (
          entry !== null &&
          typeof entry === "object" &&
          (entry as { method?: unknown }).method === "tools/call"
        ) {
          const toolName = (entry as { params?: { name?: string } }).params?.name;
          if (typeof toolName === "string") return toolName;
        }
      }
      return undefined;
    }
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      (parsed as { method?: unknown }).method === "tools/call"
    ) {
      return (parsed as { params?: { name?: string } }).params?.name;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

type RedactResult = {
  redacted: unknown;
  stats: RedactionStats;
};

function redactToolResponsePayload(
  payload: unknown,
  unwrapJsonStrings: boolean,
): RedactResult {
  const allStats = makeStats();

  function processEntry(entry: unknown): unknown {
    if (entry !== null && typeof entry === "object" && "result" in entry) {
      const out = { ...(entry as Record<string, unknown>) };
      const stats = makeStats();
      out.result = redactMcpToolResult(out.result, DEFAULT_RULES, stats, {
        unwrapJsonStrings,
      });
      // Merge stats
      allStats.totalMatches += stats.totalMatches;
      for (const [rule, count] of Object.entries(stats.byRule)) {
        allStats.byRule[rule] = (allStats.byRule[rule] ?? 0) + count;
      }
      return out;
    }
    return entry;
  }

  let redacted: unknown;
  if (Array.isArray(payload)) {
    redacted = payload.map(processEntry);
  } else if (
    payload !== null &&
    typeof payload === "object" &&
    "result" in (payload as Record<string, unknown>)
  ) {
    redacted = processEntry(payload);
  } else {
    redacted = payload;
  }

  return { redacted, stats: allStats };
}

export function createHttpProxyServer(options: HttpProxyOptions) {
  const upstreamBase = new URL(options.upstream);
  const metrics = new MetricsCollector();

  const server = createServer(async (req, res) => {
    // Parse URL early to check for /metrics endpoint
    let incomingUrl: URL;
    try {
      incomingUrl = new URL(req.url ?? "/", "http://proxy.local");
    } catch {
      writeJsonError(
        res,
        400,
        "Invalid request URL",
        "Unable to parse incoming request target",
      );
      return;
    }

    // Handle /metrics endpoint
    if (incomingUrl.pathname === "/metrics" && req.method === "GET") {
      const prometheusText = metrics.formatPrometheus();
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain; charset=utf-8; version=0.0.4");
      res.setHeader("content-length", Buffer.byteLength(prometheusText));
      res.end(prometheusText);
      return;
    }

    metrics.recordRequest();

    const requestBody = await readBody(req).catch((err: Error) => {
      writeJsonError(res, 400, "Invalid request body", err.message);
      return null;
    });
    if (requestBody === null) return;
    // preserve upstream's own path (e.g. "/mcp") instead of letting it be replaced
    const basePath = upstreamBase.pathname.endsWith("/")
      ? upstreamBase.pathname.slice(0, -1)
      : upstreamBase.pathname;
    const suffix = incomingUrl.pathname === "/" ? "" : incomingUrl.pathname;
    const url = new URL(
      `${basePath}${suffix}${incomingUrl.search}`,
      upstreamBase,
    );
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (key.toLowerCase() === "host" || value === undefined) continue;
      if (Array.isArray(value)) {
        for (const v of value) headers.append(key, v);
      } else {
        headers.set(key, value);
      }
    }

    let upstreamResponse: Response;
    try {
      upstreamResponse = await fetch(url, {
        method: req.method,
        headers,
        body:
          req.method === "GET" || req.method === "HEAD"
            ? undefined
            : new Uint8Array(requestBody),
        redirect: "manual",
      });
    } catch (err) {
      const detail =
        err instanceof Error ? err.message : "Failed to contact upstream";
      writeJsonError(res, 502, "Upstream request failed", detail);
      return;
    }

    let upstreamBody: Buffer;
    try {
      upstreamBody = Buffer.from(await upstreamResponse.arrayBuffer());
    } catch (err) {
      const detail =
        err instanceof Error ? err.message : "Failed to read upstream response";
      writeJsonError(res, 502, "Upstream response failed", detail);
      return;
    }
    const shouldRedact = shouldRedactToolResponse(requestBody);

    let responseBody = upstreamBody;
    if (shouldRedact) {
      metrics.recordToolCall();
      const responseText = upstreamBody.toString("utf8");
      let parsed: unknown;
      try {
        parsed = JSON.parse(responseText);
      } catch {
        writeJsonError(
          res,
          502,
          "Upstream returned invalid JSON for tools/call",
          "Unable to parse upstream JSON response",
        );
        return;
      }

      try {
        const result = redactToolResponsePayload(
          parsed,
          options.unwrapJsonStrings ?? false,
        );
        responseBody = Buffer.from(JSON.stringify(result.redacted), "utf8");
        if (result.stats.totalMatches > 0) {
          metrics.recordRedactions(result.stats.byRule);
          const toolName = extractToolName(requestBody);
          if (toolName) {
            process.stderr.write(
              `[mcp-redact-proxy] tool=${toolName} redacted=${
                result.stats.totalMatches
              } by=${JSON.stringify(result.stats.byRule)}\n`,
            );
          }
        }
      } catch (err) {
        const detail =
          err instanceof Error ? err.message : "Redaction pipeline failed";
        writeJsonError(res, 502, "Redaction failed", detail);
        return;
      }
    }

    res.statusCode = upstreamResponse.status;
    for (const [key, value] of upstreamResponse.headers.entries()) {
      const lower = key.toLowerCase();
      // response body is fully buffered, so chunked framing headers must be dropped
      if (lower === "content-length" || lower === "transfer-encoding") {
        continue;
      }
      res.setHeader(key, value);
    }
    res.setHeader("content-length", String(responseBody.length));
    res.end(responseBody);
  });

  return server;
}
