import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { DEFAULT_RULES } from "./rules.js";
import { makeStats, redactMcpToolResult } from "./redact.js";

export type HttpProxyOptions = {
  host: string;
  port: number;
  upstream: string;
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

function redactToolResponsePayload(payload: unknown): unknown {
  if (Array.isArray(payload)) {
    return payload.map((entry) => {
      if (
        entry !== null &&
        typeof entry === "object" &&
        "result" in entry
      ) {
        const out = { ...(entry as Record<string, unknown>) };
        const stats = makeStats();
        out.result = redactMcpToolResult(out.result, DEFAULT_RULES, stats);
        return out;
      }
      return entry;
    });
  }

  if (
    payload !== null &&
    typeof payload === "object" &&
    "result" in (payload as Record<string, unknown>)
  ) {
    const out = { ...(payload as Record<string, unknown>) };
    const stats = makeStats();
    out.result = redactMcpToolResult(out.result, DEFAULT_RULES, stats);
    return out;
  }

  return payload;
}

export function createHttpProxyServer(options: HttpProxyOptions) {
  const upstreamBase = new URL(options.upstream);

  const server = createServer(async (req, res) => {
    const requestBody = await readBody(req).catch((err: Error) => {
      writeJsonError(res, 400, "Invalid request body", err.message);
      return null;
    });
    if (requestBody === null) return;

    const url = new URL(req.url ?? "/", upstreamBase);
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
            : requestBody,
        redirect: "manual",
      });
    } catch (err) {
      const detail =
        err instanceof Error ? err.message : "Failed to contact upstream";
      writeJsonError(res, 502, "Upstream request failed", detail);
      return;
    }

    const upstreamBody = Buffer.from(await upstreamResponse.arrayBuffer());
    const shouldRedact = shouldRedactToolResponse(requestBody);

    let responseBody = upstreamBody;
    if (shouldRedact) {
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
        const redacted = redactToolResponsePayload(parsed);
        responseBody = Buffer.from(JSON.stringify(redacted), "utf8");
      } catch (err) {
        const detail =
          err instanceof Error ? err.message : "Redaction pipeline failed";
        writeJsonError(res, 502, "Redaction failed", detail);
        return;
      }
    }

    res.statusCode = upstreamResponse.status;
    for (const [key, value] of upstreamResponse.headers.entries()) {
      if (key.toLowerCase() === "content-length") continue;
      res.setHeader(key, value);
    }
    res.setHeader("content-length", String(responseBody.length));
    res.end(responseBody);
  });

  return server;
}
