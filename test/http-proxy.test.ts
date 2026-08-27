import { createServer, type Server } from "node:http";
import { describe, it, expect } from "vitest";
import { createHttpProxyServer } from "../src/http-proxy.ts";

async function listenRandom(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("Failed to read server address");
  }
  return addr.port;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

describe("HTTP proxy mode", () => {
  it("redacts tools/call responses and preserves headers", async () => {
    let upstreamSawClientHeader: string | undefined;
    const upstream = createServer(async (req, res) => {
      upstreamSawClientHeader = req.headers["x-client-trace"] as
        | string
        | undefined;
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.setHeader("x-upstream-header", "kept");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  user: { email: "alice@example.com" },
                  status: "ok",
                }),
              },
            ],
          },
        }),
      );
    });
    const upstreamPort = await listenRandom(upstream);

    const proxy = createHttpProxyServer({
      host: "127.0.0.1",
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
    });
    const proxyPort = await listenRandom(proxy);

    try {
      const response = await fetch(`http://127.0.0.1:${proxyPort}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-client-trace": "trace-123",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "query_logs", arguments: {} },
        }),
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("x-upstream-header")).toBe("kept");
      expect(upstreamSawClientHeader).toBe("trace-123");

      const payload = (await response.json()) as {
        result: { content: Array<{ type: string; text: string }> };
      };
      const textBlock = payload.result.content[0].text;
      expect(textBlock).not.toContain("alice@example.com");
      expect(textBlock).toMatch(/<EMAIL_[a-f0-9]{6}>/);
      expect(textBlock).toContain("status");
    } finally {
      await closeServer(proxy);
      await closeServer(upstream);
    }
  });

  it("fails close when tools/call upstream response is invalid JSON", async () => {
    const upstream = createServer(async (_req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end("NOT_JSON alice@example.com");
    });
    const upstreamPort = await listenRandom(upstream);

    const proxy = createHttpProxyServer({
      host: "127.0.0.1",
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
    });
    const proxyPort = await listenRandom(proxy);

    try {
      const response = await fetch(`http://127.0.0.1:${proxyPort}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "query_logs", arguments: {} },
        }),
      });

      expect(response.status).toBe(502);
      const text = await response.text();
      expect(text).toContain("invalid JSON");
      expect(text).not.toContain("alice@example.com");
    } finally {
      await closeServer(proxy);
      await closeServer(upstream);
    }
  });

  it("returns 502 when the upstream response body terminates", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input, init) => {
      if (String(input).startsWith("https://upstream.example")) {
        return {
          status: 200,
          headers: new Headers(),
          arrayBuffer: async () => {
            throw new TypeError("terminated");
          },
        } as Response;
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    const proxy = createHttpProxyServer({
      host: "127.0.0.1",
      port: 0,
      upstream: "https://upstream.example/mcp",
    });
    const proxyPort = await listenRandom(proxy);

    try {
      const response = await fetch(`http://127.0.0.1:${proxyPort}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" }),
      });

      expect(response.status).toBe(502);
      expect(await response.text()).toContain("Upstream response failed");
    } finally {
      globalThis.fetch = originalFetch;
      await closeServer(proxy);
    }
  });

  it("exposes /metrics endpoint with Prometheus format", async () => {
    let upstreamCallCount = 0;
    const upstream = createServer(async (req, res) => {
      upstreamCallCount++;
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  email: "test@example.com",
                  uuid: "f3623e55-5b76-4c1b-b045-89ea36c71978",
                }),
              },
            ],
          },
        }),
      );
    });
    const upstreamPort = await listenRandom(upstream);

    const proxy = createHttpProxyServer({
      host: "127.0.0.1",
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
    });
    const proxyPort = await listenRandom(proxy);

    try {
      // Make a tool call
      await fetch(`http://127.0.0.1:${proxyPort}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "query_logs", arguments: {} },
        }),
      });

      // Fetch metrics
      const response = await fetch(`http://127.0.0.1:${proxyPort}/metrics`, {
        method: "GET",
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        "text/plain; charset=utf-8; version=0.0.4",
      );

      const text = await response.text();
      // Check for Prometheus format elements
      expect(text).toContain("# HELP mcp_redact_requests_total");
      expect(text).toContain("# TYPE mcp_redact_requests_total counter");
      expect(text).toContain("mcp_redact_requests_total 1");

      expect(text).toContain("# HELP mcp_redact_tool_calls_total");
      expect(text).toContain("mcp_redact_tool_calls_total 1");

      expect(text).toContain("# HELP mcp_redact_redactions_total");
      expect(text).toContain("mcp_redact_redactions_total 2"); // email + uuid

      expect(text).toContain("# HELP mcp_redact_rule_redactions_total");
      expect(text).toContain('mcp_redact_rule_redactions_total{rule="email"} 1');
      expect(text).toContain('mcp_redact_rule_redactions_total{rule="uuid"} 1');
    } finally {
      await closeServer(proxy);
      await closeServer(upstream);
    }
  });
});
