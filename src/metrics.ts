/**
 * Prometheus-style metrics collector for the proxy.
 *
 * Tracks redaction statistics across requests and formats them
 * for scraping via the /metrics endpoint.
 */

export type MetricsSnapshot = {
  totalRequests: number;
  totalToolCalls: number;
  totalRedactions: number;
  redactionsByRule: Record<string, number>;
};

export class MetricsCollector {
  private totalRequests = 0;
  private totalToolCalls = 0;
  private totalRedactions = 0;
  private redactionsByRule: Record<string, number> = {};

  recordToolCall(): void {
    this.totalToolCalls++;
  }

  recordRedactions(byRule: Record<string, number>): void {
    for (const [rule, count] of Object.entries(byRule)) {
      this.redactionsByRule[rule] = (this.redactionsByRule[rule] ?? 0) + count;
      this.totalRedactions += count;
    }
  }

  recordRequest(): void {
    this.totalRequests++;
  }

  snapshot(): MetricsSnapshot {
    return {
      totalRequests: this.totalRequests,
      totalToolCalls: this.totalToolCalls,
      totalRedactions: this.totalRedactions,
      redactionsByRule: { ...this.redactionsByRule },
    };
  }

  /**
   * Format metrics in Prometheus text format.
   * See: https://prometheus.io/docs/instrumenting/exposition_formats/
   */
  formatPrometheus(): string {
    const snap = this.snapshot();
    const lines: string[] = [];

    // Total requests
    lines.push("# HELP mcp_redact_requests_total Total HTTP requests processed");
    lines.push("# TYPE mcp_redact_requests_total counter");
    lines.push(`mcp_redact_requests_total ${snap.totalRequests}`);
    lines.push("");

    // Total tool calls
    lines.push(
      "# HELP mcp_redact_tool_calls_total Total tools/call requests processed",
    );
    lines.push("# TYPE mcp_redact_tool_calls_total counter");
    lines.push(`mcp_redact_tool_calls_total ${snap.totalToolCalls}`);
    lines.push("");

    // Total redactions
    lines.push(
      "# HELP mcp_redact_redactions_total Total values redacted across all rules",
    );
    lines.push("# TYPE mcp_redact_redactions_total counter");
    lines.push(`mcp_redact_redactions_total ${snap.totalRedactions}`);
    lines.push("");

    // Redactions by rule
    lines.push(
      "# HELP mcp_redact_rule_redactions_total Values redacted per rule",
    );
    lines.push("# TYPE mcp_redact_rule_redactions_total counter");
    for (const [rule, count] of Object.entries(snap.redactionsByRule).sort()) {
      // Escape label value (replace backslashes and quotes)
      const escapedRule = rule.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      lines.push(`mcp_redact_rule_redactions_total{rule="${escapedRule}"} ${count}`);
    }

    return lines.join("\n") + "\n";
  }
}
