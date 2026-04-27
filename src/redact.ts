import type {
  FieldRedactionRule,
  PathRedactionRule,
  RedactionRule,
  StringRedactionRule,
} from "./rules.js";

export type RedactionStats = {
  totalMatches: number;
  byRule: Record<string, number>;
};

export function makeStats(): RedactionStats {
  return { totalMatches: 0, byRule: {} };
}

function bumpStat(stats: RedactionStats | undefined, name: string, by = 1) {
  if (!stats || by === 0) return;
  stats.byRule[name] = (stats.byRule[name] ?? 0) + by;
  stats.totalMatches += by;
}

function isFieldRule(r: RedactionRule): r is FieldRedactionRule {
  return r.kind === "field";
}

function isPathRule(r: RedactionRule): r is PathRedactionRule {
  return r.kind === "path";
}

function isStringRule(r: RedactionRule): r is StringRedactionRule {
  return r.kind !== "field" && r.kind !== "path";
}

/**
 * Match a path-glob (`**`, `*`, literals separated by `/`) against a list of
 * path segments. Standard recursive matcher — `**` consumes 0+ segments, `*`
 * matches a single segment, literal segments match exactly.
 */
function matchPathGlob(glob: string, segments: readonly string[]): boolean {
  const parts = glob.split("/").filter((p) => p.length > 0);
  return matchAt(parts, segments, 0, 0);
}

function matchAt(
  parts: string[],
  segs: readonly string[],
  pi: number,
  si: number,
): boolean {
  while (pi < parts.length) {
    const p = parts[pi];
    if (p === "**") {
      if (pi === parts.length - 1) return true;
      for (let k = si; k <= segs.length; k++) {
        if (matchAt(parts, segs, pi + 1, k)) return true;
      }
      return false;
    }
    if (si >= segs.length) return false;
    if (p !== "*" && p !== segs[si]) return false;
    pi++;
    si++;
  }
  return si === segs.length;
}

function pathRuleMatches(
  paths: readonly string[],
  segments: readonly string[],
): boolean {
  for (const g of paths) {
    if (matchPathGlob(g, segments)) return true;
  }
  return false;
}

function fieldMatches(
  fields: readonly (string | RegExp)[],
  key: string,
): boolean {
  for (const f of fields) {
    if (typeof f === "string") {
      if (f.toLowerCase() === key.toLowerCase()) return true;
    } else if (f.test(key)) {
      return true;
    }
  }
  return false;
}

function applyValueReplace(
  rule: FieldRedactionRule | PathRedactionRule,
  value: string,
): string {
  return typeof rule.replace === "function"
    ? rule.replace(value)
    : rule.replace;
}

/**
 * Recursively redact every string leaf inside `value` using a single field-
 * or path-rule's replacement. Used when a parent key (or path) matches and
 * we want to scrub the whole subtree.
 */
function redactSubtreeWith(
  value: unknown,
  rule: FieldRedactionRule | PathRedactionRule,
  stats?: RedactionStats,
): unknown {
  if (typeof value === "string") {
    bumpStat(stats, rule.name);
    return applyValueReplace(rule, value);
  }
  if (Array.isArray(value)) {
    return value.map((v) => redactSubtreeWith(v, rule, stats));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactSubtreeWith(v, rule, stats);
    }
    return out;
  }
  return value;
}

/**
 * Apply all string-pattern rules to a single string. Each rule's replacements
 * are not re-scanned by later rules (standard `String.replace` behaviour).
 *
 * This is exported for tests and for callers that already have a string and
 * want regex-only redaction (no JSON walking, no field-aware logic).
 */
export function redactText(
  input: string,
  rules: readonly RedactionRule[],
  stats?: RedactionStats,
): string {
  let out = input;
  for (const rule of rules) {
    if (!isStringRule(rule)) continue;
    let count = 0;
    out = out.replace(rule.pattern, (match, ...args) => {
      count++;
      const groups = args.filter((a) => typeof a === "string") as string[];
      return typeof rule.replace === "function"
        ? rule.replace(match, ...groups)
        : match.replace(rule.pattern, rule.replace);
    });
    bumpStat(stats, rule.name, count);
  }
  return out;
}

/**
 * Recursively walk any JSON value and redact strings.
 *
 * Resolution order at each node:
 *   1. Path rule — fires if the current path matches a `paths` glob.
 *   2. Field rule — fires if the parent key matches `fields`.
 *   3. String rules — applied to every remaining string leaf.
 *
 * Once a field/path rule fires on a subtree, string rules don't re-scan it.
 *
 * Returns a new value — does not mutate the input.
 */
export function redactJson(
  value: unknown,
  rules: readonly RedactionRule[],
  stats?: RedactionStats,
  parentKey?: string,
  parentPath: readonly string[] = [],
): unknown {
  // 1) Path-rule short-circuit.
  for (const rule of rules) {
    if (!isPathRule(rule)) continue;
    if (pathRuleMatches(rule.paths, parentPath)) {
      return redactSubtreeWith(value, rule, stats);
    }
  }

  // 2) Field-rule short-circuit (uses parent key).
  if (parentKey !== undefined) {
    for (const rule of rules) {
      if (!isFieldRule(rule)) continue;
      if (fieldMatches(rule.fields, parentKey)) {
        return redactSubtreeWith(value, rule, stats);
      }
    }
  }

  // 3) Descend / apply string rules to leaves.
  if (typeof value === "string") {
    return redactText(value, rules, stats);
  }
  if (Array.isArray(value)) {
    return value.map((v, i) =>
      redactJson(v, rules, stats, undefined, [...parentPath, String(i)]),
    );
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactJson(v, rules, stats, k, [...parentPath, k]);
    }
    return out;
  }
  return value;
}

/**
 * Redact an MCP `tools/call` result envelope.
 *
 * MCP tools return data inside `content: [{type: "text", text: "..."}]`. When
 * the text is a JSON string (the common case for tools that return structured
 * objects), plain string-leaf walking can't see the keys — so field rules
 * miss everything. This helper detects JSON text blocks, parses them, runs
 * full `redactJson` (with field-aware logic) over the parsed value, and
 * serialises the redacted object back into the text block.
 *
 * Non-text content blocks (images, resource links) and non-JSON text blocks
 * are passed to `redactJson` directly.
 */
export function redactMcpToolResult(
  result: unknown,
  rules: readonly RedactionRule[],
  stats?: RedactionStats,
): unknown {
  if (
    result === null ||
    typeof result !== "object" ||
    !Array.isArray((result as { content?: unknown }).content)
  ) {
    return redactJson(result, rules, stats);
  }

  const envelope = result as Record<string, unknown> & { content: unknown[] };
  const newContent = envelope.content.map((block) => {
    if (
      block !== null &&
      typeof block === "object" &&
      (block as { type?: unknown }).type === "text" &&
      typeof (block as { text?: unknown }).text === "string"
    ) {
      const text = (block as { text: string }).text;
      const trimmed = text.trimStart();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed = JSON.parse(text);
          const redacted = redactJson(parsed, rules, stats);
          return { ...(block as object), text: JSON.stringify(redacted, null, 2) };
        } catch {
          // fall through to string-leaf redaction
        }
      }
      return { ...(block as object), text: redactText(text, rules, stats) };
    }
    return redactJson(block, rules, stats);
  });

  // Walk the rest of the envelope (e.g. `isError`, `structuredContent`) so
  // field rules still fire on top-level structured payloads.
  const redactedEnvelope: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(envelope)) {
    if (k === "content") {
      redactedEnvelope[k] = newContent;
    } else {
      redactedEnvelope[k] = redactJson(v, rules, stats, k);
    }
  }
  return redactedEnvelope;
}
