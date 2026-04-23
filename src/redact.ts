import type { RedactionRule } from "./rules.js";

export type RedactionStats = {
  totalMatches: number;
  byRule: Record<string, number>;
};

export function makeStats(): RedactionStats {
  return { totalMatches: 0, byRule: {} };
}

/**
 * Apply all rules in order to a single string. Each rule's replacements are
 * not re-scanned by later rules (standard `String.replace` behaviour).
 */
export function redactText(
  input: string,
  rules: readonly RedactionRule[],
  stats?: RedactionStats,
): string {
  let out = input;
  for (const rule of rules) {
    let count = 0;
    out = out.replace(rule.pattern, (match, ...args) => {
      count++;
      // `args` from String.replace ends with (offset, string, [groups]). We
      // forward only the capture groups to user replacer functions.
      const groups = args.filter((a) => typeof a === "string") as string[];
      return typeof rule.replace === "function"
        ? rule.replace(match, ...groups)
        : match.replace(rule.pattern, rule.replace);
    });
    if (stats && count > 0) {
      stats.byRule[rule.name] = (stats.byRule[rule.name] ?? 0) + count;
      stats.totalMatches += count;
    }
  }
  return out;
}

/**
 * Recursively walk any JSON value and redact string leaves. Numbers, booleans,
 * null and keys are left untouched.
 *
 * Returns a new value — does not mutate the input.
 */
export function redactJson(
  value: unknown,
  rules: readonly RedactionRule[],
  stats?: RedactionStats,
): unknown {
  if (typeof value === "string") {
    return redactText(value, rules, stats);
  }
  if (Array.isArray(value)) {
    return value.map((v) => redactJson(v, rules, stats));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactJson(v, rules, stats);
    }
    return out;
  }
  return value;
}
