import { createHash } from "node:crypto";

/**
 * A redaction rule: a regex + a replacement (literal or computed from match).
 *
 * When `replace` is a function it receives the match plus any capture groups —
 * same signature as `String.prototype.replace`'s function argument.
 */
export type RedactionRule = {
  readonly name: string;
  readonly pattern: RegExp;
  readonly replace: string | ((match: string, ...groups: string[]) => string);
};

/**
 * Build a deterministic short-hash replacer. Same input always produces the
 * same output within a process run, which lets the LLM still correlate
 * "same user / same parcel" across log lines without ever seeing the real id.
 *
 * Uses SHA-256 truncated to 6 hex chars (24 bits) — low collision risk for the
 * typical log sample the LLM sees in one conversation.
 */
const hashReplacer =
  (prefix: string) =>
  (match: string): string => {
    const h = createHash("sha256").update(match).digest("hex").slice(0, 6);
    return `<${prefix}_${h}>`;
  };

/**
 * Default redaction rules tailored for the observed PII/secret patterns in
 * Qest's DPD stack (My Pickup, Tracking, ManagementPUS, …). Order matters:
 * earlier rules run first and their replacements are not re-scanned.
 */
export const DEFAULT_RULES: readonly RedactionRule[] = [
  // API keys / auth tokens must run first — they often contain substrings that
  // would otherwise match narrower rules (hex crypto, UUIDs, etc.).
  {
    name: "api-key-header",
    // Match any non-word chars between the key name and the value so the rule
    // works both on plain (` "x-api-key": "abc..." `) and on escaped JSON
    // strings (` \"x-api-key\":\"abc...\" `) as they appear when Loki log lines
    // are embedded inside MCP `text` content.
    pattern:
      /((?:x-api-key|authorization|api[-_]?key|bearer|secret|password)\W+)([a-zA-Z0-9_\-.]{20,})/gi,
    replace: (_m, prefix: string) => `${prefix}<REDACTED_SECRET>`,
  },
  {
    name: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    replace: "<JWT>",
  },
  {
    name: "grafana-sa-token",
    // Grafana service account tokens: glsa_<hex>_<shortid>
    pattern: /\bglsa_[A-Za-z0-9_]{20,}\b/g,
    replace: "<GRAFANA_SA_TOKEN>",
  },

  // Personal identifiers
  {
    name: "email",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replace: hashReplacer("EMAIL"),
  },
  {
    name: "uuid",
    pattern:
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    replace: hashReplacer("UUID"),
  },
  {
    name: "phone-cz",
    pattern: /\+?420[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3}\b/g,
    replace: "<PHONE_CZ>",
  },
  {
    name: "phone-sk",
    pattern: /\+?421[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3}\b/g,
    replace: "<PHONE_SK>",
  },
  {
    name: "phone-intl",
    pattern: /\+\d{9,15}\b/g,
    replace: "<PHONE>",
  },

  // Payment data
  {
    name: "card-last4-masked",
    // "Visa **** **** **** 1234"
    pattern: /\*{4,}\s?\*{4,}\s?\*{4,}\s?\d{4}/g,
    replace: "<CARD_****_****_****_XXXX>",
  },
  {
    name: "card-pan",
    // Formatted PAN only (with space/dash separators) to avoid false positives
    // on raw 13–19-digit strings like parcel numbers and other business ids.
    pattern: /\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{3,4}\b/g,
    replace: "<CARD_PAN>",
  },
  {
    name: "worldline-auth-code",
    // "Authorization code:           (00)510096"
    pattern: /(Authorization code:\s+\(\d{2}\))\d{6}/g,
    replace: "$1XXXXXX",
  },
  {
    name: "hex-crypto",
    // ARQC, AID, and similar uppercase hex blobs. Require at least one A–F
    // letter so we don't swallow purely numeric ids (parcel numbers, …).
    pattern: /\b(?=[0-9A-F]*[A-F])[0-9A-F]{12,}\b/g,
    replace: "<HEX_CRYPTO>",
  },

  // DPD domain identifiers — hash so correlation still works.
  //
  // Note: 14-digit parcel numbers are intentionally NOT redacted. They are not
  // personal data on their own and are the primary key devs need to correlate
  // a log line with a concrete shipment when debugging. If that changes (e.g.
  // parcel numbers are ever combined with recipient address in a single log
  // line), reconsider.
  {
    name: "pudo-id",
    pattern: /\b(?:CZ|SK|PL|HU)\d{5}\b/g,
    replace: hashReplacer("PUDO"),
  },
];
