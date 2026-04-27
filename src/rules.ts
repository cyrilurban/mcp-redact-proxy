import { createHash } from "node:crypto";

/**
 * String-pattern rule — applied to every string leaf via regex. Use this for
 * **self-identifying** values (JWTs, emails, IBANs) — anything that can be
 * recognised without knowing which JSON key it came from.
 */
export type StringRedactionRule = {
  readonly kind?: "string";
  readonly name: string;
  readonly pattern: RegExp;
  readonly replace: string | ((match: string, ...groups: string[]) => string);
};

/**
 * Field-aware rule — fires when a JSON property's key matches `fields`. Use
 * this for values that look like ordinary strings on their own ("Jiří Nesvarba",
 * "Ke Zdibsku 193") and are only sensitive because of the surrounding key.
 *
 * If the matched value is itself an object/array, every string leaf inside is
 * replaced — so a single rule on `address` will cover `{street, city, zipCode}`
 * regardless of nesting.
 *
 * Field matching is case-insensitive when given as a string; provide a RegExp
 * for fancier matching (e.g. `/Name$/i`).
 */
export type FieldRedactionRule = {
  readonly kind: "field";
  readonly name: string;
  readonly fields: readonly (string | RegExp)[];
  readonly replace: string | ((value: string) => string);
};

/**
 * Path-aware rule — fires on values whose JSON path matches one of `paths`.
 * Use this for "the value field of a KeyValueItem inside additionalInfo" cases
 * where neither the key alone nor the value alone is enough to decide.
 *
 * Path globs:
 *   - `*` matches a single segment (object key or array index).
 *   - `**` matches zero or more segments.
 *   - Segments are joined with `/`. Array indices are decimal strings.
 *
 * Example: `**\/additionalInfo/*\/value` redacts the `value` of every
 * `additionalInfo` array item, regardless of how deep `additionalInfo` lives.
 */
export type PathRedactionRule = {
  readonly kind: "path";
  readonly name: string;
  readonly paths: readonly string[];
  readonly replace: string | ((value: string) => string);
};

export type RedactionRule =
  | StringRedactionRule
  | FieldRedactionRule
  | PathRedactionRule;

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
 * Same idea, but for field rules where the entire value (not a regex match) is
 * what we hash. Identical implementation — exposed under a different name so
 * the call sites read clearly.
 */
const fieldHashReplacer = hashReplacer;

/**
 * Default redaction rules. Order matters for string rules: earlier rules run
 * first and their replacements are not re-scanned.
 *
 * Field rules run before string rules at each JSON node — once a field rule
 * fires on a subtree, the string rules don't re-scan it.
 */
export const DEFAULT_RULES: readonly RedactionRule[] = [
  // ── Secrets first ────────────────────────────────────────────────────────
  // API keys / auth tokens must run first — they often contain substrings that
  // would otherwise match narrower rules (hex crypto, UUIDs, etc.).
  {
    name: "api-key-header",
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
    pattern: /\bglsa_[A-Za-z0-9_]{20,}\b/g,
    replace: "<GRAFANA_SA_TOKEN>",
  },

  // ── Personal identifiers (self-identifying patterns) ─────────────────────
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

  // ── Banking (self-identifying patterns) ──────────────────────────────────
  {
    name: "iban",
    // ISO 13616 IBAN: 2 country letters + 2 check digits + up to 30 alnum.
    // Allow optional spaces between groups of 4 (printed format).
    pattern:
      /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g,
    replace: hashReplacer("IBAN"),
  },
  // Note: standalone BIC/SWIFT detection is intentionally not regex-based —
  // 8-letter all-caps strings are too common as ordinary words to match
  // safely. The `bic` field rule below catches them via JSON key.
  {
    name: "cz-bank-account",
    // Czech bank account format: [prefix-]number/bankCode where bankCode is
    // exactly 4 digits (e.g. 0100 KB, 0300 ČSOB). Optional 2–6 digit prefix.
    pattern: /\b(?:\d{2,6}-)?\d{2,10}\/\d{4}\b/g,
    replace: hashReplacer("BANK_ACCT"),
  },

  // ── Payment cards ────────────────────────────────────────────────────────
  {
    name: "card-last4-masked",
    pattern: /\*{4,}\s?\*{4,}\s?\*{4,}\s?\d{4}/g,
    replace: "<CARD_****_****_****_XXXX>",
  },
  {
    name: "card-pan",
    pattern: /\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{3,4}\b/g,
    replace: "<CARD_PAN>",
  },
  {
    name: "worldline-auth-code",
    pattern: /(Authorization code:\s+\(\d{2}\))\d{6}/g,
    replace: "$1XXXXXX",
  },
  {
    name: "hex-crypto",
    pattern: /\b(?=[0-9A-F]*[A-F])[0-9A-F]{12,}\b/g,
    replace: "<HEX_CRYPTO>",
  },

  // ── Field-aware rules (keys + values that aren't self-identifying) ───────
  // Names of people and companies. We list explicit *leaf* fields rather than
  // container objects (`receiver`, `sender`, …) — a container match would
  // hash the whole subtree with the NAME prefix, which would clash with the
  // address-field and string-pattern rules below.
  //
  // `name` is included even though it's overloaded (event-type names, MPS
  // names): the safety win on receiver/courier/carrier names outweighs the
  // cosmetic loss of seeing literal event-type strings. Add a more specific
  // path-based override later if it becomes a problem.
  {
    kind: "field",
    name: "name-field",
    fields: [
      "name",
      "contactName",
      "name2",
      "company",
      "owner",
      "editPerson",
      "author",
      "pickupPointName",
    ],
    replace: fieldHashReplacer("NAME"),
  },
  // Postal addresses. `country` is intentionally left out (ISO code or numeric
  // code, not personal). `pudoId` (PUDO ids like CZ12345) is also kept — devs
  // need them and they are not personal data on their own.
  {
    kind: "field",
    name: "address-field",
    fields: [
      "street",
      "city",
      "zipCode",
      "building",
      "floor",
      "department",
      "delivery",
      "address",
    ],
    replace: fieldHashReplacer("ADDR"),
  },
  // Phone numbers via JSON key — covers values that don't carry an
  // international prefix and would slip past the `phone-cz`/`phone-sk`/
  // `phone-intl` patterns (e.g. carrier records that store a bare
  // "722 044 240"). String rules still run on free-text occurrences in `note`,
  // `content`, etc.
  {
    kind: "field",
    name: "phone-field",
    fields: [
      "phone",
      "phoneNumber",
      "contactPhone",
      "receiverPhone",
      "devicePhone",
      "recipientPhone",
      "telephone",
      "mobilePhone",
    ],
    replace: "<PHONE>",
  },
  // Banking — both the field-aware path and the IBAN/BIC patterns above kick
  // in. Field rule wins first because of the descent order, which is what we
  // want: a value sitting under `bankAccount` is redacted regardless of its
  // exact format.
  {
    kind: "field",
    name: "bank-field",
    fields: [
      "iban",
      "bic",
      "bankAccount",
      "bankCode",
      "bankName",
      "variableSymbol",
    ],
    replace: fieldHashReplacer("BANK"),
  },

  // Free-text message bodies. These tend to embed names, addresses, parcel
  // info reformatted as natural language ("Balík je připravený v AlzaBox
  // Jihlava…") that no other rule can reliably catch.
  {
    kind: "field",
    name: "message-field",
    fields: ["note", "content", "text", "emailTemplate"],
    replace: fieldHashReplacer("MSG"),
  },

  // KeyValueItem metadata pattern: `additionalInfo: [{key, value}, …]` and
  // similar. Redact only the `value` so Claude can still see which attribute
  // it was (e.g. `key=receiver_name`). The pattern shows up in DPD events but
  // also in many other systems' metadata payloads — generic enough.
  {
    kind: "path",
    name: "key-value-item-value",
    paths: [
      "**/additionalInfo/*/value",
      "**/properties/*/value",
      "**/attributes/*/value",
      "**/metadata/*/value",
      "**/tags/*/value",
    ],
    replace: hashReplacer("META"),
  },

  // Note: DPD business identifiers (14-digit parcel numbers, PUDO ids like
  // CZ12345, MPS ids, customer DSW) are intentionally NOT redacted. On their
  // own they are not personal data and devs need them to correlate a log line
  // with a concrete shipment, pickup point, or customer.
];
