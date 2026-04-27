# @qest/mcp-redact-proxy

A tiny stdio proxy that sits between an MCP client (Claude Code, Cursor, VS Code extension, …) and any MCP server, and **redacts PII / secrets** from tool-call responses before they ever reach the LLM.

Built out of a GDPR concern when wiring Claude Code into production Grafana/Loki queries. Written as defense-in-depth — the real fix is to never log PII in the first place (`pino.redact` + field whitelist at the logger), but until every service is audited this proxy gives you a safety net.

## Why another gateway?

We evaluated [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway) and it had two blockers:

1. It builds dynamic Python functions from the inner MCP's tool schema, which crashes on tools with reserved words (`for` in Prometheus alerting) or hyphens (`filter-query` in Tempo search) in parameter names.
2. The Presidio plugin is English-only out of the box and doesn't know about domain-specific identifiers we cared about.

So this is ~200 lines of TypeScript doing exactly one thing: pipe JSON-RPC through, regex-redact the `tools/call` response payloads, nothing else.

## What it redacts by default

There are two kinds of rule:

- **String-pattern rules** (regex) — fire on every string leaf. Use for self-identifying values like emails, JWTs, IBANs.
- **Field-aware rules** — fire when a JSON property's *key* matches. Use for values that look like ordinary strings on their own (a name, a street) and only need redacting because of the surrounding key.

| Rule                  | Kind   | Catches                                                | Replacement                        |
| --------------------- | ------ | ------------------------------------------------------ | ---------------------------------- |
| `api-key-header`      | string | `x-api-key`, `authorization`, `bearer`, `secret`, `password` values (incl. escaped JSON) | `<REDACTED_SECRET>`   |
| `jwt`                 | string | `eyJ...` JSON Web Tokens                               | `<JWT>`                            |
| `grafana-sa-token`    | string | `glsa_...` Grafana service account tokens             | `<GRAFANA_SA_TOKEN>`               |
| `email`               | string | `user@domain.tld`                                      | `<EMAIL_abc123>` (SHA-256 hash)    |
| `uuid`                | string | RFC 4122 UUIDs (Cognito sub, request ids)              | `<UUID_abc123>` (SHA-256 hash)     |
| `phone-cz` / `-sk`    | string | `+420…`, `+421…` numbers                               | `<PHONE_CZ>` / `<PHONE_SK>`        |
| `phone-intl`          | string | `+CC...` other international numbers                  | `<PHONE>`                          |
| `iban`                | string | ISO 13616 IBANs (`CZ65 0800…`, `DE89 3704…`)           | `<IBAN_abc123>`                    |
| `cz-bank-account`     | string | Czech bank accounts (`19-1234567890/0100`)             | `<BANK_ACCT_abc123>`               |
| `card-last4-masked`   | string | `Visa **** **** **** 1234` strings                    | `<CARD_****_****_****_XXXX>`       |
| `card-pan`            | string | Formatted PAN `1234-5678-9012-3456`                    | `<CARD_PAN>`                       |
| `worldline-auth-code` | string | `Authorization code: (00)510096`                       | `Authorization code: (00)XXXXXX`   |
| `hex-crypto`          | string | ARQC, AID (hex blobs 12+ chars with at least one A-F) | `<HEX_CRYPTO>`                     |
| `name-field`          | field  | Keys: `name`, `contactName`, `name2`, `company`, `owner`, `editPerson`, `author`, `pickupPointName` | `<NAME_abc123>` (SHA-256 hash) |
| `address-field`       | field  | Keys: `street`, `city`, `zipCode`, `building`, `floor`, `department`, `delivery`, `address` | `<ADDR_abc123>`        |
| `bank-field`          | field  | Keys: `iban`, `bic`, `bankAccount`, `bankCode`, `bankName`, `variableSymbol` | `<BANK_abc123>`             |

Hash-based rules use a deterministic SHA-256 truncated to 6 hex chars, so the same email / uuid / name always produces the same token **within one process run**. This lets the LLM still correlate events ("same user triggered the error 7×") without ever seeing the real identifier.

### MCP envelope handling

Most MCP tools wrap their result inside `content: [{type: "text", text: "<stringified JSON>"}]`. Plain string-leaf walking can't see the keys inside that string, so field rules would miss everything. The proxy detects JSON text blocks, parses them, runs full field-aware redaction over the parsed value, and re-serialises — so `bankAccount` and `street` get scrubbed even though they live inside a wrapper string.

## Install

```bash
yarn add --dev @qest/mcp-redact-proxy
# or globally:
npm i -g @qest/mcp-redact-proxy
```

## Usage

Drop-in replacement for any MCP server command. Put `--` and then the original command:

```bash
mcp-redact-proxy -- uvx mcp-grafana
```

### Claude Code / VS Code extension

In `~/.claude.json` replace your existing entry:

```jsonc
{
  "mcpServers": {
    "grafana": {
      "type": "stdio",
      "command": "mcp-redact-proxy",
      "args": ["--", "uvx", "mcp-grafana"],
      "env": {
        "GRAFANA_URL": "https://your-org.grafana.net",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_..."
      }
    }
  }
}
```

Environment variables are inherited by the inner command, so put credentials there as usual.

### Verifying it's on

On every redacted tool call the proxy writes a one-line stats report to its stderr:

```
[mcp-redact-proxy] tool=query_loki_logs redacted=8 by={"api-key-header":2,"email":2,"uuid":4}
```

If you see zero redactions on a response you expect to contain PII, tighten the rules.

## Extending rules

The default rule set is in [`src/rules.ts`](src/rules.ts). Adding a domain-specific rule is:

```ts
export const DEFAULT_RULES: readonly RedactionRule[] = [
  // …
  {
    name: "internal-ticket-id",
    pattern: /\bTCK-\d{6}\b/g,
    replace: "<TICKET>",
  },
];
```

Rebuild (`yarn build`) and publish a new patch version.

## What this is **not**

- **Not a primary GDPR control.** Pino redact + whitelist at the logger is. This proxy is defense-in-depth.
- **Not NLP-based.** We intentionally avoided Presidio / LLM-based redaction because (a) regex is explainable to compliance, (b) no spaCy download on every startup, (c) Czech-language support is poor in off-the-shelf NLP PII libs.
- **Not a request redactor.** The LLM's outgoing queries (LogQL, WIQL, etc.) are not redacted — if that's a concern you shouldn't be using the MCP at all.
- **Not a bypass.** Someone sufficiently motivated can still exfiltrate via a contrived query; use Grafana service-account-token scoping for strong access control.

## Development

```bash
yarn install
yarn test           # vitest
yarn test:watch
yarn build          # tsc → dist/
yarn dev -- uvx mcp-grafana  # run against a real MCP
```

## License

MIT
