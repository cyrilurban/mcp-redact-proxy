import { describe, it, expect } from "vitest";
import { redactText, redactJson, makeStats } from "../src/redact.ts";
import { DEFAULT_RULES } from "../src/rules.ts";

describe("redactText — individual rules", () => {
  it("redacts emails with consistent hash (same email → same token)", () => {
    const stats = makeStats();
    const out = redactText(
      "User blechova.blanka@seznam.cz triggered error for blechova.blanka@seznam.cz; cc: jiri.novak@example.cz",
      DEFAULT_RULES,
      stats,
    );
    expect(out).not.toMatch(/blechova|jiri\.novak/);
    const tokens = out.match(/<EMAIL_[a-f0-9]{6}>/g);
    expect(tokens).toHaveLength(3);
    expect(tokens![0]).toBe(tokens![1]); // same email → same hash
    expect(tokens![0]).not.toBe(tokens![2]); // different email → different hash
    expect(stats.byRule.email).toBe(3);
  });

  it("redacts x-api-key in plain JSON form", () => {
    const input = `"headers":{"x-api-key":"mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23","User-Agent":"axios/0.27.2"}`;
    const out = redactText(input, DEFAULT_RULES);
    expect(out).toContain("<REDACTED_SECRET>");
    expect(out).not.toContain("mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23");
    expect(out).toContain("User-Agent");
    expect(out).toContain("axios/0.27.2");
  });

  it("redacts x-api-key in escaped-JSON form (Loki embeds stringified JSON)", () => {
    // This is what a Loki `text` content looks like: the log line is itself
    // JSON, stringified, so quotes inside are escaped with backslashes.
    const input = String.raw`{"headers":{\"x-api-key\":\"mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23\"}}`;
    const out = redactText(input, DEFAULT_RULES);
    expect(out).toContain("<REDACTED_SECRET>");
    expect(out).not.toContain("mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23");
  });

  it("redacts Grafana service account tokens", () => {
    const input = "token=glsa_HgtnDRFPYwtsHIJlzytsl6nLHsusn6OC_7854d5bb";
    expect(redactText(input, DEFAULT_RULES)).toContain("<GRAFANA_SA_TOKEN>");
  });

  it("redacts Cognito sub UUIDs consistently", () => {
    const input =
      "cognitoSub=f3623e55-5b76-4c1b-b045-89ea36c71978 other=a7cdcfcb-3a7e-4e23-868a-43edeedbe15b first=f3623e55-5b76-4c1b-b045-89ea36c71978";
    const out = redactText(input, DEFAULT_RULES);
    expect(out).not.toContain("f3623e55");
    expect(out).not.toContain("a7cdcfcb");
    const tokens = out.match(/<UUID_[a-f0-9]{6}>/g);
    expect(tokens).toHaveLength(3);
    expect(tokens![0]).toBe(tokens![2]);
    expect(tokens![0]).not.toBe(tokens![1]);
  });

  it("redacts PUDO IDs for CZ/SK/PL/HU with correlation-preserving hash", () => {
    const out = redactText(
      "CZ47227 sends for CZ21313, not for CZ47227; SK12345 separate; PL99999",
      DEFAULT_RULES,
    );
    const pudos = out.match(/<PUDO_[a-f0-9]{6}>/g)!;
    expect(pudos).toHaveLength(5);
    expect(pudos[0]).toBe(pudos[2]); // CZ47227 appears twice
    expect(pudos[0]).not.toBe(pudos[1]); // CZ47227 ≠ CZ21313
  });

  it("redacts Czech phone numbers in several forms", () => {
    expect(redactText("+420 602 123 456", DEFAULT_RULES)).toContain(
      "<PHONE_CZ>",
    );
    expect(redactText("420602123456", DEFAULT_RULES)).toContain("<PHONE_CZ>");
    expect(redactText("+420-602-123-456", DEFAULT_RULES)).toContain(
      "<PHONE_CZ>",
    );
  });

  it("redacts Slovak phone numbers", () => {
    expect(redactText("+421 905 123 456", DEFAULT_RULES)).toContain(
      "<PHONE_SK>",
    );
  });

  it("redacts other international phones", () => {
    expect(redactText("+4915112345678", DEFAULT_RULES)).toContain("<PHONE>");
  });

  it("redacts masked card last4 strings from receipts", () => {
    expect(redactText("Visa **** **** **** 0902", DEFAULT_RULES)).toContain(
      "<CARD_****_****_****_XXXX>",
    );
    expect(
      redactText("Mastercard **** **** **** 2970", DEFAULT_RULES),
    ).toContain("<CARD_****_****_****_XXXX>");
  });

  it("redacts Worldline authorization code preserving (00) prefix", () => {
    const input = "Authorization code:           (00)510096";
    const out = redactText(input, DEFAULT_RULES);
    expect(out).toContain("(00)XXXXXX");
    expect(out).not.toContain("510096");
  });

  it("redacts ARQC-style hex crypto blobs", () => {
    expect(redactText("ARQC: C66C19398898FDA9", DEFAULT_RULES)).toContain(
      "<HEX_CRYPTO>",
    );
    expect(redactText("AID: A0000000031010", DEFAULT_RULES)).toContain(
      "<HEX_CRYPTO>",
    );
  });

  it("redacts parcel numbers as correlation-preserving hash", () => {
    const out = redactText(
      "parcelNo 13845140149749 and again 13845140149749 but not 23655041587090",
      DEFAULT_RULES,
    );
    const tokens = out.match(/<PARCEL_[a-f0-9]{6}>/g)!;
    expect(tokens).toHaveLength(3);
    expect(tokens[0]).toBe(tokens[1]); // same parcel
    expect(tokens[0]).not.toBe(tokens[2]); // different parcel
  });

  it("leaves non-matching text untouched", () => {
    const input =
      "GraphQL response status=ok level=info duration=123ms count=42";
    expect(redactText(input, DEFAULT_RULES)).toBe(input);
  });
});

describe("redactJson — structural recursion", () => {
  it("walks nested objects and arrays, redacting only string leaves", () => {
    const input = {
      user: { email: "test@example.com", id: 615 },
      errors: [
        { message: "sub: f3623e55-5b76-4c1b-b045-89ea36c71978", code: 400 },
      ],
      count: 42,
      active: true,
      nothing: null,
    };
    const stats = makeStats();
    const out = redactJson(input, DEFAULT_RULES, stats) as typeof input;
    expect(out.user.email).toMatch(/^<EMAIL_[a-f0-9]{6}>$/);
    expect(out.user.id).toBe(615);
    expect(out.errors[0].message).toMatch(/^sub: <UUID_[a-f0-9]{6}>$/);
    expect(out.errors[0].code).toBe(400);
    expect(out.count).toBe(42);
    expect(out.active).toBe(true);
    expect(out.nothing).toBeNull();
    expect(stats.totalMatches).toBe(2);
  });

  it("does not mutate the input", () => {
    const input = { email: "test@example.com" };
    redactJson(input, DEFAULT_RULES);
    expect(input.email).toBe("test@example.com");
  });
});

describe("real-world log line from DPD My Pickup production", () => {
  it("redacts every category of PII found in the sample", () => {
    const realLog = JSON.stringify({
      time: "2026-04-23T11:08:30.819Z",
      level: "info",
      msg: "GraphQL response:",
      user: {
        id: 6611,
        email: "hieucz123@gmail.com",
        cognitoSub: "a7cdcfcb-3a7e-4e23-868a-43edeedbe15b",
        pudoId: "CZ37907",
      },
      response: {
        errors: [
          {
            message: "Something went wrong",
            extensions: {
              exception: {
                payload: {
                  error: {
                    config: {
                      headers: {
                        "x-api-key": "mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23",
                        "User-Agent": "axios/0.27.2",
                      },
                    },
                    status: 405,
                  },
                },
              },
            },
          },
        ],
      },
    });

    const stats = makeStats();
    const out = redactText(realLog, DEFAULT_RULES, stats);

    expect(out).not.toContain("hieucz123@gmail.com");
    expect(out).not.toContain("a7cdcfcb-3a7e-4e23-868a-43edeedbe15b");
    expect(out).not.toContain("CZ37907");
    expect(out).not.toContain("mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23");

    // But keep structural / non-sensitive fields readable
    expect(out).toContain("GraphQL response");
    expect(out).toContain("Something went wrong");
    expect(out).toContain("User-Agent");
    expect(out).toContain("axios/0.27.2");
    expect(out).toContain('"status":405');

    expect(stats.byRule.email).toBeGreaterThanOrEqual(1);
    expect(stats.byRule.uuid).toBeGreaterThanOrEqual(1);
    expect(stats.byRule["pudo-id"]).toBeGreaterThanOrEqual(1);
    expect(stats.byRule["api-key-header"]).toBeGreaterThanOrEqual(1);
  });
});
