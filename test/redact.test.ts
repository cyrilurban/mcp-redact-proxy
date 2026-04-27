import { describe, it, expect } from "vitest";
import {
  makeStats,
  redactJson,
  redactMcpToolResult,
  redactText,
} from "../src/redact.ts";
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

  it("does NOT redact PUDO IDs — devs need them for debugging", () => {
    const input =
      "CZ47227 sends for CZ21313, not for CZ47227; SK12345 separate; PL99999";
    const out = redactText(input, DEFAULT_RULES);
    expect(out).toBe(input);
    expect(out).not.toContain("<PUDO");
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

  it("does NOT redact parcel numbers — devs need them for debugging", () => {
    const out = redactText(
      "parcelNo 13845140149749 and again 13845140149749 but not 23655041587090",
      DEFAULT_RULES,
    );
    expect(out).toContain("13845140149749");
    expect(out).toContain("23655041587090");
    expect(out).not.toContain("<PARCEL");
  });

  it("redacts IBAN with consistent hash, both spaced and compact", () => {
    const stats = makeStats();
    const out = redactText(
      "primary CZ65 0800 0000 1920 0014 5399 same CZ6508000000192000145399 other DE89 3704 0044 0532 0130 00",
      DEFAULT_RULES,
      stats,
    );
    const tokens = out.match(/<IBAN_[a-f0-9]{6}>/g);
    expect(tokens).toHaveLength(3);
    expect(out).not.toMatch(/CZ65|DE89/);
    expect(stats.byRule.iban).toBe(3);
  });

  it("redacts Czech bank account numbers (with and without prefix)", () => {
    const out = redactText(
      "ucet 19-1234567890/0100 a 670100-2210123456/6210",
      DEFAULT_RULES,
    );
    const tokens = out.match(/<BANK_ACCT_[a-f0-9]{6}>/g);
    expect(tokens).toHaveLength(2);
    expect(out).not.toContain("1234567890");
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

  it("field rules redact names, addresses and bank fields by key", () => {
    const input = {
      info: {
        receiver: {
          name: "VF International Sagl",
          contactName: "Veronika Froncová",
          contactEmail: "v.froncova@example.com",
          contactPhone: "+420 284 089 355",
          street: "Ke Zdibsku 193",
          city: "Zdiby",
          zipCode: "25066",
          country: "203", // ISO numeric — must NOT be redacted
          pudoId: "CZ47227", // PUDO id — must NOT be redacted
        },
        courierTour: {
          courier: { name: "Jiří Nesvarba", phoneNumber: "+420 704 640 029" },
          deduplicationKey: "2371-708-2026-02-17",
        },
        parcelNumber: "23715032074790", // must NOT be redacted
        status: "Delivered", // must NOT be redacted (not in field list)
      },
      cod: {
        amount: 1500,
        currency: "CZK",
        bankAccount: "1234567890",
        bankCode: "0100",
        bankName: "Komerční banka",
        iban: "CZ6508000000192000145399",
        variableSymbol: "987654321",
      },
    };

    const stats = makeStats();
    const out = redactJson(input, DEFAULT_RULES, stats) as typeof input;

    // Names hashed
    expect(out.info.receiver.name).toMatch(/^<NAME_[a-f0-9]{6}>$/);
    expect(out.info.receiver.contactName).toMatch(/^<NAME_[a-f0-9]{6}>$/);
    // courier subtree → all string leaves hashed by name-field
    expect(out.info.courierTour.courier.name).toMatch(/^<NAME_[a-f0-9]{6}>$/);

    // Addresses hashed
    expect(out.info.receiver.street).toMatch(/^<ADDR_[a-f0-9]{6}>$/);
    expect(out.info.receiver.city).toMatch(/^<ADDR_[a-f0-9]{6}>$/);
    expect(out.info.receiver.zipCode).toMatch(/^<ADDR_[a-f0-9]{6}>$/);

    // Banking hashed
    expect(out.cod.bankAccount).toMatch(/^<BANK_[a-f0-9]{6}>$/);
    expect(out.cod.bankCode).toMatch(/^<BANK_[a-f0-9]{6}>$/);
    expect(out.cod.bankName).toMatch(/^<BANK_[a-f0-9]{6}>$/);
    expect(out.cod.iban).toMatch(/^<BANK_[a-f0-9]{6}>$/);
    expect(out.cod.variableSymbol).toMatch(/^<BANK_[a-f0-9]{6}>$/);

    // Email still hit by string rule (no field rule for contactEmail).
    expect(out.info.receiver.contactEmail).toMatch(/^<EMAIL_[a-f0-9]{6}>$/);
    // Phones hit by phone-field rule (fires before string rule), giving the
    // generic <PHONE> marker rather than the locale-specific <PHONE_CZ>.
    expect(out.info.receiver.contactPhone).toBe("<PHONE>");
    expect(out.info.courierTour.courier.phoneNumber).toBe("<PHONE>");

    // Business identifiers preserved
    expect(out.info.parcelNumber).toBe("23715032074790");
    expect(out.info.status).toBe("Delivered");
    expect(out.info.receiver.country).toBe("203");
    expect(out.info.receiver.pudoId).toBe("CZ47227");
    expect(out.info.courierTour.deduplicationKey).toBe("2371-708-2026-02-17");
    expect(out.cod.amount).toBe(1500);
    expect(out.cod.currency).toBe("CZK");
  });

  it("redacts BIC values via the bank-field key rule (no standalone BIC pattern)", () => {
    const out = redactJson(
      { cod: { bic: "GIBACZPX", currency: "CZK" } },
      DEFAULT_RULES,
    ) as { cod: { bic: string; currency: string } };
    expect(out.cod.bic).toMatch(/^<BANK_[a-f0-9]{6}>$/);
    expect(out.cod.currency).toBe("CZK");
  });

  it("path rule redacts KeyValueItem `value` while keeping `key` visible", () => {
    const input = {
      events: [
        {
          name: "scan",
          additionalInfo: [
            { key: "receiver_name", value: "Nikola Hladek" },
            { key: "cod_amount", value: "1783" },
            { key: "sender_name", value: "H&M Online" },
          ],
        },
      ],
    };
    const stats = makeStats();
    const out = redactJson(input, DEFAULT_RULES, stats) as typeof input;
    const ai = out.events[0].additionalInfo;
    // keys remain visible for correlation
    expect(ai[0].key).toBe("receiver_name");
    expect(ai[1].key).toBe("cod_amount");
    expect(ai[2].key).toBe("sender_name");
    // values are hashed — even the benign 1783, by design (path-based, not key-aware)
    expect(ai[0].value).toMatch(/^<META_[a-f0-9]{6}>$/);
    expect(ai[1].value).toMatch(/^<META_[a-f0-9]{6}>$/);
    expect(ai[2].value).toMatch(/^<META_[a-f0-9]{6}>$/);
    // identical PII → identical hash
    expect(ai[0].value).not.toBe(ai[1].value);
    expect(stats.byRule["key-value-item-value"]).toBe(3);
  });

  it("message-field rule redacts SMS / email content bodies", () => {
    const input = {
      notifications: [
        {
          content: "Balík je připravený v AlzaBox Jihlava, Pelhřimovská 70.",
          emailTemplate: "PUDO_READY_v3",
          purpose: "PICKUP_READY",
        },
      ],
      conversations: [{ text: "Jsem před domem, prosím sejděte" }],
      events: [{ note: "Volat zákazníka Nikolu Hladkovou", asCode: "P1" }],
    };
    const out = redactJson(input, DEFAULT_RULES) as typeof input;
    expect(out.notifications[0].content).toMatch(/^<MSG_[a-f0-9]{6}>$/);
    expect(out.notifications[0].emailTemplate).toMatch(/^<MSG_[a-f0-9]{6}>$/);
    expect(out.notifications[0].purpose).toBe("PICKUP_READY"); // not in rule
    expect(out.conversations[0].text).toMatch(/^<MSG_[a-f0-9]{6}>$/);
    expect(out.events[0].note).toMatch(/^<MSG_[a-f0-9]{6}>$/);
    expect(out.events[0].asCode).toBe("P1"); // not in rule
  });

  it("phone-field rule redacts bare phone numbers without an international prefix", () => {
    const out = redactJson(
      {
        carrier: { phoneNumber: "722 044 240" },
        receiverPhone: "605123456",
        contactPhone: "+420 284 089 355",
      },
      DEFAULT_RULES,
    ) as { carrier: { phoneNumber: string }; receiverPhone: string; contactPhone: string };
    expect(out.carrier.phoneNumber).toBe("<PHONE>");
    expect(out.receiverPhone).toBe("<PHONE>");
    expect(out.contactPhone).toBe("<PHONE>");
  });

  it("identical values inside a field rule produce identical hashes", () => {
    const input = {
      a: { contactName: "Veronika Froncová" },
      b: { contactName: "Veronika Froncová" },
      c: { contactName: "Někdo Jiný" },
    };
    const out = redactJson(input, DEFAULT_RULES) as typeof input;
    expect(out.a.contactName).toBe(out.b.contactName);
    expect(out.a.contactName).not.toBe(out.c.contactName);
  });
});

describe("redactMcpToolResult — MCP envelope handling", () => {
  it("parses JSON text content so field rules can fire on the structured payload", () => {
    const innerData = {
      info: {
        receiver: { name: "VF International", street: "Ke Zdibsku 193" },
        parcelNumber: "23715032074790",
      },
    };
    const envelope = {
      content: [{ type: "text", text: JSON.stringify(innerData) }],
    };
    const stats = makeStats();
    const out = redactMcpToolResult(envelope, DEFAULT_RULES, stats) as {
      content: { type: string; text: string }[];
    };
    const redacted = JSON.parse(out.content[0].text);
    expect(redacted.info.receiver.name).toMatch(/^<NAME_[a-f0-9]{6}>$/);
    expect(redacted.info.receiver.street).toMatch(/^<ADDR_[a-f0-9]{6}>$/);
    expect(redacted.info.parcelNumber).toBe("23715032074790");
    expect(stats.byRule["name-field"]).toBeGreaterThanOrEqual(1);
    expect(stats.byRule["address-field"]).toBeGreaterThanOrEqual(1);
  });

  it("falls back to string redaction when text content is not JSON", () => {
    const envelope = {
      content: [{ type: "text", text: "user@example.com sent a request" }],
    };
    const out = redactMcpToolResult(envelope, DEFAULT_RULES) as {
      content: { type: string; text: string }[];
    };
    expect(out.content[0].text).toMatch(/<EMAIL_[a-f0-9]{6}> sent a request/);
  });

  it("preserves non-text content blocks (images / resources)", () => {
    const envelope = {
      content: [
        { type: "image", data: "iVBORw0KG…", mimeType: "image/png" },
        { type: "text", text: "ok" },
      ],
    };
    const out = redactMcpToolResult(envelope, DEFAULT_RULES) as {
      content: { type: string; data?: string; text?: string }[];
    };
    expect(out.content[0]).toMatchObject({ type: "image" });
    expect(out.content[1]).toMatchObject({ type: "text", text: "ok" });
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
    expect(out).not.toContain("mYy0Lp2pMU21jYI1EFJl6PbPxjHMuQ23");

    // But keep structural / non-sensitive fields readable — including
    // business identifiers like PUDO id and parcel no that devs need.
    expect(out).toContain("GraphQL response");
    expect(out).toContain("Something went wrong");
    expect(out).toContain("User-Agent");
    expect(out).toContain("axios/0.27.2");
    expect(out).toContain('"status":405');
    expect(out).toContain("CZ37907"); // PUDO id stays visible

    expect(stats.byRule.email).toBeGreaterThanOrEqual(1);
    expect(stats.byRule.uuid).toBeGreaterThanOrEqual(1);
    expect(stats.byRule["api-key-header"]).toBeGreaterThanOrEqual(1);
  });
});
