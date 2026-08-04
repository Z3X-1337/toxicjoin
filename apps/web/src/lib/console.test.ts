import { afterEach, describe, expect, it, vi } from "vitest";

import { CONSOLE_PRESETS, DEFAULT_PRESET_ID, presetById } from "../data/presets";
import { CONSOLE_ENDPOINTS, ConsoleApiError, submitConsoleQuery } from "./console";
import {
  buildConsoleRequest,
  isConsoleFormComplete,
  type ConsoleFormState,
} from "../hooks/useQueryConsole";

const FORM: ConsoleFormState = {
  taskPurpose: "  Count orders  ",
  sql: "  SELECT o.category FROM orders o  ",
  subjectDataset: " customers ",
  subjectField: " customer_id ",
  mode: "analyze",
};

function stubFetch(implementation: typeof fetch) {
  vi.stubGlobal("fetch", implementation);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("console request building", () => {
  it("trims every operator-supplied field before sending", () => {
    expect(buildConsoleRequest(FORM)).toEqual({
      task_purpose: "Count orders",
      sql: "SELECT o.category FROM orders o",
      subject_key: { dataset: "customers", field_path: "customer_id" },
      dialect: "duckdb",
    });
  });

  it("treats whitespace-only input as incomplete", () => {
    expect(isConsoleFormComplete(FORM)).toBe(true);
    expect(isConsoleFormComplete({ ...FORM, sql: "   " })).toBe(false);
    expect(isConsoleFormComplete({ ...FORM, subjectField: "" })).toBe(false);
  });
});

describe("console transport", () => {
  it("targets the real endpoint for the selected action", async () => {
    const calls: string[] = [];
    stubFetch((async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ effective_decision: "ALLOW" }), { status: 200 });
    }) as typeof fetch);

    await submitConsoleQuery(buildConsoleRequest(FORM), "analyze");
    await submitConsoleQuery(buildConsoleRequest(FORM), "execute");

    expect(calls).toEqual([CONSOLE_ENDPOINTS.analyze, CONSOLE_ENDPOINTS.execute]);
  });

  it("never substitutes replay data when the API is unreachable", async () => {
    stubFetch((async () => {
      throw new TypeError("network down");
    }) as typeof fetch);

    await expect(submitConsoleQuery(buildConsoleRequest(FORM), "execute")).rejects.toBeInstanceOf(
      ConsoleApiError,
    );
  });

  it("surfaces the API error code rather than a generic failure", async () => {
    stubFetch((async () =>
      new Response(JSON.stringify({ detail: { code: "RATE_LIMIT_EXCEEDED" } }), {
        status: 429,
      })) as typeof fetch);

    await expect(
      submitConsoleQuery(buildConsoleRequest(FORM), "execute"),
    ).rejects.toMatchObject({ code: "RATE_LIMIT_EXCEEDED", status: 429 });
  });
});

describe("console presets", () => {
  it("exposes the three outcomes and both closed bypasses", () => {
    const kinds = CONSOLE_PRESETS.map((preset) => preset.kind);
    expect(kinds.filter((kind) => kind === "outcome")).toHaveLength(3);
    expect(kinds.filter((kind) => kind === "attack")).toHaveLength(2);
  });

  it("expects every attack preset to be blocked", () => {
    const attacks = CONSOLE_PRESETS.filter((preset) => preset.kind === "attack");
    expect(attacks.every((preset) => preset.expectedDecision === "BLOCK")).toBe(true);
  });

  it("declares a weak subject key only in the subject-attack preset", () => {
    const weak = CONSOLE_PRESETS.filter(
      (preset) => preset.request.subject_key.dataset !== "customers",
    );
    expect(weak.map((preset) => preset.id)).toEqual(["attack-weak-subject-key"]);
  });

  it("resolves an unknown preset id to a real preset instead of undefined", () => {
    expect(presetById("does-not-exist")).toBeDefined();
    expect(presetById(DEFAULT_PRESET_ID).id).toBe(DEFAULT_PRESET_ID);
  });
});
