import { afterEach, describe, expect, it, vi } from "vitest";

import type { DemoScenario } from "../types";
import { bootstrapJudgeSession, executeScenario } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Render-only API boundary", () => {
  it("rejects bootstrap when the same-origin API is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));

    await expect(bootstrapJudgeSession()).rejects.toEqual(
      expect.objectContaining({
        name: "ToxicJoinApiError",
        message: "The Render API is currently unreachable.",
      }),
    );
  });

  it("does not return static scenario data after an execution failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 503 })));
    const scenario = {
      request: {
        task_purpose: "test",
        sql: "SELECT 1",
        subject_key: { dataset: "x", field_path: "id" },
        dialect: "duckdb",
      },
    } as DemoScenario;

    await expect(executeScenario(scenario)).rejects.toEqual(
      expect.objectContaining({ name: "ToxicJoinApiError", status: 503 }),
    );
  });
});
