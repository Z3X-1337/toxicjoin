import { describe, expect, it } from "vitest";

import type { DemoScenario, PipelineResponse } from "../types";
import { shouldAutoRunSelectedScenario } from "./useJudgeSession";

const SELECTED_SCENARIO = {} as DemoScenario;

function state(overrides: Partial<{
  bootstrapping: boolean;
  running: boolean;
  result: PipelineResponse | null;
  error: string | null;
}> = {}) {
  return {
    bootstrapping: false,
    running: false,
    result: null,
    error: null,
    ...overrides,
  };
}

describe("shouldAutoRunSelectedScenario", () => {
  it("allows the single initial execution when the session is ready", () => {
    expect(shouldAutoRunSelectedScenario(state(), SELECTED_SCENARIO)).toBe(true);
  });

  it("stops automatic execution after a protected execution error", () => {
    expect(
      shouldAutoRunSelectedScenario(
        state({ error: "Request failed: 503" }),
        SELECTED_SCENARIO,
      ),
    ).toBe(false);
  });

  it.each([
    ["bootstrapping", state({ bootstrapping: true }), SELECTED_SCENARIO],
    ["running", state({ running: true }), SELECTED_SCENARIO],
    ["completed", state({ result: {} as PipelineResponse }), SELECTED_SCENARIO],
    ["no scenario", state(), null],
  ])("does not auto-run while %s", (_label, sessionState, scenario) => {
    expect(shouldAutoRunSelectedScenario(sessionState, scenario)).toBe(false);
  });
});
