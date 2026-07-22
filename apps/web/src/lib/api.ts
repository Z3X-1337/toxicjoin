import {
  replayBenchmark,
  replayHealth,
  replayResults,
  replayScenarios,
} from "../data/replay";
import type {
  BenchmarkSummary,
  DemoScenario,
  DemoScenarioList,
  HealthResponse,
  PipelineResponse,
  SourceMode,
} from "../types";

const REQUEST_TIMEOUT_MS = 12_000;

export class ToxicJoinApiError extends Error {
  public constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = "ToxicJoinApiError";
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  headers.set("Content-Type", "application/json");

  try {
    const response = await fetch(path, {
      ...init,
      headers,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new ToxicJoinApiError(`Request failed: ${response.status}`, response.status);
    }
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ToxicJoinApiError) {
      throw error;
    }
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ToxicJoinApiError("The ToxicJoin API request timed out.");
    }
    throw new ToxicJoinApiError("The ToxicJoin API is unavailable.");
  } finally {
    window.clearTimeout(timeout);
  }
}

export interface BootstrapResult {
  sourceMode: SourceMode;
  health: HealthResponse;
  scenarios: DemoScenario[];
  benchmark: BenchmarkSummary;
  warning: string | null;
}

export async function bootstrapJudgeSession(): Promise<BootstrapResult> {
  try {
    const [health, scenarioList, benchmark] = await Promise.all([
      requestJson<HealthResponse>("/api/health"),
      requestJson<DemoScenarioList>("/api/demo/scenarios"),
      requestJson<BenchmarkSummary>("/api/benchmark/summary"),
    ]);
    return {
      sourceMode: "api",
      health,
      scenarios: scenarioList.scenarios,
      benchmark,
      warning: null,
    };
  } catch {
    return {
      sourceMode: "replay",
      health: replayHealth,
      scenarios: replayScenarios,
      benchmark: replayBenchmark,
      warning:
        "API unavailable. Showing a clearly labeled deterministic replay; no live execution or DataHub write is being claimed.",
    };
  }
}

export async function executeScenario(
  scenario: DemoScenario,
  sourceMode: SourceMode,
): Promise<PipelineResponse> {
  if (sourceMode === "replay") {
    const replay = replayResults[scenario.scenario_id];
    if (!replay) {
      throw new ToxicJoinApiError("Replay scenario not found.");
    }
    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, 420);
    });
    return replay;
  }

  return requestJson<PipelineResponse>("/api/execute-safe", {
    method: "POST",
    body: JSON.stringify(scenario.request),
  });
}
