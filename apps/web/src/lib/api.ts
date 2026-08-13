import type { BenchmarkSummary, DemoScenario, DemoScenarioList, HealthResponse, PipelineResponse } from "../types";

const REQUEST_TIMEOUT_MS = 45_000;

export class ToxicJoinApiError extends Error {
  public constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = "ToxicJoinApiError";
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  headers.set("Content-Type", "application/json");
  try {
    const response = await fetch(path, { ...init, headers, signal: controller.signal });
    if (!response.ok) throw new ToxicJoinApiError(`Request failed with HTTP ${response.status}.`, response.status);
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ToxicJoinApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw new ToxicJoinApiError("The Render service did not become ready in time.");
    throw new ToxicJoinApiError("The Render API is currently unreachable.");
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export interface BootstrapResult { health: HealthResponse; scenarios: DemoScenario[]; benchmark: BenchmarkSummary; }

export async function bootstrapJudgeSession(): Promise<BootstrapResult> {
  const [health, scenarioList, benchmark] = await Promise.all([
    requestJson<HealthResponse>("/api/ready"),
    requestJson<DemoScenarioList>("/api/demo/scenarios"),
    requestJson<BenchmarkSummary>("/api/benchmark/summary"),
  ]);
  return { health, scenarios: scenarioList.scenarios, benchmark };
}

export async function executeScenario(scenario: DemoScenario): Promise<PipelineResponse> {
  return requestJson<PipelineResponse>("/api/execute-safe", { method: "POST", body: JSON.stringify(scenario.request) });
}
