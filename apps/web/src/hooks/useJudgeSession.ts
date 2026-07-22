import { useCallback, useEffect, useMemo, useState } from "react";

import {
  bootstrapJudgeSession,
  executeScenario,
  ToxicJoinApiError,
} from "../lib/api";
import type {
  BenchmarkSummary,
  DemoScenario,
  HealthResponse,
  PipelineResponse,
  SourceMode,
} from "../types";

interface JudgeSessionState {
  sourceMode: SourceMode;
  health: HealthResponse | null;
  scenarios: DemoScenario[];
  benchmark: BenchmarkSummary | null;
  selectedScenarioId: string;
  result: PipelineResponse | null;
  bootstrapping: boolean;
  running: boolean;
  notice: string | null;
  error: string | null;
}

interface JudgeSessionActions {
  selectScenario: (scenarioId: string) => void;
  runSelectedScenario: () => Promise<void>;
  retryBootstrap: () => Promise<void>;
}

export interface JudgeSessionController extends JudgeSessionState, JudgeSessionActions {
  selectedScenario: DemoScenario | null;
}

const DEFAULT_SCENARIO = "rewrite-churn-regions";

const INITIAL_STATE: JudgeSessionState = {
  sourceMode: "replay",
  health: null,
  scenarios: [],
  benchmark: null,
  selectedScenarioId: DEFAULT_SCENARIO,
  result: null,
  bootstrapping: true,
  running: false,
  notice: null,
  error: null,
};

export function useJudgeSession(): JudgeSessionController {
  const [state, setState] = useState<JudgeSessionState>(INITIAL_STATE);

  const bootstrap = useCallback(async (): Promise<void> => {
    setState((current) => ({
      ...current,
      bootstrapping: true,
      error: null,
    }));
    const loaded = await bootstrapJudgeSession();
    const selectedScenarioId = loaded.scenarios.some(
      (scenario) => scenario.scenario_id === DEFAULT_SCENARIO,
    )
      ? DEFAULT_SCENARIO
      : (loaded.scenarios[0]?.scenario_id ?? "");

    setState((current) => ({
      ...current,
      sourceMode: loaded.sourceMode,
      health: loaded.health,
      scenarios: loaded.scenarios,
      benchmark: loaded.benchmark,
      selectedScenarioId,
      result: null,
      bootstrapping: false,
      running: false,
      notice: loaded.warning,
      error: null,
    }));
  }, []);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  const selectedScenario = useMemo(
    () =>
      state.scenarios.find(
        (scenario) => scenario.scenario_id === state.selectedScenarioId,
      ) ?? null,
    [state.scenarios, state.selectedScenarioId],
  );

  const runScenario = useCallback(
    async (scenario: DemoScenario): Promise<void> => {
      setState((current) => ({
        ...current,
        running: true,
        error: null,
      }));
      try {
        const result = await executeScenario(scenario, state.sourceMode);
        setState((current) => ({
          ...current,
          result,
          running: false,
          error: null,
        }));
      } catch (error) {
        const message =
          error instanceof ToxicJoinApiError
            ? error.message
            : "The protected execution could not be completed.";
        setState((current) => ({
          ...current,
          running: false,
          error: message,
        }));
      }
    },
    [state.sourceMode],
  );

  useEffect(() => {
    if (
      state.bootstrapping ||
      state.running ||
      state.result ||
      !selectedScenario
    ) {
      return;
    }
    void runScenario(selectedScenario);
  }, [runScenario, selectedScenario, state.bootstrapping, state.result, state.running]);

  const selectScenario = useCallback((scenarioId: string): void => {
    setState((current) => ({
      ...current,
      selectedScenarioId: scenarioId,
      result: null,
      error: null,
    }));
  }, []);

  const runSelectedScenario = useCallback(async (): Promise<void> => {
    if (!selectedScenario) {
      return;
    }
    await runScenario(selectedScenario);
  }, [runScenario, selectedScenario]);

  return {
    ...state,
    selectedScenario,
    selectScenario,
    runSelectedScenario,
    retryBootstrap: bootstrap,
  };
}
