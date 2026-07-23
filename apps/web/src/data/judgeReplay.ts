import {
  replayBenchmark,
  replayHealth,
  replayResults as baseReplayResults,
  replayScenarios,
} from "./replay";
import type { PipelineResponse } from "../types";

const INVALID_ORDER = [
  "ORDER BY c.coarse_region",
  "HAVING COUNT(DISTINCT c.customer_id) >= 20",
].join("\n");
const VALID_ORDER = [
  "HAVING COUNT(DISTINCT c.customer_id) >= 20",
  "ORDER BY c.coarse_region",
].join("\n");

function normalizeReplayResult(result: PipelineResponse): PipelineResponse {
  if (!result.safe_sql) {
    return result;
  }
  return {
    ...result,
    safe_sql: result.safe_sql.replace(INVALID_ORDER, VALID_ORDER),
  };
}

export { replayBenchmark, replayHealth, replayScenarios };

export const replayResults: Record<string, PipelineResponse> = Object.fromEntries(
  Object.entries(baseReplayResults).map(([scenarioId, result]) => [
    scenarioId,
    normalizeReplayResult(result),
  ]),
);
