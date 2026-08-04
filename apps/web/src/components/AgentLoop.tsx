import { useCallback, useState } from "react";

import { ConsoleApiError } from "../lib/console";
import type { Decision } from "../types";

/**
 * The Governed Agent loop.
 *
 * This is the claim the project is built around, made watchable: the agent proposes, ToxicJoin
 * refuses, the agent reads a deterministic reason code and tries again. Authorization never
 * moves. Like the console, this panel calls the real endpoint and never falls back to canned
 * data.
 */

const AGENT_ENDPOINT = "/api/agent/run";

interface AgentAttempt {
  iteration: number;
  capability: string;
  task_purpose: string;
  sql: string;
  proposal_sha256: string;
  decision: Decision;
  reason_codes: string[];
  safe_sql: string | null;
  receipt_id: string;
  released_row_count: number | null;
}

interface AgentSessionResult {
  goal: string;
  goal_sha256: string;
  data_context_sha256: string;
  attempts: AgentAttempt[];
  final_decision: Decision;
  succeeded: boolean;
  exhausted_attempts: boolean;
}

const GOAL_PRESETS = [
  "Find regions with elevated churn risk",
  "Export customers with sensitive support cases",
  "Compare average spend across regions",
] as const satisfies readonly string[];

export function AgentLoop() {
  const [goal, setGoal] = useState<string>(GOAL_PRESETS[0]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AgentSessionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    if (!goal.trim() || running) {
      return;
    }
    setRunning(true);
    setError(null);
    try {
      const response = await fetch(AGENT_ENDPOINT, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ goal: goal.trim() }),
      });
      if (!response.ok) {
        throw new ConsoleApiError(`The agent run failed with HTTP ${response.status}.`);
      }
      setResult((await response.json()) as AgentSessionResult);
    } catch (caught) {
      setResult(null);
      setError(
        caught instanceof ConsoleApiError
          ? caught.message
          : "The ToxicJoin API is unreachable. Start it and retry.",
      );
    } finally {
      setRunning(false);
    }
  }, [goal, running]);

  return (
    <section className="console-panel" id="agent" aria-labelledby="agent-heading">
      <header className="console-header">
        <div>
          <h2 id="agent-heading">Governed Agent loop</h2>
          <p>
            An agent proposes SQL for a goal. ToxicJoin decides. The agent only ever receives a
            deterministic reason code, never authority — so a refusal is terminal unless the
            agent itself produces something safe.
          </p>
        </div>
      </header>

      <div className="console-presets" role="group" aria-label="Example goals">
        {GOAL_PRESETS.map((preset) => (
          <button
            key={preset}
            type="button"
            className={["console-preset", goal === preset ? "is-active" : ""]
              .filter(Boolean)
              .join(" ")}
            onClick={() => {
              setGoal(preset);
              setResult(null);
              setError(null);
            }}
            disabled={running}
          >
            <strong>{preset}</strong>
          </button>
        ))}
      </div>

      <form
        className="console-form"
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
      >
        <label className="console-field">
          <span>Agent goal</span>
          <input
            type="text"
            value={goal}
            maxLength={2000}
            onChange={(event) => setGoal(event.target.value)}
            placeholder="What should the agent try to find out?"
            aria-label="Agent goal"
          />
        </label>
        <div className="console-actions">
          <button type="submit" className="console-submit" disabled={!goal.trim() || running}>
            {running ? "Agent working…" : "Run agent"}
          </button>
        </div>
      </form>

      {error ? (
        <div className="console-error" role="alert">
          <strong>Agent run did not complete</strong>
          <p>{error}</p>
        </div>
      ) : null}

      {result ? (
        <div className="console-result">
          <div className="console-result-head">
            <span className={`console-verdict verdict-${result.final_decision.toLowerCase()}`}>
              {result.final_decision}
            </span>
            <div className="console-result-meta">
              <span>
                attempts <strong>{result.attempts.length}</strong>
              </span>
              <span>
                outcome{" "}
                <strong>
                  {result.succeeded ? "released after remediation" : "never released"}
                </strong>
              </span>
            </div>
          </div>

          <ol className="agent-timeline">
            {result.attempts.map((attempt) => (
              <li
                key={attempt.proposal_sha256}
                className={`agent-step step-${attempt.decision.toLowerCase()}`}
              >
                <div className="agent-step-head">
                  <span className="agent-step-index">#{attempt.iteration + 1}</span>
                  <span className={`console-verdict verdict-${attempt.decision.toLowerCase()}`}>
                    {attempt.decision}
                  </span>
                  <span className="agent-step-rows">
                    {attempt.released_row_count === null
                      ? "no rows released"
                      : `${attempt.released_row_count} rows released`}
                  </span>
                </div>
                <pre>{attempt.safe_sql ?? attempt.sql}</pre>
                <ul className="console-reasons">
                  {attempt.reason_codes.map((code) => (
                    <li key={code}>{code}</li>
                  ))}
                </ul>
                <div className="console-receipt">
                  <span>
                    receipt <code>{attempt.receipt_id}</code>
                  </span>
                </div>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </section>
  );
}
