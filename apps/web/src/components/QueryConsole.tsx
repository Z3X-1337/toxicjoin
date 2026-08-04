import { CONSOLE_ENDPOINTS } from "../lib/console";
import { GovernanceStrip } from "./GovernanceStrip";
import { presetById } from "../data/presets";
import { useQueryConsole } from "../hooks/useQueryConsole";
import type { Decision, PipelineResponse } from "../types";

function decisionClass(decision: Decision): string {
  return `console-verdict verdict-${decision.toLowerCase()}`;
}

function reasonCodes(result: PipelineResponse): string[] {
  const final = result.final_decision?.reason_codes ?? [];
  return final.length > 0 ? final : result.initial_decision.reason_codes;
}

function ConsoleResult({ result }: { result: PipelineResponse }) {
  const execution = result.verification?.execution ?? null;
  const checks = result.verification?.checks ?? [];
  const failed = checks.filter((check) => !check.passed);

  return (
    <div className="console-result">
      <div className="console-result-head">
        <span className={decisionClass(result.effective_decision)}>
          {result.effective_decision}
        </span>
        <div className="console-result-meta">
          <span>
            initial <strong>{result.initial_decision.decision}</strong>
          </span>
          <span>
            policy <strong>{result.receipt.policy_version}</strong>
          </span>
          <span>
            mode <strong>{result.receipt.mode}</strong>
          </span>
        </div>
      </div>

      <ul className="console-reasons">
        {reasonCodes(result).map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>

      <GovernanceStrip receipt={result.receipt} />

      {result.safe_sql ? (
        <details className="console-block" open>
          <summary>Generated safe SQL (reparsed, regrounded, re-evaluated)</summary>
          <pre>{result.safe_sql}</pre>
        </details>
      ) : null}

      {checks.length > 0 ? (
        <details className="console-block" open={failed.length > 0}>
          <summary>
            Verification — {checks.length - failed.length}/{checks.length} passed
          </summary>
          <ul className="console-checks">
            {checks.map((check) => (
              <li key={check.name} className={check.passed ? "check-pass" : "check-fail"}>
                <span>{check.passed ? "PASS" : "FAIL"}</span>
                <div>
                  <strong>{check.name}</strong>
                  <p>{check.detail}</p>
                </div>
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      {execution ? (
        <details className="console-block" open>
          <summary>
            Released rows — {execution.preview_row_count}
            {execution.truncated ? " (truncated preview)" : ""}
          </summary>
          <div className="console-table-scroll">
            <table className="console-table">
              <thead>
                <tr>
                  {execution.columns.map((column) => (
                    <th key={column}>{column}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {execution.rows.map((row, rowIndex) => (
                  <tr key={rowIndex}>
                    {row.map((cell, cellIndex) => (
                      <td key={cellIndex}>{cell === null ? "NULL" : String(cell)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ) : (
        <p className="console-no-rows">
          No rows were released. ToxicJoin only returns data after an effective ALLOW that
          also passes independent verification.
        </p>
      )}

      <div className="console-receipt">
        <span>
          receipt <code>{result.receipt.receipt_id}</code>
        </span>
        <span>
          content sha256 <code>{result.receipt.content_sha256.slice(0, 16)}…</code>
        </span>
      </div>
    </div>
  );
}

export function QueryConsole() {
  const workbench = useQueryConsole();
  const activePreset = workbench.activePresetId ? presetById(workbench.activePresetId) : null;

  return (
    <section className="console-panel" id="console" aria-labelledby="console-heading">
      <header className="console-header">
        <div>
          <h2 id="console-heading">Live console</h2>
          <p>
            Every run is a real HTTP call to <code>{CONSOLE_ENDPOINTS[workbench.mode]}</code> on
            this deployment. Nothing on this panel is replayed or simulated.
          </p>
        </div>
      </header>

      <div className="console-presets" role="group" aria-label="Example queries">
        {workbench.presets.map((preset) => (
          <button
            key={preset.id}
            type="button"
            className={[
              "console-preset",
              `preset-${preset.kind}`,
              workbench.activePresetId === preset.id ? "is-active" : "",
            ]
              .filter(Boolean)
              .join(" ")}
            onClick={() => workbench.applyPreset(preset.id)}
            disabled={workbench.running}
          >
            <strong>{preset.label}</strong>
            <span>{preset.summary}</span>
          </button>
        ))}
      </div>

      {activePreset ? (
        <p className="console-expectation">
          <strong>Expected:</strong> {activePreset.expectation}
        </p>
      ) : null}

      <form
        className="console-form"
        onSubmit={(event) => {
          event.preventDefault();
          void workbench.submit();
        }}
      >
        <label className="console-field">
          <span>Task purpose</span>
          <input
            type="text"
            value={workbench.taskPurpose}
            maxLength={2000}
            onChange={(event) => workbench.setTaskPurpose(event.target.value)}
            placeholder="Why this data is needed"
            aria-label="Task purpose"
          />
        </label>

        <label className="console-field console-field-wide">
          <span>Proposed SQL</span>
          <textarea
            value={workbench.sql}
            rows={10}
            spellCheck={false}
            onChange={(event) => workbench.setSql(event.target.value)}
            placeholder="SELECT ..."
            aria-label="Proposed SQL"
          />
        </label>

        <div className="console-row">
          <label className="console-field">
            <span>Subject dataset</span>
            <input
              type="text"
              value={workbench.subjectDataset}
              onChange={(event) => workbench.setSubjectDataset(event.target.value)}
              placeholder="customers"
              aria-label="Subject dataset"
            />
          </label>
          <label className="console-field">
            <span>Subject field</span>
            <input
              type="text"
              value={workbench.subjectField}
              onChange={(event) => workbench.setSubjectField(event.target.value)}
              placeholder="customer_id"
              aria-label="Subject field"
            />
          </label>
          <fieldset className="console-mode">
            <legend>Action</legend>
            <label>
              <input
                type="radio"
                name="console-mode"
                checked={workbench.mode === "analyze"}
                onChange={() => workbench.setMode("analyze")}
                aria-label="Analyze only"
              />
              Analyze only
            </label>
            <label>
              <input
                type="radio"
                name="console-mode"
                checked={workbench.mode === "execute"}
                onChange={() => workbench.setMode("execute")}
                aria-label="Execute safe"
              />
              Execute safe
            </label>
          </fieldset>
        </div>

        <div className="console-actions">
          <button type="submit" className="console-submit" disabled={!workbench.canSubmit}>
            {workbench.running ? "Evaluating…" : "Evaluate query"}
          </button>
          <button
            type="button"
            className="console-reset"
            onClick={workbench.reset}
            disabled={workbench.running}
          >
            Reset
          </button>
        </div>
      </form>

      {workbench.error ? (
        <div className="console-error" role="alert">
          <strong>Request did not complete</strong>
          <p>{workbench.error}</p>
        </div>
      ) : null}

      {workbench.result ? <ConsoleResult result={workbench.result} /> : null}
    </section>
  );
}
