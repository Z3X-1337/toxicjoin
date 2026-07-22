import { decisionStyle } from "../lib/presentation";
import type { DemoScenario } from "../types";

interface ScenarioRailProps {
  scenarios: DemoScenario[];
  selectedScenarioId: string;
  running: boolean;
  onSelect: (scenarioId: string) => void;
  onRun: () => void;
}

export function ScenarioRail({
  scenarios,
  selectedScenarioId,
  running,
  onSelect,
  onRun,
}: ScenarioRailProps) {
  const selected = scenarios.find(
    (scenario) => scenario.scenario_id === selectedScenarioId,
  );

  return (
    <aside className="scenario-rail" aria-label="Judge scenarios">
      <div className="section-eyebrow">Decision lab</div>
      <h2>Choose the agent request</h2>
      <p className="section-copy">
        Three deterministic paths prove that ToxicJoin blocks risk, remediates safe
        work, and avoids unnecessary denial.
      </p>

      <nav className="scenario-list" aria-label="Available scenarios">
        {scenarios.map((scenario, index) => {
          const selectedState = scenario.scenario_id === selectedScenarioId;
          const expected = decisionStyle(scenario.expected_initial_decision);
          return (
            <button
              className={`scenario-button ${selectedState ? "is-selected" : ""}`}
              key={scenario.scenario_id}
              type="button"
              aria-pressed={selectedState}
              onClick={() => onSelect(scenario.scenario_id)}
            >
              <span className="scenario-index">0{index + 1}</span>
              <span className="scenario-content">
                <strong>{scenario.title}</strong>
                <small>{scenario.description}</small>
              </span>
              <span className={`decision-pip tone-${expected.tone}`}>
                {scenario.expected_initial_decision}
              </span>
            </button>
          );
        })}
      </nav>

      <button
        className="run-button"
        type="button"
        disabled={!selected || running}
        onClick={onRun}
      >
        <span className="run-icon" aria-hidden="true">
          {running ? "⋯" : "▶"}
        </span>
        {running ? "Evaluating protected execution" : "Run protected execution"}
      </button>

      <div className="rail-note">
        <strong>Deterministic authority</strong>
        <span>The policy engine decides. An LLM cannot override the result.</span>
      </div>
    </aside>
  );
}
