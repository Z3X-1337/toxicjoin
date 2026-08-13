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
      <div className="section-eyebrow">Test cases</div>
      <h3>Choose a request</h3>
      <p className="section-copy">
        Three bounded cases cover safe access, enforceable repair, and fail-closed denial.
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
        {running ? "Evaluating…" : "Run selected case"}
      </button>

      <div className="rail-note">
        <strong>Authority stays with policy</strong>
        <span>The agent can revise its request. It cannot override a decision.</span>
      </div>
    </aside>
  );
}
