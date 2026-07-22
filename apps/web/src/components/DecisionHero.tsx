import {
  buildRiskNarrative,
  decisionStyle,
  humanizeCode,
} from "../lib/presentation";
import type { DemoScenario, PipelineResponse } from "../types";

interface DecisionHeroProps {
  scenario: DemoScenario | null;
  result: PipelineResponse | null;
  running: boolean;
}

export function DecisionHero({ scenario, result, running }: DecisionHeroProps) {
  const initialDecision = result?.initial_decision.decision ??
    scenario?.expected_initial_decision ??
    "REWRITE";
  const effectiveDecision = result?.effective_decision ??
    scenario?.expected_effective_decision ??
    "ALLOW";
  const initialStyle = decisionStyle(initialDecision);
  const effectiveStyle = decisionStyle(effectiveDecision);
  const reasons = result?.initial_decision.reason_codes ?? [];

  return (
    <section className="decision-hero" aria-labelledby="decision-title">
      <div className="hero-copy">
        <div className="section-eyebrow">Pre-execution control plane</div>
        <h1 id="decision-title">
          Stop sensitive data from <em>emerging</em> at query time.
        </h1>
        <p>
          ToxicJoin inspects the agent&apos;s SQL, grounds every field in governed
          context, and acts before unsafe composition reaches the warehouse.
        </p>
      </div>

      <div className={`decision-display tone-${effectiveStyle.tone}`}>
        <div className="decision-orbit" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <span className="decision-caption">
          {running ? "Evaluating" : "Effective outcome"}
        </span>
        <strong>{running ? "ANALYZING" : effectiveDecision}</strong>
        <p>{running ? "Resolving governed evidence…" : effectiveStyle.summary}</p>
      </div>

      <div className="decision-journey" aria-label="Decision lifecycle">
        <div className={`journey-step tone-${initialStyle.tone}`}>
          <span>01</span>
          <div>
            <small>Initial policy</small>
            <strong>{initialDecision}</strong>
          </div>
        </div>
        <div className="journey-arrow" aria-hidden="true">
          →
        </div>
        <div className={`journey-step tone-${effectiveStyle.tone}`}>
          <span>02</span>
          <div>
            <small>After remediation</small>
            <strong>{effectiveDecision}</strong>
          </div>
        </div>
        <div className="journey-evidence">
          <small>Risk signal</small>
          <strong>{buildRiskNarrative(result)}</strong>
        </div>
      </div>

      <div className="reason-row" aria-label="Policy reasons">
        {(reasons.length ? reasons : ["WAITING_FOR_PIPELINE"]).map((reason) => (
          <span key={reason}>{humanizeCode(reason)}</span>
        ))}
      </div>
    </section>
  );
}
