import { buildRiskNarrative, decisionStyle, humanizeCode } from "../lib/presentation";
import type { DemoScenario, PipelineResponse } from "../types";

interface DecisionHeroProps { scenario: DemoScenario | null; result: PipelineResponse | null; running: boolean; }

export function DecisionHero({ scenario, result, running }: DecisionHeroProps) {
  const initialDecision = result?.initial_decision.decision ?? scenario?.expected_initial_decision ?? "REWRITE";
  const effectiveDecision = result?.effective_decision ?? scenario?.expected_effective_decision ?? "ALLOW";
  const initialStyle = decisionStyle(initialDecision);
  const effectiveStyle = decisionStyle(effectiveDecision);
  const reasons = result?.initial_decision.reason_codes ?? [];
  return (
    <section className="decision-hero" aria-labelledby="decision-title">
      <div className="decision-context">
        <p className="section-eyebrow">Effective decision</p>
        <h3 id="decision-title">{scenario?.title ?? "Preparing the decision pipeline"}</h3>
        <p>{scenario?.description ?? "Connecting to the public Render API and loading scenarios."}</p>
      </div>
      <div className={`decision-display tone-${effectiveStyle.tone}`}>
        <span className="decision-caption">{running ? "Evaluating request" : "Final outcome"}</span>
        <strong>{running ? "CHECKING" : effectiveDecision}</strong>
        <p>{running ? "Resolving policy evidence…" : effectiveStyle.summary}</p>
      </div>
      <div className="decision-journey" aria-label="Decision lifecycle">
        <div className={`journey-step tone-${initialStyle.tone}`}><small>Initial</small><strong>{initialDecision}</strong></div>
        <span className="journey-arrow" aria-hidden="true">→</span>
        <div className={`journey-step tone-${effectiveStyle.tone}`}><small>Effective</small><strong>{effectiveDecision}</strong></div>
        <div className="journey-evidence"><small>Primary signal</small><strong>{buildRiskNarrative(result)}</strong></div>
      </div>
      <div className="reason-row" aria-label="Policy reasons">
        {(reasons.length ? reasons : ["WAITING_FOR_PIPELINE"]).map((reason) => <span key={reason}>{humanizeCode(reason)}</span>)}
      </div>
    </section>
  );
}
