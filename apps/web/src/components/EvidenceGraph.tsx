import {
  buildEvidenceNodes,
  buildRiskNarrative,
  humanizeCode,
} from "../lib/presentation";
import type { PipelineResponse } from "../types";

interface EvidenceGraphProps {
  result: PipelineResponse | null;
}

export function EvidenceGraph({ result }: EvidenceGraphProps) {
  const nodes = buildEvidenceNodes(result?.receipt ?? null);
  const hasRisk = result?.initial_decision.decision !== "ALLOW";

  return (
    <section className="panel evidence-panel" aria-labelledby="evidence-title">
      <div className="panel-heading">
        <div>
          <div className="section-eyebrow">Governed evidence graph</div>
          <h2 id="evidence-title">Sensitivity appears in the combination</h2>
        </div>
        <span className={`graph-state ${hasRisk ? "is-risk" : "is-clear"}`}>
          {hasRisk ? "Derived risk detected" : "No prohibited composition"}
        </span>
      </div>

      <div className="evidence-stage">
        <div className="evidence-nodes" role="list" aria-label="Governed columns">
          {nodes.length ? (
            nodes.map((node, index) => (
              <article
                className={`evidence-node role-${node.role}`}
                key={node.id}
                role="listitem"
                style={{ "--node-delay": `${index * 55}ms` } as React.CSSProperties}
              >
                <span className="node-dataset">{node.dataset}</span>
                <strong>{node.field}</strong>
                <small>{humanizeCode(node.category)}</small>
                <span className="node-status">
                  {node.resolved ? "Governed" : "Unresolved"}
                </span>
              </article>
            ))
          ) : (
            <div className="graph-placeholder">
              <span aria-hidden="true">◎</span>
              <p>Evidence nodes appear after the protected execution completes.</p>
            </div>
          )}
        </div>

        <div className={`derived-risk-node ${hasRisk ? "is-risk" : "is-clear"}`}>
          <span className="risk-ring" aria-hidden="true" />
          <small>{hasRisk ? "Derived sensitivity" : "Composition verdict"}</small>
          <strong>{buildRiskNarrative(result)}</strong>
          <p>
            {hasRisk
              ? "The policy evaluates the joined output, not each dataset in isolation."
              : "The supported policy found no sensitive combination requiring intervention."}
          </p>
        </div>
      </div>

      <div className="graph-legend" aria-label="Evidence graph legend">
        <span><i className="legend-subject" /> Subject key</span>
        <span><i className="legend-quasi" /> Quasi-identifier</span>
        <span><i className="legend-sensitive" /> Sensitive attribute</span>
        <span><i className="legend-low" /> Low risk</span>
      </div>
    </section>
  );
}
