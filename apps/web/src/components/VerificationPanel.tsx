import { humanizeCode } from "../lib/presentation";
import type { VerificationResult } from "../types";

interface VerificationPanelProps {
  verification: VerificationResult | null | undefined;
  blocked: boolean;
}

export function VerificationPanel({ verification, blocked }: VerificationPanelProps) {
  const checks = verification?.checks ?? [];

  return (
    <section className="panel verification-panel" aria-labelledby="verification-title">
      <div className="panel-heading compact-heading">
        <div>
          <div className="section-eyebrow">Independent verification</div>
          <h2 id="verification-title">Trust, then verify again</h2>
        </div>
        <span
          className={`verification-state ${
            verification?.passed ? "is-passed" : blocked ? "is-stopped" : ""
          }`}
        >
          {verification?.passed
            ? "All checks passed"
            : blocked
              ? "Execution intentionally skipped"
              : "Awaiting result"}
        </span>
      </div>

      {checks.length ? (
        <ol className="verification-list">
          {checks.map((check, index) => (
            <li key={check.name} className={check.passed ? "is-passed" : "is-failed"}>
              <span className="check-index">{String(index + 1).padStart(2, "0")}</span>
              <span className="check-icon" aria-hidden="true">
                {check.passed ? "✓" : "×"}
              </span>
              <div>
                <strong>{humanizeCode(check.name)}</strong>
                <p>{check.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      ) : (
        <div className="empty-proof">
          <span aria-hidden="true">⊘</span>
          <div>
            <strong>{blocked ? "Unsafe SQL never reached DuckDB" : "No checks yet"}</strong>
            <p>
              {blocked
                ? "A BLOCK decision terminates the request before database execution."
                : "Run a scenario to populate the verification chain."}
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
