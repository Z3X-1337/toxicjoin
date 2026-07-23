import { buildSqlDiff } from "../lib/presentation";
import type { DemoScenario, PipelineResponse } from "../types";

interface SqlWorkbenchProps {
  scenario: DemoScenario | null;
  result: PipelineResponse | null;
}

export function SqlWorkbench({ scenario, result }: SqlWorkbenchProps) {
  const originalSql = scenario?.request.sql ?? "-- Select a scenario";
  const safeSql = result?.safe_sql ?? null;
  const diff = buildSqlDiff(originalSql, safeSql);
  const rewriteApplied = Boolean(safeSql);

  return (
    <section className="panel sql-panel" aria-labelledby="sql-title">
      <div className="panel-heading">
        <div>
          <div className="section-eyebrow">SQL control boundary</div>
          <h2 id="sql-title">Original request vs. executable query</h2>
        </div>
        <span className={`rewrite-state ${rewriteApplied ? "is-applied" : ""}`}>
          {rewriteApplied ? "Verified rewrite applied" : "No rewrite emitted"}
        </span>
      </div>

      <div className="sql-purpose">
        <small>Agent task purpose</small>
        <strong>{scenario?.request.task_purpose ?? "Waiting for scenario"}</strong>
      </div>

      <div className="sql-columns">
        <div className="code-window">
          <div className="code-toolbar">
            <span>agent_request.sql</span>
            <span className="code-tag">UNTRUSTED INPUT</span>
          </div>
          <pre><code>{originalSql}</code></pre>
        </div>

        <div className="code-window safe-window">
          <div className="code-toolbar">
            <span>toxicjoin_safe.sql</span>
            <span className="code-tag">{rewriteApplied ? "REPARSED + VERIFIED" : "UNCHANGED"}</span>
          </div>
          <pre><code>{safeSql ?? originalSql}</code></pre>
        </div>
      </div>

      <details className="diff-details" open={rewriteApplied}>
        <summary>Inspect structural SQL diff</summary>
        <div className="diff-lines">
          {diff.map((line, index) => (
            <div className={`diff-line is-${line.kind}`} key={`${line.kind}-${index}`}>
              <span aria-hidden="true">
                {line.kind === "added" ? "+" : line.kind === "removed" ? "−" : "·"}
              </span>
              <code>{line.safe ?? line.original}</code>
            </div>
          ))}
        </div>
      </details>
    </section>
  );
}
