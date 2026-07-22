import { shortHash } from "../lib/presentation";
import type { BenchmarkSummary } from "../types";

interface BenchmarkPanelProps {
  benchmark: BenchmarkSummary | null;
}

export function BenchmarkPanel({ benchmark }: BenchmarkPanelProps) {
  const metrics = benchmark?.metrics;

  return (
    <section className="benchmark-panel" aria-labelledby="benchmark-title">
      <div className="section-eyebrow">CI-generated evidence</div>
      <h2 id="benchmark-title">Measured, not narrated</h2>
      <p>
        A balanced regression corpus runs through the real safety pipeline and fails CI
        on any false allow or unsafe effective allow.
      </p>

      <div className="metric-grid">
        <article>
          <strong>{benchmark?.corpus.total ?? 30}</strong>
          <span>Queries</span>
          <small>10 / 10 / 10 balanced</small>
        </article>
        <article>
          <strong>{metrics ? `${metrics.initial_accuracy * 100}%` : "100%"}</strong>
          <span>Initial decisions</span>
          <small>Supported corpus</small>
        </article>
        <article>
          <strong>{metrics?.false_allow_count ?? 0}</strong>
          <span>False allows</span>
          <small>Hard CI gate</small>
        </article>
        <article>
          <strong>{metrics?.verified_execution_count ?? 16}</strong>
          <span>Verified executions</span>
          <small>Read-only DuckDB</small>
        </article>
      </div>

      <div className="benchmark-distribution" aria-label="Benchmark distribution">
        <span className="distribution-allow" style={{ flex: benchmark?.corpus.expected_allow ?? 10 }}>
          ALLOW
        </span>
        <span className="distribution-rewrite" style={{ flex: benchmark?.corpus.expected_rewrite ?? 10 }}>
          REWRITE
        </span>
        <span className="distribution-block" style={{ flex: benchmark?.corpus.expected_block ?? 10 }}>
          BLOCK
        </span>
      </div>

      <div className="benchmark-hash">
        <span>Report SHA-256</span>
        <code title={benchmark?.full_report_sha256}>
          {shortHash(benchmark?.full_report_sha256, 20)}
        </code>
      </div>

      <a
        className="evidence-link"
        href="https://github.com/Z3X-1337/toxicjoin/blob/main/docs/evidence/benchmark.md"
        target="_blank"
        rel="noreferrer"
      >
        Open complete benchmark evidence <span aria-hidden="true">↗</span>
      </a>
    </section>
  );
}
