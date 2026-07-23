import { formatValue } from "../lib/presentation";
import type { ExecutionResult } from "../types";

interface ResultTableProps {
  execution: ExecutionResult | null | undefined;
  blocked: boolean;
}

export function ResultTable({ execution, blocked }: ResultTableProps) {
  return (
    <section className="panel result-panel" aria-labelledby="result-title">
      <div className="panel-heading compact-heading">
        <div>
          <div className="section-eyebrow">Read-only execution</div>
          <h2 id="result-title">Verified output preview</h2>
        </div>
        {execution ? (
          <span className="latency-pill">{execution.elapsed_ms.toFixed(2)} ms</span>
        ) : null}
      </div>

      {execution ? (
        <>
          <div className="table-shell">
            <table>
              <thead>
                <tr>
                  {execution.columns.map((column) => (
                    <th key={column} scope="col">{column}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {execution.rows.map((row, rowIndex) => (
                  <tr key={`row-${rowIndex}`}>
                    {execution.columns.map((column, columnIndex) => (
                      <td key={`${rowIndex}-${column}`}>
                        {formatValue(row[columnIndex])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="result-footnote">
            <span>{execution.preview_row_count} rows inspected</span>
            <span>{execution.truncated ? "Preview truncated" : "Complete result inspected"}</span>
            <span>Read-only DuckDB</span>
          </div>
        </>
      ) : (
        <div className="execution-stopped">
          <span className="stop-mark" aria-hidden="true">■</span>
          <div>
            <strong>{blocked ? "No query was executed" : "Awaiting protected execution"}</strong>
            <p>
              {blocked
                ? "The policy boundary terminated the request before the database connection was used."
                : "A bounded result preview appears only after final verification passes."}
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
