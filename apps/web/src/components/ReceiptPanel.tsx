import { humanizeCode, shortHash } from "../lib/presentation";
import type { DecisionReceipt, SourceMode } from "../types";

interface ReceiptPanelProps {
  receipt: DecisionReceipt | null | undefined;
  sourceMode: SourceMode;
}

export function ReceiptPanel({ receipt, sourceMode }: ReceiptPanelProps) {
  return (
    <section className="panel receipt-panel" aria-labelledby="receipt-title">
      <div className="panel-heading compact-heading">
        <div>
          <div className="section-eyebrow">Immutable execution receipt</div>
          <h2 id="receipt-title">Evidence that survives the demo</h2>
        </div>
        <span className={`writeback-state state-${receipt?.writeback.state ?? "pending"}`}>
          {sourceMode === "replay"
            ? "Replay — no live write claimed"
            : humanizeCode(receipt?.writeback.state ?? "pending")}
        </span>
      </div>

      {receipt ? (
        <div className="receipt-content">
          <dl className="receipt-grid">
            <div>
              <dt>Receipt ID</dt>
              <dd>{receipt.receipt_id}</dd>
            </div>
            <div>
              <dt>Policy version</dt>
              <dd>{receipt.policy_version}</dd>
            </div>
            <div>
              <dt>Initial → final</dt>
              <dd>
                {receipt.initial_decision} → {receipt.final_decision ?? receipt.initial_decision}
              </dd>
            </div>
            <div>
              <dt>Governed columns</dt>
              <dd>{receipt.columns.length}</dd>
            </div>
            <div>
              <dt>Original SQL hash</dt>
              <dd title={receipt.sql.original_sha256}>{shortHash(receipt.sql.original_sha256)}</dd>
            </div>
            <div>
              <dt>Safe SQL hash</dt>
              <dd title={receipt.sql.safe_sha256 ?? undefined}>{shortHash(receipt.sql.safe_sha256)}</dd>
            </div>
          </dl>

          <div className="receipt-integrity">
            <div className="integrity-mark" aria-hidden="true">✓</div>
            <div>
              <small>Content integrity</small>
              <strong title={receipt.content_sha256}>{shortHash(receipt.content_sha256, 18)}</strong>
              <p>Recomputed and checked on every receipt read.</p>
            </div>
          </div>

          <div className="receipt-privacy">
            <span aria-hidden="true">◇</span>
            <p>
              Persisted receipt contains policy evidence and execution metadata,
              <strong> never raw result rows.</strong>
            </p>
          </div>
        </div>
      ) : (
        <div className="empty-proof">
          <span aria-hidden="true">#</span>
          <div>
            <strong>Receipt pending</strong>
            <p>Every decision path produces a content-hashed audit record.</p>
          </div>
        </div>
      )}
    </section>
  );
}
