import type { DecisionReceipt } from "../types";

/**
 * The composition, made visible.
 *
 * Every other panel reports a verdict. This one shows *why* one is possible: each governed
 * column the query touched, coloured by its DataHub classification. The product's whole
 * argument is that individually acceptable fields can combine into an unsafe disclosure, and
 * that argument lands far harder when a reviewer can see a pseudonym sitting beside two
 * quasi-identifiers and a sensitive attribute than when they read the sentence.
 */

const CATEGORY_META: Record<string, { label: string; tone: string; weight: number }> = {
  DIRECT_IDENTIFIER: { label: "direct identifier", tone: "direct", weight: 4 },
  STABLE_PSEUDONYM: { label: "stable pseudonym", tone: "pseudonym", weight: 3 },
  SENSITIVE_ATTRIBUTE: { label: "sensitive", tone: "sensitive", weight: 3 },
  QUASI_IDENTIFIER: { label: "quasi-identifier", tone: "quasi", weight: 2 },
  PUBLIC_OR_LOW_RISK: { label: "public", tone: "public", weight: 0 },
  UNCLASSIFIED: { label: "unclassified", tone: "unknown", weight: 5 },
};

function meta(category: string) {
  return (
    CATEGORY_META[category] ?? { label: category.toLowerCase(), tone: "unknown", weight: 5 }
  );
}

export function GovernanceStrip({ receipt }: { receipt: DecisionReceipt | null }) {
  const columns = receipt?.columns ?? [];
  if (columns.length === 0) {
    return null;
  }

  // Riskiest first: the reader should meet the reason for the verdict immediately, not hunt
  // for it among public columns.
  const ordered = [...columns].sort((left, right) => {
    const delta = meta(right.category).weight - meta(left.category).weight;
    return delta !== 0 ? delta : left.field_path.localeCompare(right.field_path);
  });

  const protectedCount = ordered.filter((column) => meta(column.category).weight > 0).length;

  return (
    <section className="governance-strip" aria-label="Governed columns used by this query">
      <div className="governance-strip-head">
        <h3>Governed evidence</h3>
        <p>
          {ordered.length} column{ordered.length === 1 ? "" : "s"} resolved through DataHub
          {protectedCount > 0 ? ` · ${protectedCount} protected` : " · none protected"}
        </p>
      </div>

      <ul className="governance-columns">
        {ordered.map((column) => {
          const info = meta(column.category);
          return (
            <li key={`${column.dataset}.${column.field_path}`} className={`gov-chip gov-${info.tone}`}>
              <span className="gov-chip-field">
                <span className="gov-chip-dataset">{column.dataset}.</span>
                {column.field_path}
              </span>
              <span className="gov-chip-category">{info.label}</span>
              {column.resolved ? null : <span className="gov-chip-warn">unresolved</span>}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
