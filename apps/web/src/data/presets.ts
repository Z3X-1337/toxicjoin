import type { ConsoleMode } from "../lib/console";
import type { Decision, PipelineRequest } from "../types";

/**
 * One-click console presets.
 *
 * The first three demonstrate the three deterministic outcomes. The last two are the two
 * privacy bypasses that were proven exploitable against an earlier build and are now closed;
 * they are included so a reviewer can watch the firewall reject them live rather than take
 * a changelog entry on trust.
 */

export type PresetKind = "outcome" | "attack";

export interface ConsolePreset {
  id: string;
  label: string;
  kind: PresetKind;
  summary: string;
  /** What the operator should observe, phrased as a claim they can check on screen. */
  expectation: string;
  expectedDecision: Decision;
  defaultMode: ConsoleMode;
  request: PipelineRequest;
}

const CUSTOMER_SUBJECT = {
  dataset: "customers",
  field_path: "customer_id",
  alias: "c",
};

const PRESETS = [
  {
    id: "allow-public-aggregate",
    label: "Allow — low-risk aggregate",
    kind: "outcome",
    summary: "A public category count carries no sensitive attribute and needs no threshold.",
    expectation: "ALLOW, executed read-only, with a bounded result preview.",
    expectedDecision: "ALLOW",
    defaultMode: "execute",
    request: {
      task_purpose: "Count orders by public category",
      sql: [
        "SELECT o.category, COUNT(*) AS order_count",
        "FROM orders o",
        "GROUP BY o.category",
        "ORDER BY o.category",
      ].join("\n"),
      subject_key: CUSTOMER_SUBJECT,
      dialect: "duckdb",
    },
  },
  {
    id: "rewrite-churn-regions",
    label: "Rewrite — add a subject threshold",
    kind: "outcome",
    summary:
      "A useful churn aggregate that lacks the trusted minimum distinct-subject threshold.",
    expectation:
      "REWRITE first, then a verified ALLOW after the generated SQL is reparsed and regrounded.",
    expectedDecision: "ALLOW",
    defaultMode: "execute",
    request: {
      task_purpose: "Identify regions with elevated churn risk",
      sql: [
        "SELECT",
        "  c.coarse_region,",
        "  AVG(r.churn_score) AS average_churn,",
        "  COUNT(DISTINCT c.customer_id) AS subject_count",
        "FROM customers c",
        "JOIN retention_scores r ON c.customer_id = r.customer_id",
        "GROUP BY c.coarse_region",
      ].join("\n"),
      subject_key: CUSTOMER_SUBJECT,
      dialect: "duckdb",
    },
  },
  {
    id: "block-compositional-risk",
    label: "Block — compositional re-identification",
    kind: "outcome",
    summary:
      "A stable pseudonym, two quasi-identifiers and a sensitive attribute at row granularity.",
    expectation: "BLOCK before DuckDB is called. No rows are ever produced.",
    expectedDecision: "BLOCK",
    defaultMode: "execute",
    request: {
      task_purpose: "Export customers with sensitive support cases",
      sql: [
        "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category",
        "FROM customers c",
        "JOIN support_cases s ON c.customer_id = s.customer_id",
      ].join("\n"),
      subject_key: CUSTOMER_SUBJECT,
      dialect: "duckdb",
    },
  },
  {
    id: "attack-fabricated-subject-count",
    label: "Attack — fabricated subject_count",
    kind: "attack",
    summary:
      "Aliases the literal 999 as subject_count and inverts the HAVING threshold with NOT, so the query returns exactly the cohorts below the minimum.",
    expectation:
      "BLOCK. The threshold is not a top-level AND conjunct, and subject_count carries no governed lineage.",
    expectedDecision: "BLOCK",
    defaultMode: "execute",
    request: {
      task_purpose: "Average spend by cohort",
      sql: [
        "SELECT c.age_band, c.coarse_region,",
        "       AVG(o.purchase_amount) AS avg_spend,",
        "       999 AS subject_count",
        "FROM customers c",
        "JOIN orders o ON c.customer_id = o.customer_id",
        "GROUP BY c.age_band, c.coarse_region",
        "HAVING NOT (COUNT(DISTINCT c.customer_id) >= 20)",
      ].join("\n"),
      subject_key: CUSTOMER_SUBJECT,
      dialect: "duckdb",
    },
  },
  {
    id: "attack-weak-subject-key",
    label: "Attack — caller-chosen weak subject",
    kind: "attack",
    summary:
      "Declares orders.order_id as the privacy subject. Counting orders satisfies the threshold while cohorts hold as few as four distinct customers.",
    expectation:
      "BLOCK with UNTRUSTED_SUBJECT_KEY. Only a governed identifier may witness k-anonymity.",
    expectedDecision: "BLOCK",
    defaultMode: "execute",
    request: {
      task_purpose: "Average spend by cohort",
      sql: [
        "SELECT c.age_band, c.coarse_region,",
        "       AVG(o.purchase_amount) AS avg_spend,",
        "       COUNT(DISTINCT o.order_id) AS subject_count",
        "FROM customers c",
        "JOIN orders o ON c.customer_id = o.customer_id",
        "GROUP BY c.age_band, c.coarse_region",
        "HAVING COUNT(DISTINCT o.order_id) >= 20",
      ].join("\n"),
      subject_key: { dataset: "orders", field_path: "order_id", alias: "o" },
      dialect: "duckdb",
    },
  },
] as const satisfies readonly ConsolePreset[];

// A non-empty tuple type keeps `presetById` total: the fallback element is statically known
// to exist, so an unknown id can never produce `undefined` at runtime.
export const CONSOLE_PRESETS: readonly ConsolePreset[] = PRESETS;

export const DEFAULT_PRESET_ID = "rewrite-churn-regions";

export function presetById(id: string): ConsolePreset {
  return PRESETS.find((preset) => preset.id === id) ?? PRESETS[0];
}
