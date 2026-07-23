import type {
  ColumnRef,
  Decision,
  DecisionReceipt,
  PipelineResponse,
  ReceiptColumnEvidence,
} from "../types";

export interface DecisionStyle {
  label: string;
  summary: string;
  tone: "allow" | "rewrite" | "block";
}

export interface EvidenceNode {
  id: string;
  dataset: string;
  field: string;
  category: string;
  role: "subject" | "quasi" | "sensitive" | "low-risk" | "unknown";
  tags: string[];
  resolved: boolean;
}

export interface SqlDiffLine {
  kind: "same" | "added" | "removed";
  original?: string;
  safe?: string;
}

const CATEGORY_ROLE: Record<string, EvidenceNode["role"]> = {
  STABLE_PSEUDONYM: "subject",
  DIRECT_IDENTIFIER: "subject",
  QUASI_IDENTIFIER: "quasi",
  SENSITIVE_ATTRIBUTE: "sensitive",
  PUBLIC_OR_LOW_RISK: "low-risk",
  UNCLASSIFIED: "unknown",
};

export function decisionStyle(decision: Decision): DecisionStyle {
  switch (decision) {
    case "ALLOW":
      return {
        label: "Allowed",
        summary: "The final query satisfied the deterministic safety policy.",
        tone: "allow",
      };
    case "REWRITE":
      return {
        label: "Rewrite required",
        summary: "The request can proceed only after a constrained, verified rewrite.",
        tone: "rewrite",
      };
    case "BLOCK":
      return {
        label: "Blocked",
        summary: "The request stopped before the database executor was called.",
        tone: "block",
      };
  }
}

export function humanizeCode(value: string): string {
  return value
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function shortHash(value: string | null | undefined, length = 12): string {
  if (!value) {
    return "not available";
  }
  return `${value.slice(0, length)}…${value.slice(-4)}`;
}

export function columnKey(column: ColumnRef): string {
  return `${column.dataset}.${column.field_path}`;
}

export function buildEvidenceNodes(
  receipt: DecisionReceipt | null,
): EvidenceNode[] {
  if (!receipt) {
    return [];
  }
  return receipt.columns.map((column) => ({
    id: `${column.dataset}.${column.field_path}`,
    dataset: column.dataset,
    field: column.field_path,
    category: column.category,
    role: CATEGORY_ROLE[column.category] ?? "unknown",
    tags: column.tags,
    resolved: column.resolved,
  }));
}

export function buildRiskNarrative(result: PipelineResponse | null): string {
  if (!result) {
    return "Run a scenario to generate a governed evidence path.";
  }
  const categories = new Set(result.receipt.columns.map((column) => column.category));
  if (result.initial_decision.decision === "BLOCK") {
    return [
      categories.has("STABLE_PSEUDONYM") ? "stable subject key" : "identity signal",
      categories.has("QUASI_IDENTIFIER") ? "quasi-identifiers" : "linkable context",
      categories.has("SENSITIVE_ATTRIBUTE") ? "sensitive attribute" : "governed data",
    ].join(" + ");
  }
  if (result.initial_decision.decision === "REWRITE") {
    const required = result.initial_decision.evidence.required_minimum_group_size;
    return `Sensitive grouped output required a minimum distinct-subject threshold${
      typeof required === "number" ? ` of ${required}` : ""
    }.`;
  }
  return "No prohibited sensitive composition was detected in the supported policy profile.";
}

export function buildSqlDiff(originalSql: string, safeSql?: string | null): SqlDiffLine[] {
  const original = normalizeSqlLines(originalSql);
  if (!safeSql) {
    return original.map((line) => ({ kind: "same", original: line, safe: line }));
  }
  const safe = normalizeSqlLines(safeSql);
  const originalSet = new Set(original);
  const safeSet = new Set(safe);
  const rows: SqlDiffLine[] = [];

  for (const line of original) {
    if (!safeSet.has(line)) {
      rows.push({ kind: "removed", original: line });
    } else {
      rows.push({ kind: "same", original: line, safe: line });
    }
  }
  for (const line of safe) {
    if (!originalSet.has(line)) {
      rows.push({ kind: "added", safe: line });
    }
  }
  return rows;
}

export function categoryLabel(column: ReceiptColumnEvidence): string {
  return humanizeCode(column.category);
}

export function formatValue(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? value.toLocaleString("en-US")
      : value.toLocaleString("en-US", { maximumFractionDigits: 5 });
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

function normalizeSqlLines(sql: string): string[] {
  return sql
    .trim()
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);
}
