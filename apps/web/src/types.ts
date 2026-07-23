export type Decision = "ALLOW" | "REWRITE" | "BLOCK";
export type ReceiptMode = "fixture" | "live" | "replay";
export type SourceMode = "api" | "replay";

export interface ColumnRef {
  dataset: string;
  field_path: string;
  alias?: string | null;
}

export interface QueryPlan {
  statement_type: string;
  source_datasets: string[];
  projected_columns: ColumnRef[];
  referenced_columns: ColumnRef[];
  join_columns: ColumnRef[];
  group_by_columns: ColumnRef[];
  aggregate_functions: string[];
  contains_wildcard: boolean;
  is_grouped: boolean;
  minimum_group_size_present?: number | null;
  minimum_group_size_subject?: ColumnRef | null;
  analysis_warnings: string[];
}

export interface PolicyDecision {
  decision: Decision;
  reason_codes: string[];
  policy_version: string;
  evidence: Record<string, unknown>;
  rewrite_required: boolean;
}

export interface VerificationCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ExecutionResult {
  query_sha256: string;
  query_plan: QueryPlan;
  columns: string[];
  rows: unknown[][];
  preview_row_count: number;
  truncated: boolean;
  elapsed_ms: number;
}

export interface VerificationResult {
  passed: boolean;
  query_plan: QueryPlan | null;
  policy_decision: PolicyDecision | null;
  checks: VerificationCheck[];
  execution: ExecutionResult | null;
  execution_error: string | null;
}

export interface ReceiptColumnEvidence {
  dataset: string;
  field_path: string;
  category: string;
  datahub_urn?: string | null;
  tags: string[];
  glossary_terms: string[];
  resolved: boolean;
}

export interface ReceiptSqlEvidence {
  original_sha256: string;
  safe_sha256?: string | null;
  sanitized_original?: string | null;
  sanitized_safe?: string | null;
}

export interface ReceiptExecutionSummary {
  query_sha256: string;
  columns: string[];
  preview_row_count: number;
  truncated: boolean;
}

export interface ReceiptWriteback {
  state: "not_attempted" | "pending" | "verified" | "failed";
  target_urns: string[];
  document_urn?: string | null;
  verified_at?: string | null;
  error_code?: string | null;
}

export interface DecisionReceipt {
  schema_version: string;
  receipt_id: string;
  created_at: string;
  mode: ReceiptMode;
  task_purpose: string;
  initial_decision: Decision;
  initial_reason_codes: string[];
  initial_evidence: Record<string, unknown>;
  final_decision?: Decision | null;
  final_reason_codes: string[];
  final_evidence: Record<string, unknown>;
  policy_version: string;
  sql: ReceiptSqlEvidence;
  columns: ReceiptColumnEvidence[];
  verification: VerificationCheck[];
  execution?: ReceiptExecutionSummary | null;
  writeback: ReceiptWriteback;
  content_sha256: string;
}

export interface PipelineRequest {
  task_purpose: string;
  sql: string;
  subject_key: ColumnRef;
  dialect: string;
}

export interface PipelineResponse {
  effective_decision: Decision;
  initial_decision: PolicyDecision;
  final_decision?: PolicyDecision | null;
  safe_sql?: string | null;
  original_plan?: QueryPlan | null;
  final_plan?: QueryPlan | null;
  verification?: VerificationResult | null;
  receipt: DecisionReceipt;
}

export interface DemoScenario {
  scenario_id: string;
  title: string;
  description: string;
  request: PipelineRequest;
  expected_initial_decision: Decision;
  expected_effective_decision: Decision;
}

export interface DemoScenarioList {
  scenarios: DemoScenario[];
}

export interface HealthResponse {
  status: "ok" | "degraded";
  version: string;
  mode: ReceiptMode;
  policy_version: string;
  database_ready: boolean;
  receipt_store_ready: boolean;
}

export interface BenchmarkSummary {
  schema_version: string;
  benchmark_version: string;
  policy_version: string;
  corpus: {
    total: number;
    expected_allow: number;
    expected_rewrite: number;
    expected_block: number;
  };
  metrics: {
    initial_accuracy: number;
    effective_accuracy: number;
    reason_accuracy: number;
    full_case_accuracy: number;
    false_allow_count: number;
    unsafe_effective_allow_count: number;
    rewrite_remediated_count: number;
    rewrite_fail_closed_count: number;
    verified_execution_count: number;
  };
  data_fingerprint: string;
  full_report_sha256: string;
  gate_failures: string[];
  scope_note: string;
}

export interface JudgeSession {
  sourceMode: SourceMode;
  health: HealthResponse;
  scenarios: DemoScenario[];
  benchmark: BenchmarkSummary;
  selectedScenarioId: string;
  result: PipelineResponse | null;
  loading: boolean;
  error: string | null;
}
