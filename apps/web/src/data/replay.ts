import type {
  BenchmarkSummary,
  DecisionReceipt,
  DemoScenario,
  HealthResponse,
  PipelineResponse,
  PolicyDecision,
  QueryPlan,
  VerificationCheck,
} from "../types";

const SUBJECT = {
  dataset: "customers",
  field_path: "customer_id",
  alias: "c",
} as const;

const REWRITE_SQL = `SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
ORDER BY c.coarse_region`;

const SAFE_SQL = `${REWRITE_SQL}
HAVING COUNT(DISTINCT c.customer_id) >= 20`;

const BLOCK_SQL = `SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
FROM customers c
JOIN support_cases s ON c.customer_id = s.customer_id`;

const ALLOW_SQL = `SELECT o.category, COUNT(*) AS order_count
FROM orders o
GROUP BY o.category
ORDER BY o.category`;

export const replayHealth: HealthResponse = {
  status: "ok",
  version: "0.1.0",
  mode: "replay",
  policy_version: "0.1.0",
  database_ready: true,
  receipt_store_ready: true,
};

export const replayBenchmark: BenchmarkSummary = {
  schema_version: "1.0",
  benchmark_version: "1.0",
  policy_version: "0.1.0",
  corpus: {
    total: 30,
    expected_allow: 10,
    expected_rewrite: 10,
    expected_block: 10,
  },
  metrics: {
    initial_accuracy: 1,
    effective_accuracy: 1,
    reason_accuracy: 1,
    full_case_accuracy: 1,
    false_allow_count: 0,
    unsafe_effective_allow_count: 0,
    rewrite_remediated_count: 6,
    rewrite_fail_closed_count: 4,
    verified_execution_count: 16,
  },
  data_fingerprint:
    "bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16",
  full_report_sha256:
    "4a1b7630012ffd54eba698b6bf1fd66a9dc3b6167d2513ef1c4c5519a8483987",
  gate_failures: [],
  scope_note:
    "Deterministic regression corpus for the declared ToxicJoin SQL and policy profile; not a claim of universal privacy detection.",
};

export const replayScenarios: DemoScenario[] = [
  {
    scenario_id: "rewrite-churn-regions",
    title: "Rewrite a sensitive churn analysis",
    description:
      "A useful aggregate lacks a trusted minimum-subject threshold. ToxicJoin rewrites, reparses, executes, and verifies the safe query.",
    request: {
      task_purpose: "Identify regions with elevated churn risk",
      sql: REWRITE_SQL,
      subject_key: SUBJECT,
      dialect: "duckdb",
    },
    expected_initial_decision: "REWRITE",
    expected_effective_decision: "ALLOW",
  },
  {
    scenario_id: "block-sensitive-export",
    title: "Block compositional re-identification",
    description:
      "A stable pseudonym, precise location, age band, and sensitive support category form an unsafe individual profile.",
    request: {
      task_purpose: "Export customers with sensitive support cases",
      sql: BLOCK_SQL,
      subject_key: SUBJECT,
      dialect: "duckdb",
    },
    expected_initial_decision: "BLOCK",
    expected_effective_decision: "BLOCK",
  },
  {
    scenario_id: "allow-public-order-counts",
    title: "Allow a low-risk aggregate",
    description:
      "A public category count has no sensitive composition and executes without a rewrite.",
    request: {
      task_purpose: "Count orders by public category",
      sql: ALLOW_SQL,
      subject_key: {
        dataset: "orders",
        field_path: "customer_id",
        alias: "o",
      },
      dialect: "duckdb",
    },
    expected_initial_decision: "ALLOW",
    expected_effective_decision: "ALLOW",
  },
];

const rewritePlan: QueryPlan = {
  statement_type: "SELECT",
  source_datasets: ["customers", "retention_scores"],
  projected_columns: [
    { dataset: "customers", field_path: "coarse_region", alias: "c" },
    { dataset: "retention_scores", field_path: "churn_score", alias: "r" },
    SUBJECT,
  ],
  referenced_columns: [
    SUBJECT,
    { dataset: "customers", field_path: "coarse_region", alias: "c" },
    { dataset: "retention_scores", field_path: "customer_id", alias: "r" },
    { dataset: "retention_scores", field_path: "churn_score", alias: "r" },
  ],
  join_columns: [
    SUBJECT,
    { dataset: "retention_scores", field_path: "customer_id", alias: "r" },
  ],
  group_by_columns: [
    { dataset: "customers", field_path: "coarse_region", alias: "c" },
  ],
  aggregate_functions: ["AVG", "COUNT"],
  contains_wildcard: false,
  is_grouped: true,
  minimum_group_size_present: null,
  minimum_group_size_subject: null,
  analysis_warnings: [],
};

const safePlan: QueryPlan = {
  ...rewritePlan,
  minimum_group_size_present: 20,
  minimum_group_size_subject: SUBJECT,
};

const checks: VerificationCheck[] = [
  {
    name: "policy_allow",
    passed: true,
    detail: "Final deterministic decision is ALLOW.",
  },
  {
    name: "trusted_subject_threshold",
    passed: true,
    detail: "COUNT(DISTINCT customers.customer_id) >= 20.",
  },
  {
    name: "no_raw_forbidden_output",
    passed: true,
    detail: "No forbidden field is projected as a raw output column.",
  },
  {
    name: "complete_result_set",
    passed: true,
    detail: "All result groups were inspected.",
  },
  {
    name: "observed_group_sizes",
    passed: true,
    detail: "Minimum observed group size is 40.",
  },
];

function policy(
  decision: PolicyDecision["decision"],
  reason: string,
  evidence: Record<string, unknown>,
  rewriteRequired = false,
): PolicyDecision {
  return {
    decision,
    reason_codes: [reason],
    policy_version: "0.1.0",
    evidence,
    rewrite_required: rewriteRequired,
  };
}

function receipt(
  id: string,
  initial: PolicyDecision,
  final: PolicyDecision | null,
  columns: DecisionReceipt["columns"],
  options: {
    safeSql?: string;
    verification?: VerificationCheck[];
    execution?: DecisionReceipt["execution"];
  } = {},
): DecisionReceipt {
  return {
    schema_version: "1.0",
    receipt_id: id,
    created_at: "2026-07-22T22:00:00+00:00",
    mode: "replay",
    task_purpose: "Deterministic judge replay",
    initial_decision: initial.decision,
    initial_reason_codes: initial.reason_codes,
    initial_evidence: initial.evidence,
    final_decision: final?.decision ?? null,
    final_reason_codes: final?.reason_codes ?? [],
    final_evidence: final?.evidence ?? {},
    policy_version: "0.1.0",
    sql: {
      original_sha256:
        "7c8d53a9da721fbfd3dd46bbf6ad455098e8c6aab54bfb163aa27a0c79db9ac4",
      safe_sha256: options.safeSql
        ? "8a61c84b604962a8a8870462dc115571414741c5ab4f20c7aef779a9ad647788"
        : null,
      sanitized_original: "SELECT … FROM governed_assets",
      sanitized_safe: options.safeSql ? "SELECT … HAVING COUNT(DISTINCT ?) >= ?" : null,
    },
    columns,
    verification: options.verification ?? [],
    execution: options.execution ?? null,
    writeback: {
      state: "not_attempted",
      target_urns: [],
      document_urn: null,
      verified_at: null,
      error_code: null,
    },
    content_sha256:
      "61f4a06639ac4277013b74bbba8cbdf95b8aa4064e6b20a1329ee88ea17a2cc1",
  };
}

const rewriteInitial = policy(
  "REWRITE",
  "SMALL_GROUP_RISK",
  {
    required_minimum_group_size: 20,
    detected_minimum_group_size: null,
    threshold_subject_matches: false,
  },
  true,
);
const rewriteFinal = policy("ALLOW", "NO_COMPOSITIONAL_RISK", {
  trusted_minimum_group_size: 20,
  trusted_threshold_subject: "customers.customer_id",
});

const commonRewriteColumns: DecisionReceipt["columns"] = [
  {
    dataset: "customers",
    field_path: "customer_id",
    category: "STABLE_PSEUDONYM",
    datahub_urn:
      "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)",
    tags: ["toxicjoin:stable-pseudonym"],
    glossary_terms: ["urn:li:glossaryTerm:StableCustomerIdentifier"],
    resolved: true,
  },
  {
    dataset: "customers",
    field_path: "coarse_region",
    category: "QUASI_IDENTIFIER",
    datahub_urn:
      "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)",
    tags: ["toxicjoin:coarse-location"],
    glossary_terms: ["urn:li:glossaryTerm:CoarseRegion"],
    resolved: true,
  },
  {
    dataset: "retention_scores",
    field_path: "churn_score",
    category: "SENSITIVE_ATTRIBUTE",
    datahub_urn:
      "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.retention_scores,PROD)",
    tags: ["toxicjoin:model-output"],
    glossary_terms: ["urn:li:glossaryTerm:ChurnScore"],
    resolved: true,
  },
];

const rewriteResult: PipelineResponse = {
  effective_decision: "ALLOW",
  initial_decision: rewriteInitial,
  final_decision: rewriteFinal,
  safe_sql: SAFE_SQL,
  original_plan: rewritePlan,
  final_plan: safePlan,
  verification: {
    passed: true,
    query_plan: safePlan,
    policy_decision: rewriteFinal,
    checks,
    execution: {
      query_sha256:
        "8a61c84b604962a8a8870462dc115571414741c5ab4f20c7aef779a9ad647788",
      query_plan: safePlan,
      columns: ["coarse_region", "average_churn", "subject_count"],
      rows: [
        ["central", 0.62175, 40],
        ["north", 0.61375, 40],
        ["south", 0.60625, 40],
      ],
      preview_row_count: 3,
      truncated: false,
      elapsed_ms: 4.28,
    },
    execution_error: null,
  },
  receipt: receipt(
    "tj_0123456789abcdef",
    rewriteInitial,
    rewriteFinal,
    commonRewriteColumns,
    {
      safeSql: SAFE_SQL,
      verification: checks,
      execution: {
        query_sha256:
          "8a61c84b604962a8a8870462dc115571414741c5ab4f20c7aef779a9ad647788",
        columns: ["coarse_region", "average_churn", "subject_count"],
        preview_row_count: 3,
        truncated: false,
      },
    },
  ),
};

const blockedDecision = policy(
  "BLOCK",
  "COMPOSITIONAL_REIDENTIFICATION_RISK",
  {
    projected_categories: [
      "STABLE_PSEUDONYM",
      "QUASI_IDENTIFIER",
      "QUASI_IDENTIFIER",
      "SENSITIVE_ATTRIBUTE",
    ],
    quasi_identifier_count: 2,
  },
);

const blockedResult: PipelineResponse = {
  effective_decision: "BLOCK",
  initial_decision: blockedDecision,
  final_decision: null,
  safe_sql: null,
  original_plan: {
    ...rewritePlan,
    source_datasets: ["customers", "support_cases"],
    is_grouped: false,
    group_by_columns: [],
    aggregate_functions: [],
  },
  final_plan: null,
  verification: null,
  receipt: receipt("tj_1111111111111111", blockedDecision, null, [
    {
      dataset: "customers",
      field_path: "customer_id",
      category: "STABLE_PSEUDONYM",
      tags: ["toxicjoin:stable-pseudonym"],
      glossary_terms: [],
      resolved: true,
    },
    {
      dataset: "customers",
      field_path: "age_band",
      category: "QUASI_IDENTIFIER",
      tags: ["toxicjoin:quasi-identifier"],
      glossary_terms: [],
      resolved: true,
    },
    {
      dataset: "customers",
      field_path: "precise_area",
      category: "QUASI_IDENTIFIER",
      tags: ["toxicjoin:precise-location"],
      glossary_terms: [],
      resolved: true,
    },
    {
      dataset: "support_cases",
      field_path: "case_category",
      category: "SENSITIVE_ATTRIBUTE",
      tags: ["toxicjoin:sensitive-support"],
      glossary_terms: [],
      resolved: true,
    },
  ]),
};

const allowDecision = policy("ALLOW", "NO_COMPOSITIONAL_RISK", {
  projected_categories: ["PUBLIC_OR_LOW_RISK"],
});

const allowResult: PipelineResponse = {
  effective_decision: "ALLOW",
  initial_decision: allowDecision,
  final_decision: null,
  safe_sql: null,
  original_plan: {
    ...rewritePlan,
    source_datasets: ["orders"],
    is_grouped: true,
    projected_columns: [
      { dataset: "orders", field_path: "category", alias: "o" },
    ],
    referenced_columns: [
      { dataset: "orders", field_path: "category", alias: "o" },
    ],
    join_columns: [],
    group_by_columns: [
      { dataset: "orders", field_path: "category", alias: "o" },
    ],
    aggregate_functions: ["COUNT"],
  },
  final_plan: null,
  verification: {
    passed: true,
    query_plan: null,
    policy_decision: allowDecision,
    checks: [
      {
        name: "policy_allow",
        passed: true,
        detail: "Final deterministic decision is ALLOW.",
      },
      {
        name: "bounded_preview",
        passed: true,
        detail: "Returned four preview rows without truncation.",
      },
    ],
    execution: {
      query_sha256:
        "d72f37335b702d121b24a510ca6c58ae954ee761d00875b0f67b3c12508b5add",
      query_plan: rewritePlan,
      columns: ["category", "order_count"],
      rows: [
        ["books", 30],
        ["electronics", 30],
        ["groceries", 30],
        ["home", 30],
      ],
      preview_row_count: 4,
      truncated: false,
      elapsed_ms: 2.11,
    },
    execution_error: null,
  },
  receipt: receipt("tj_2222222222222222", allowDecision, null, [
    {
      dataset: "orders",
      field_path: "category",
      category: "PUBLIC_OR_LOW_RISK",
      tags: [],
      glossary_terms: [],
      resolved: true,
    },
  ], {
    verification: [
      {
        name: "policy_allow",
        passed: true,
        detail: "Final deterministic decision is ALLOW.",
      },
    ],
    execution: {
      query_sha256:
        "d72f37335b702d121b24a510ca6c58ae954ee761d00875b0f67b3c12508b5add",
      columns: ["category", "order_count"],
      preview_row_count: 4,
      truncated: false,
    },
  }),
};

export const replayResults: Record<string, PipelineResponse> = {
  "rewrite-churn-regions": rewriteResult,
  "block-sensitive-export": blockedResult,
  "allow-public-order-counts": allowResult,
};
