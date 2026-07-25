from __future__ import annotations

import p5_exact_release_candidate as harness


# Stateful disclosure scope is deliberately subject-bound. The safe aggregate reads only
# the orders dataset, so the governed subject namespace must come from that same source.
# This matches the permanent P2 regression contract in
# tests/security/test_cumulative_disclosure_gate.py (_SUBJECT = orders.customer_id).
harness.SAFE_AGGREGATE["subject_key"] = {
    "dataset": "orders",
    "field_path": "customer_id",
    "alias": "o",
}


if __name__ == "__main__":
    harness.main()
