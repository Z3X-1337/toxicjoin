from __future__ import annotations

from toxicjoin.agent import AgentPlanner, TrustedPlannerAdapter


def test_legacy_agent_planner_name_is_only_the_trusted_adapter_alias() -> None:
    assert AgentPlanner is TrustedPlannerAdapter
    assert "trusted in-process" in (TrustedPlannerAdapter.__doc__ or "").lower()
