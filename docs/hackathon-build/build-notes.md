# Build Notes

## Locked decisions
- Name: ToxicJoin.
- Track: Agents That Do Real Work.
- Core differentiator: compositional sensitivity before SQL execution.
- Decision authority: deterministic policy engine.
- LLM role: explanation only.
- Primary database: DuckDB.
- Metadata source: DataHub OSS through MCP, with SDK for gaps such as lineage write-back.
- Frontend: React/Vite after vertical slice.
- Freeze target: August 8, 2026.

## Immediate milestone
Prove live DataHub metadata read and decision write-back before implementing the full UI.
