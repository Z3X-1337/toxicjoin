# ToxicJoin

> A compositional privacy firewall that blocks or safely rewrites risky SQL before AI data agents execute it.

ToxicJoin is being built for **Build with DataHub: The Agent Hackathon** in the **Agents That Do Real Work** category.

## Status
Planning and integration-spike scaffold. The first milestone is a verified DataHub MCP read/write loop.

## Core flow

```text
Agent task + SQL -> SQL AST -> DataHub context -> risk decision
-> ALLOW / REWRITE / BLOCK -> safe execution -> verification
-> receipt + DataHub write-back
```

## Project principles
- Deterministic safety decisions.
- Fail closed on uncertainty.
- No raw sensitive rows sent to an LLM.
- DataHub is the source of governed context and persistent decision memory.
- Honest replay mode for no-setup judging.

## License
Apache-2.0. See `LICENSE`.
