# Real DataHub OSS: read, act, write, read back

The live integration gate runs against a real ephemeral DataHub OSS quickstart. It is separate from the hosted deterministic Replay.

The official DataHub SDK seeds a small synthetic governance graph. ToxicJoin then launches the pinned official MCP server, discovers its tools and schemas, reads governed entities and lineage, writes a DataHub `Decision`, closes that MCP process, starts a fresh process, and independently reads the persisted document back.

The retained evidence proves:

- 5 datasets;
- 19 governed schema fields;
- 9 controlled tags;
- 7 glossary terms;
- 4 column-lineage writes;
- a persisted Decision written through MCP;
- successful verification from a new MCP process.

See [`output.json`](output.json) for the compact sample and [`../../docs/evidence/datahub-live.md`](../../docs/evidence/datahub-live.md) for hashes, run provenance, sanitization review, and limitations.
