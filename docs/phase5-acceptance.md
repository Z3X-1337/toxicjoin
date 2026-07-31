# Phase 5 acceptance criteria

Phase 5 closes only when all criteria pass on one exact candidate head:

1. the branch starts from the merged Phase 4 `main` revision;
2. the Live DataHub workflow checks out and records the exact candidate head and tree;
3. Ubuntu 24.04, Python 3.11.15, uv 0.8.4, DataHub SDK 1.6.0.15, MCP server 0.6.0, and `uv.lock` are verified;
4. SDK, read-only, and writer credential channels are present and pairwise distinct without serializing their values;
5. real entity, schema, tag, glossary, and column-lineage reads pass;
6. the effective writer surface is exactly `save_document`;
7. the writer closes before a fresh read-only process independently verifies the persisted marker;
8. live Agent discovery and the live semantic policy gate pass through read-only MCP;
9. all report hashes, source-contract hashes, raw-artifact hashes, and the final `SHA256SUMS` manifest verify;
10. all normal exact-head repository workflows also pass;
11. zero unresolved review threads or change requests remain;
12. Phase 6 and all explicitly excluded control-plane/release operations remain untouched;
13. the PR remains unmerged until the owner explicitly authorizes the exact final head SHA.
