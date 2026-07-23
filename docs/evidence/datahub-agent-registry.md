# ToxicJoin DataHub Agent Registry Evidence

## Result

ToxicJoin's reusable **Compositional Risk Review** skill was registered and independently read back from a real DataHub OSS development quickstart on **July 23, 2026**.

- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/30010740896
- Tested branch commit: `ef6167ff727d88caf6bc41c791fbd7933ae23920`
- Evidence Artifact: `toxicjoin-live-datahub-agent-registry`
- Artifact ID: `8565008402`
- Artifact digest: `sha256:d37677d21ec5422b515f633afdd8f7e339b7e370d99acdf1c9cb60f9674b60df`

Committed sanitized reports:

- [`datahub-agent-registry.json`](datahub-agent-registry.json)
- [`datahub-agent-registry-verified.json`](datahub-agent-registry-verified.json)

## What was registered

The git-backed skill definition is maintained at:

```text
skills/compositional-risk-review/SKILL.md
```

DataHub was given a first-class graph with:

- **5 API entities** representing the official DataHub MCP tools ToxicJoin relies on;
- **1 Agent Skill** linked back to the public git repository and exact `SKILL.md` path;
- **1 AI Agent** adopting that skill;
- the AI Agent linked to all five tool APIs;
- the AI Agent consuming all **5** governed ToxicJoin datasets through dataset lineage.

### Registered MCP tool APIs

```text
urn:li:api:toxicjoin-datahub-mcp-get-entities
urn:li:api:toxicjoin-datahub-mcp-get-lineage
urn:li:api:toxicjoin-datahub-mcp-grep-documents
urn:li:api:toxicjoin-datahub-mcp-list-schema-fields
urn:li:api:toxicjoin-datahub-mcp-save-document
```

### Registered skill

```text
urn:li:agentSkill:toxicjoin-compositional-risk-review
```

### Registered agent

```text
urn:li:aiAgent:toxicjoin-privacy-firewall-agent
```

## Independent read-back

The registration process and verification process use separate graph clients.

The verifier read DataHub's persisted native aspects and required all of the following to match the registration report:

1. `agentSkillInfo` exists;
2. the skill source repository is `https://github.com/Z3X-1337/toxicjoin`;
3. the skill source path is `skills/compositional-risk-review/SKILL.md`;
4. the skill requires exactly the five registered tool API URNs;
5. `aiAgentInfo` exists;
6. `aiAgentDependencies` links the AI Agent to the one skill and five tools;
7. `upstreamLineage` links the AI Agent to all five governed datasets;
8. every tool URN has persisted `apiProperties`.

The resulting verification report contains:

- `tool_count: 5`;
- `required_tool_count: 5`;
- `dependency_tool_count: 5`;
- `dependency_skill_count: 1`;
- `consumed_dataset_count: 5`.

## Reproducible evidence hashes

Registration report:

```text
37b2fb79f246ba83c472674e5b08b27027af905f241757b324e71dc1a6e6992d
```

Independent read-back report:

```text
cde7e273dd740910dd37e9e0ffd8615fb8b051070db1adf8257e7070d8f0ec93
```

Both hashes were manually recalculated from the persisted JSON with `report_sha256` removed and matched exactly.

## Version and stability boundary

This evidence intentionally does **not** replace ToxicJoin's stable DataHub SDK/MCP proof.

The core live integration remains proven separately with:

- `acryl-datahub==1.6.0.15`;
- the normal released DataHub OSS quickstart;
- DataHub MCP Server `0.6.0`.

Agent Registry support was not present in the `1.6.0.15` Python wheel. Published wheel inspection showed the Agent Registry helper modules first appearing in the `1.6.0.16` release-candidate series. The Agent Registry evidence therefore used:

- `acryl-datahub==1.6.0.16rc3` in an isolated optional dependency;
- `datahub docker quickstart --version quickstart`, which DataHub documents as the coordinated development images from `master`.

The development quickstart ran the coordinated `quickstart` images including:

```text
acryldata/datahub-actions:quickstart-slim
acryldata/datahub-frontend-react:quickstart
acryldata/datahub-gms:quickstart
```

This Agent Registry proof must be described as a **preview/development-channel DataHub capability**, not as a stable production dependency. ToxicJoin's enforcement path does not depend on it.

## Open-source contribution scope

The public repository includes a reusable git-backed Agent Skill:

```text
skills/compositional-risk-review/SKILL.md
```

It documents a DataHub-aware procedure for grounding agent-generated SQL, inspecting lineage, applying compositional-risk review, preserving deterministic enforcement boundaries, and independently verifying DataHub Decision write-back.

The skill is Apache-2.0 with the rest of ToxicJoin. It is an open-source DataHub Agent Skill maintained in the project repository. No claim is made that this skill has been merged into the upstream DataHub repository.

## Safety and sanitization review

The retained reports and successful Artifact contain no:

- DataHub token value;
- password;
- local DataHub endpoint;
- OpenAI or AWS secret;
- raw warehouse row;
- receipt result row.

The Agent Registry is metadata describing the reusable capability and dependencies. The deterministic ToxicJoin policy engine remains the enforcement authority for `BLOCK`, `REWRITE`, and `ALLOW`.
