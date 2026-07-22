import { describe, expect, it } from "vitest";

import { replayResults } from "../data/replay";
import {
  buildEvidenceNodes,
  buildRiskNarrative,
  buildSqlDiff,
  decisionStyle,
  shortHash,
} from "./presentation";

describe("judge presentation helpers", () => {
  it("maps decisions to distinct semantic tones", () => {
    expect(decisionStyle("ALLOW").tone).toBe("allow");
    expect(decisionStyle("REWRITE").tone).toBe("rewrite");
    expect(decisionStyle("BLOCK").tone).toBe("block");
  });

  it("renders an explicit compositional risk narrative", () => {
    const result = replayResults["block-sensitive-export"];
    expect(result).toBeDefined();
    expect(buildRiskNarrative(result ?? null)).toContain("stable subject key");
    expect(buildRiskNarrative(result ?? null)).toContain("quasi-identifiers");
    expect(buildRiskNarrative(result ?? null)).toContain("sensitive attribute");
  });

  it("builds governed evidence nodes from receipt columns", () => {
    const result = replayResults["rewrite-churn-regions"];
    const nodes = buildEvidenceNodes(result?.receipt ?? null);
    expect(nodes).toHaveLength(3);
    expect(nodes.map((node) => node.role)).toEqual([
      "subject",
      "quasi",
      "sensitive",
    ]);
    expect(nodes.every((node) => node.resolved)).toBe(true);
  });

  it("shows the minimum-group rewrite as an added SQL line", () => {
    const result = replayResults["rewrite-churn-regions"];
    expect(result?.safe_sql).toBeTruthy();
    const diff = buildSqlDiff(
      "SELECT region\nFROM governed\nGROUP BY region",
      "SELECT region\nFROM governed\nGROUP BY region\nHAVING COUNT(*) >= 20",
    );
    expect(diff.some((line) => line.kind === "added" && line.safe?.includes("HAVING"))).toBe(
      true,
    );
  });

  it("shortens hashes without losing their ending", () => {
    const hash = "0123456789abcdef0123456789abcdef";
    expect(shortHash(hash, 8)).toBe("01234567…cdef");
    expect(shortHash(null)).toBe("not available");
  });
});
