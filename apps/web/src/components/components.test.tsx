import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { replayBenchmark, replayResults, replayScenarios } from "../data/replay";
import { BenchmarkPanel } from "./BenchmarkPanel";
import { DecisionHero } from "./DecisionHero";
import { ReceiptPanel } from "./ReceiptPanel";
import { VerificationPanel } from "./VerificationPanel";

function render(element: ReactNode): string {
  return renderToStaticMarkup(element);
}

describe("judge-facing components", () => {
  it("renders the rewrite to allow lifecycle", () => {
    const scenario = replayScenarios[0];
    const result = replayResults["rewrite-churn-regions"];
    expect(scenario).toBeDefined();
    expect(result).toBeDefined();

    const html = render(
      <DecisionHero scenario={scenario ?? null} result={result ?? null} running={false} />,
    );
    expect(html).toContain("REWRITE");
    expect(html).toContain("ALLOW");
    expect(html).toContain("Small Group Risk");
  });

  it("renders all independent verification checks", () => {
    const verification = replayResults["rewrite-churn-regions"]?.verification;
    const html = render(
      <VerificationPanel verification={verification} blocked={false} />,
    );
    expect(html).toContain("All checks passed");
    expect(html).toContain("Observed Group Sizes");
    expect(html).toContain("Minimum observed group size is 40");
  });

  it("labels replay receipts without claiming a live write", () => {
    const receipt = replayResults["rewrite-churn-regions"]?.receipt;
    const html = render(<ReceiptPanel receipt={receipt} sourceMode="replay" />);
    expect(html).toContain("Replay — no live write claimed");
    expect(html).toContain("never raw result rows");
  });

  it("renders measured benchmark gates", () => {
    const html = render(<BenchmarkPanel benchmark={replayBenchmark} />);
    expect(html).toContain("30");
    expect(html).toContain("100%");
    expect(html).toContain("False allows");
  });
});
