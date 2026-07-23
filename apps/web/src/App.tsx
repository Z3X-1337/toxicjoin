import { BenchmarkPanel } from "./components/BenchmarkPanel";
import { DecisionHero } from "./components/DecisionHero";
import { EvidenceGraph } from "./components/EvidenceGraph";
import { ProductHeader } from "./components/ProductHeader";
import { ReceiptPanel } from "./components/ReceiptPanel";
import { ResultTable } from "./components/ResultTable";
import { ScenarioRail } from "./components/ScenarioRail";
import { SqlWorkbench } from "./components/SqlWorkbench";
import { VerificationPanel } from "./components/VerificationPanel";
import { useJudgeSession } from "./hooks/useJudgeSession";

export function App() {
  const session = useJudgeSession();
  const blocked = session.result?.effective_decision === "BLOCK";
  const execution = session.result?.verification?.execution;

  return (
    <div className="app-shell" id="top">
      <div className="ambient-grid" aria-hidden="true" />
      <div className="ambient-glow glow-one" aria-hidden="true" />
      <div className="ambient-glow glow-two" aria-hidden="true" />

      <ProductHeader health={session.health} sourceMode={session.sourceMode} />

      {session.notice ? (
        <div className="mode-notice" role="status">
          <span aria-hidden="true">R</span>
          <p>{session.notice}</p>
        </div>
      ) : null}

      {session.error ? (
        <div className="error-notice" role="alert">
          <div>
            <strong>Protected execution did not complete</strong>
            <p>{session.error}</p>
          </div>
          <button type="button" onClick={() => void session.runSelectedScenario()}>
            Retry scenario
          </button>
        </div>
      ) : null}

      <main className="judge-layout">
        <div className="left-column">
          <ScenarioRail
            scenarios={session.scenarios}
            selectedScenarioId={session.selectedScenarioId}
            running={session.running || session.bootstrapping}
            onSelect={session.selectScenario}
            onRun={() => void session.runSelectedScenario()}
          />
          <BenchmarkPanel benchmark={session.benchmark} />
        </div>

        <div className="main-column">
          <DecisionHero
            scenario={session.selectedScenario}
            result={session.result}
            running={session.running || session.bootstrapping}
          />
          <EvidenceGraph result={session.result} />
          <SqlWorkbench scenario={session.selectedScenario} result={session.result} />

          <div className="proof-grid">
            <VerificationPanel
              verification={session.result?.verification}
              blocked={blocked}
            />
            <ResultTable execution={execution} blocked={blocked} />
          </div>

          <ReceiptPanel
            receipt={session.result?.receipt}
            sourceMode={session.sourceMode}
          />
        </div>
      </main>

      <footer className="product-footer">
        <div>
          <strong>ToxicJoin</strong>
          <span>Evidence before claims. Fail closed on uncertainty.</span>
        </div>
        <nav aria-label="Project resources">
          <a
            href="https://github.com/Z3X-1337/toxicjoin/blob/main/docs/judge-testing.md"
            target="_blank"
            rel="noreferrer"
          >
            90-second judge guide
          </a>
          <a
            href="https://github.com/Z3X-1337/toxicjoin/blob/main/docs/threat-model.md"
            target="_blank"
            rel="noreferrer"
          >
            Threat model
          </a>
          <a
            href="https://github.com/Z3X-1337/toxicjoin"
            target="_blank"
            rel="noreferrer"
          >
            Apache-2.0 source
          </a>
        </nav>
      </footer>
    </div>
  );
}
