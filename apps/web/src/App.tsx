import { AgentLoop } from "./components/AgentLoop";
import { BenchmarkPanel } from "./components/BenchmarkPanel";
import { DecisionHero } from "./components/DecisionHero";
import { EvidenceGraph } from "./components/EvidenceGraph";
import { ProductHeader } from "./components/ProductHeader";
import { QueryConsole } from "./components/QueryConsole";
import { ReceiptPanel } from "./components/ReceiptPanel";
import { ResultTable } from "./components/ResultTable";
import { ScenarioRail } from "./components/ScenarioRail";
import { SqlWorkbench } from "./components/SqlWorkbench";
import { VerificationPanel } from "./components/VerificationPanel";
import { useJudgeSession } from "./hooks/useJudgeSession";

const REPOSITORY_URL = "https://github.com/Z3X-1337/toxicjoin";
const RENDER_URL = "https://toxicjoin-public-demo.onrender.com/";

export function App() {
  const session = useJudgeSession();
  const blocked = session.result?.effective_decision === "BLOCK";
  const execution = session.result?.verification?.execution;

  return (
    <div className="app-shell" id="top">
      <ProductHeader health={session.health} />

      <main>
        <section className="landing-hero" aria-labelledby="landing-title">
          <div className="landing-copy">
            <p className="section-eyebrow">Runtime privacy control for data agents</p>
            <h1 id="landing-title">Decide what an AI data agent may reveal.</h1>
            <p className="landing-summary">
              ToxicJoin evaluates SQL before execution, detects sensitive combinations,
              and returns one enforceable outcome: allow, rewrite, or block.
            </p>
            <div className="landing-actions">
              <a className="primary-link" href="#console">Test a query</a>
              <a className="secondary-link" href="#decision-lab">Inspect the proof</a>
            </div>
          </div>

          <div className="outcome-card" aria-label="ToxicJoin decision model">
            <div className="outcome-card-head">
              <span>Decision boundary</span>
              <strong>Before data access</strong>
            </div>
            <ol>
              <li className="outcome-allow"><span>01</span><strong>ALLOW</strong><small>Safe as proposed</small></li>
              <li className="outcome-rewrite"><span>02</span><strong>REWRITE</strong><small>Repair, then verify</small></li>
              <li className="outcome-block"><span>03</span><strong>BLOCK</strong><small>No rows released</small></li>
            </ol>
          </div>
        </section>

        <section className="trust-bar" aria-label="Public deployment status">
          <div>
            <span className={`status-dot ${session.health ? "is-online" : ""}`} aria-hidden="true" />
            <p>
              <strong>{session.health ? "Render demo online" : "Connecting to Render"}</strong>
              <span>Public fixture environment · no organization data</span>
            </p>
          </div>
          <dl>
            <div><dt>Runtime</dt><dd>FastAPI + React</dd></div>
            <div><dt>Mode</dt><dd>{session.health?.mode ?? "checking"}</dd></div>
            <div><dt>Policy</dt><dd>{session.health?.policy_version ?? "checking"}</dd></div>
          </dl>
          <a href={RENDER_URL} target="_blank" rel="noreferrer">Open deployment ↗</a>
        </section>

        {session.error ? (
          <div className="error-notice" role="alert">
            <div>
              <strong>{session.health ? "Protected execution did not complete" : "Render API is not ready"}</strong>
              <p>{session.error} Free instances may need a short cold start.</p>
            </div>
            <button
              type="button"
              onClick={() => void (session.health ? session.runSelectedScenario() : session.retryBootstrap())}
            >
              {session.health ? "Retry scenario" : "Reconnect"}
            </button>
          </div>
        ) : null}

        <section className="product-section" aria-labelledby="console-section-title">
          <header className="section-intro">
            <p className="section-eyebrow">Interactive product</p>
            <h2 id="console-section-title">Run the real safety pipeline.</h2>
            <p>Choose a bounded example or submit SQL. Every response comes from this Render deployment.</p>
          </header>
          <QueryConsole />
        </section>

        <section className="product-section lab-section" id="decision-lab" aria-labelledby="lab-title">
          <header className="section-intro">
            <p className="section-eyebrow">Decision lab</p>
            <h2 id="lab-title">Follow one request from intent to receipt.</h2>
            <p>Inspect the decision, governed fields, verified SQL, released rows, and audit evidence.</p>
          </header>

          <div className="lab-layout">
            <ScenarioRail scenarios={session.scenarios} selectedScenarioId={session.selectedScenarioId} running={session.running || session.bootstrapping} onSelect={session.selectScenario} onRun={() => void session.runSelectedScenario()} />
            <div className="lab-results">
              <DecisionHero scenario={session.selectedScenario} result={session.result} running={session.running || session.bootstrapping} />
              <EvidenceGraph result={session.result} />
              <SqlWorkbench scenario={session.selectedScenario} result={session.result} />
              <div className="proof-grid">
                <VerificationPanel verification={session.result?.verification} blocked={blocked} />
                <ResultTable execution={execution} blocked={blocked} />
              </div>
              <ReceiptPanel receipt={session.result?.receipt} />
            </div>
          </div>
        </section>

        <section className="product-section evidence-section" aria-labelledby="evidence-section-title">
          <header className="section-intro">
            <p className="section-eyebrow">Measured evidence</p>
            <h2 id="evidence-section-title">Claims backed by repeatable checks.</h2>
          </header>
          <div className="evidence-layout">
            <BenchmarkPanel benchmark={session.benchmark} />
            <AgentLoop />
          </div>
        </section>
      </main>

      <footer className="product-footer">
        <div><strong>ToxicJoin</strong><span>Fail closed. Release only verified output.</span></div>
        <nav aria-label="Project resources">
          <a href={`${REPOSITORY_URL}/blob/main/docs/judge-testing.md`} target="_blank" rel="noreferrer">Judge guide</a>
          <a href={`${REPOSITORY_URL}/blob/main/docs/threat-model.md`} target="_blank" rel="noreferrer">Threat model</a>
          <a href={REPOSITORY_URL} target="_blank" rel="noreferrer">Source code ↗</a>
        </nav>
      </footer>
    </div>
  );
}
