import type { HealthResponse } from "../types";

interface ProductHeaderProps { health: HealthResponse | null; }

export function ProductHeader({ health }: ProductHeaderProps) {
  return (
    <header className="product-header">
      <a className="brand" href="#top" aria-label="ToxicJoin home">
        <svg className="brand-mark" viewBox="0 0 42 42" aria-hidden="true">
          <path d="M8 8h26v8H24v18h-8V16H8z" />
          <path d="M26 22h8v12H22v-8h4z" />
        </svg>
        <span><strong>ToxicJoin</strong><small>Privacy control plane</small></span>
      </a>
      <nav className="header-nav" aria-label="Primary navigation">
        <a href="#console">Console</a>
        <a href="#decision-lab">Decision lab</a>
        <a href="https://github.com/Z3X-1337/toxicjoin" target="_blank" rel="noreferrer">GitHub</a>
      </nav>
      <div className="header-proof" aria-label="System status">
        <span className={`proof-dot ${health ? "is-online" : ""}`} aria-hidden="true" />
        <span>{health ? `${health.mode === "live" ? "Live DataHub" : "Fixture"} API online` : "Connecting"}</span>
      </div>
    </header>
  );
}
