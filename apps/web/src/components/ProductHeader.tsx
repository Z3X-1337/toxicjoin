import type { HealthResponse, SourceMode } from "../types";

interface ProductHeaderProps {
  health: HealthResponse | null;
  sourceMode: SourceMode;
}

export function ProductHeader({ health, sourceMode }: ProductHeaderProps) {
  const modeLabel =
    sourceMode === "replay"
      ? "Deterministic replay"
      : health?.mode === "live"
        ? "Live DataHub"
        : "Fixture execution";

  return (
    <header className="product-header">
      <a className="brand" href="#top" aria-label="ToxicJoin home">
        <span className="brand-mark" aria-hidden="true">
          TJ
        </span>
        <span>
          <strong>ToxicJoin</strong>
          <small>Compositional privacy firewall</small>
        </span>
      </a>

      <div className="header-proof" aria-label="System status">
        <span className="proof-dot" aria-hidden="true" />
        <span>{modeLabel}</span>
        <span className="proof-divider" aria-hidden="true" />
        <span>Policy {health?.policy_version ?? "0.1.0"}</span>
      </div>

      <a
        className="header-link"
        href="https://github.com/Z3X-1337/toxicjoin"
        target="_blank"
        rel="noreferrer"
      >
        Inspect source
        <span aria-hidden="true">↗</span>
      </a>
    </header>
  );
}
