from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib import error, parse, request


class ProbeFailure(AssertionError):
    """A bounded probe failure that never embeds untrusted or secret values."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeFailure(code)


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - external response parser is fail-closed.
        raise ProbeFailure("INVALID_JSON_RESPONSE") from exc


def response_code(body: bytes) -> str | None:
    payload = parse_json(body)
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    if not isinstance(detail, dict):
        return None
    value = detail.get("code")
    return str(value) if value is not None else None


def canonical_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _token(label: str) -> str:
    return f"tj-bb-{label}-{secrets.token_hex(24)}"


def write_auth_files(*, container_env: Path, client_secrets: Path) -> None:
    """Create ephemeral credentials without writing or printing them to repository/log artifacts."""

    tokens = {
        "analyze": _token("analyze"),
        "execute": _token("execute"),
        "system": _token("system"),
        "owner_execute": _token("owner-execute"),
        "owner_read": _token("owner-read"),
        "beta_read": _token("beta-read"),
        "block": _token("block"),
        "mutation": _token("mutation"),
        "rate": _token("rate"),
    }
    credentials = [
        {
            "credential_id": "bb-analyze",
            "api_key": tokens["analyze"],
            "principal_id": "bb:analyze",
            "scopes": ["analyze"],
        },
        {
            "credential_id": "bb-execute",
            "api_key": tokens["execute"],
            "principal_id": "bb:execute",
            "scopes": ["execute"],
        },
        {
            "credential_id": "bb-system",
            "api_key": tokens["system"],
            "principal_id": "bb:system",
            "scopes": ["system:read"],
        },
        {
            "credential_id": "bb-owner-execute",
            "api_key": tokens["owner_execute"],
            "principal_id": "bb:owner",
            "scopes": ["execute"],
        },
        {
            "credential_id": "bb-owner-read",
            "api_key": tokens["owner_read"],
            "principal_id": "bb:owner",
            "scopes": ["receipts:read"],
        },
        {
            "credential_id": "bb-beta-read",
            "api_key": tokens["beta_read"],
            "principal_id": "bb:beta",
            "scopes": ["receipts:read"],
        },
        {
            "credential_id": "bb-block",
            "api_key": tokens["block"],
            "principal_id": "bb:block",
            "scopes": ["execute"],
        },
        {
            "credential_id": "bb-mutation",
            "api_key": tokens["mutation"],
            "principal_id": "bb:mutation",
            "scopes": ["execute"],
        },
        {
            "credential_id": "bb-rate",
            "api_key": tokens["rate"],
            "principal_id": "bb:rate",
            "scopes": ["system:read"],
        },
    ]
    container_env.parent.mkdir(parents=True, exist_ok=True)
    client_secrets.parent.mkdir(parents=True, exist_ok=True)
    api_json = json.dumps(credentials, separators=(",", ":"))
    container_env.write_text(f"TOXICJOIN_API_KEYS_JSON={api_json}\n", encoding="utf-8")
    client_secrets.write_text(json.dumps(tokens, sort_keys=True), encoding="utf-8")
    os.chmod(container_env, 0o600)
    os.chmod(client_secrets, 0o600)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class Client:
    def __init__(self, base_url: str) -> None:
        parsed = parse.urlparse(base_url)
        if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
            raise ValueError("base URL must be explicit http://host:port")
        self.base_url = base_url.rstrip("/")
        self.host = parsed.hostname
        self.port = parsed.port
        self.observed_bodies: list[str] = []

    def call(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        data = raw_body
        resolved_headers = dict(headers or {})
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            resolved_headers.setdefault("Content-Type", "application/json")
        req = request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=resolved_headers,
            method=method,
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                status = int(response.status)
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
                body = response.read()
        except error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            body = exc.read()
        self.observed_bodies.append(body.decode("utf-8", errors="replace"))
        return status, response_headers, body

    def invalid_host(self, path: str = "/api/health") -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=20)
        try:
            connection.request("GET", path, headers={"Host": "untrusted.invalid"})
            response = connection.getresponse()
            body = response.read()
            self.observed_bodies.append(body.decode("utf-8", errors="replace"))
            return int(response.status), body
        finally:
            connection.close()


def docker_json(container_name: str) -> dict[str, Any]:
    raw = subprocess.check_output(["docker", "inspect", container_name], text=True)
    payload = json.loads(raw)
    require(isinstance(payload, list) and len(payload) == 1, "DOCKER_INSPECT_SHAPE")
    return payload[0]


def docker_exec(
    container_name: str,
    *command: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container_name, *command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


ORDERS_SUBJECT = {
    "dataset": "orders",
    "field_path": "customer_id",
    "alias": "o",
}
CUSTOMER_SUBJECT = {
    "dataset": "customers",
    "field_path": "customer_id",
    "alias": "c",
}
SAFE_AGGREGATE = {
    "task_purpose": "Phase 0 current-main black-box safe aggregate",
    "sql": (
        "SELECT o.category, COUNT(*) AS order_count "
        "FROM orders o GROUP BY o.category ORDER BY o.category"
    ),
    "subject_key": ORDERS_SUBJECT,
    "dialect": "duckdb",
}
BLOCKED_EXPORT = {
    "task_purpose": "Phase 0 current-main black-box sensitive export",
    "sql": (
        "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category "
        "FROM customers c JOIN support_cases s ON c.customer_id = s.customer_id"
    ),
    "subject_key": CUSTOMER_SUBJECT,
    "dialect": "duckdb",
}
MUTATION = {
    "task_purpose": "Phase 0 current-main black-box mutation attempt",
    "sql": "DELETE FROM orders",
    "subject_key": ORDERS_SUBJECT,
    "dialect": "duckdb",
}


def run_blackbox(
    *,
    base_url: str,
    container_name: str,
    source_sha: str,
    auth_file: Path,
    output: Path,
) -> int:
    require(len(source_sha) == 40, "SOURCE_SHA_INVALID")
    tokens = json.loads(auth_file.read_text(encoding="utf-8"))
    require(isinstance(tokens, dict), "AUTH_FILE_INVALID")
    client = Client(base_url)
    results: list[dict[str, Any]] = []
    receipt_id: str | None = None

    def check(name: str, detail: str, action: Callable[[], None]) -> None:
        try:
            action()
            results.append({"name": name, "passed": True, "detail": detail})
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001 - aggregate independent probes.
            results.append(
                {
                    "name": name,
                    "passed": False,
                    "detail": f"probe_failed:{type(exc).__name__}",
                }
            )
            print(f"FAIL {name}: {type(exc).__name__}", file=sys.stderr)

    def container_boundary() -> None:
        inspect = docker_json(container_name)
        config = inspect.get("Config", {})
        host = inspect.get("HostConfig", {})
        bindings = host.get("PortBindings") or {}
        require(config.get("User") == "10001:10001", "CONTAINER_USER")
        require(host.get("ReadonlyRootfs") is True, "ROOTFS_NOT_READ_ONLY")
        require(
            "ALL" in {str(item).upper() for item in host.get("CapDrop") or []},
            "CAP_DROP_ALL_MISSING",
        )
        require(
            any(
                str(item).startswith("no-new-privileges")
                for item in host.get("SecurityOpt") or []
            ),
            "NO_NEW_PRIVILEGES_MISSING",
        )
        require(host.get("PidsLimit") == 128, "PID_LIMIT")
        require(host.get("Memory") == 805306368, "MEMORY_LIMIT")
        require(host.get("NanoCpus") == 1_000_000_000, "CPU_LIMIT")
        entries = bindings.get("8000/tcp") or []
        require(bool(entries), "PORT_BINDING_MISSING")
        require(
            all(entry.get("HostIp") == "127.0.0.1" for entry in entries),
            "PORT_NOT_LOOPBACK_ONLY",
        )
        require(
            docker_exec(container_name, "id", "-u").stdout.strip() == "10001",
            "RUNTIME_UID",
        )
        root_write = docker_exec(
            container_name,
            "python",
            "-c",
            "from pathlib import Path; Path('/app/bb-root-write').write_text('x')",
            check=False,
        )
        require(root_write.returncode != 0, "ROOTFS_WRITABLE")
        runtime_write = docker_exec(
            container_name,
            "python",
            "-c",
            (
                "from pathlib import Path; "
                "p=Path('/var/lib/toxicjoin/bb-runtime-write'); "
                "p.write_text('ok'); p.unlink()"
            ),
        )
        require(runtime_write.returncode == 0, "RUNTIME_VOLUME_NOT_WRITABLE")

    check(
        "container_boundary",
        "non-root, read-only rootfs, dropped capabilities, no-new-privileges, bounded loopback container",
        container_boundary,
    )

    def public_liveness() -> None:
        status, headers, body = client.call("GET", "/api/health")
        require(status == 200, "HEALTH_STATUS")
        require(parse_json(body) == {"status": "ok"}, "HEALTH_PAYLOAD")
        require(headers.get("x-content-type-options") == "nosniff", "NOSNIFF")
        require(headers.get("x-frame-options") == "DENY", "FRAME_HEADER")
        require("default-src 'self'" in headers.get("content-security-policy", ""), "CSP")
        require(headers.get("cache-control") == "no-store, max-age=0", "CACHE_CONTROL")
        require("strict-transport-security" not in headers, "HSTS_OVER_HTTP")

    check(
        "public_liveness_minimal",
        "minimal unauthenticated liveness and security headers verified",
        public_liveness,
    )

    def restricted_root() -> None:
        status, _, body = client.call("GET", "/")
        require(status == 200, "ROOT_STATUS")
        require(parse_json(body) == {"name": "ToxicJoin"}, "ROOT_PAYLOAD")

    check(
        "restricted_root_minimal",
        "restricted root exposes no version, docs, or judge metadata",
        restricted_root,
    )

    def hidden_surface() -> None:
        for path in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/demo/scenarios",
            "/api/benchmark/summary",
            "/assets/index.js",
        ):
            status, _, _ = client.call("GET", path)
            require(status == 404, "RESTRICTED_SURFACE_EXPOSED")

    check(
        "restricted_surface_hidden",
        "docs, schema, demo, benchmark, and judge assets are not exposed",
        hidden_surface,
    )

    def hostile_host() -> None:
        status, _ = client.invalid_host()
        require(status == 400, "TRUSTED_HOST_BYPASS")

    check("trusted_host_enforced", "untrusted Host header rejected", hostile_host)

    def missing_bearer() -> None:
        status, headers, body = client.call("GET", "/api/ready")
        require(status == 401, "MISSING_BEARER_STATUS")
        require(response_code(body) == "AUTH_MISSING_BEARER", "MISSING_BEARER_CODE")
        require(headers.get("www-authenticate") == "Bearer", "AUTH_CHALLENGE")

    check(
        "auth_missing_bearer",
        "protected readiness rejects unauthenticated access",
        missing_bearer,
    )

    def invalid_key() -> None:
        status, _, body = client.call(
            "GET",
            "/api/ready",
            headers=bearer("invalid-blackbox-key"),
        )
        require(status == 401, "INVALID_KEY_STATUS")
        require(response_code(body) == "AUTH_INVALID_API_KEY", "INVALID_KEY_CODE")

    check("auth_invalid_key", "invalid bearer key rejected", invalid_key)

    def invalid_session() -> None:
        headers = bearer(tokens["system"])
        headers["X-ToxicJoin-Session"] = "invalid session with spaces"
        status, _, body = client.call("GET", "/api/ready", headers=headers)
        require(status == 401, "INVALID_SESSION_STATUS")
        require(response_code(body) == "AUTH_INVALID_SESSION", "INVALID_SESSION_CODE")

    check("auth_invalid_session", "malformed session identity rejected", invalid_session)

    def scope_ready() -> None:
        status, _, body = client.call(
            "GET",
            "/api/ready",
            headers=bearer(tokens["execute"]),
        )
        require(status == 403, "SYSTEM_SCOPE_STATUS")
        payload = parse_json(body)
        require(payload.get("detail", {}).get("code") == "AUTH_INSUFFICIENT_SCOPE", "SYSTEM_SCOPE_CODE")
        require(payload.get("detail", {}).get("required_scope") == "system:read", "SYSTEM_SCOPE_VALUE")

    check(
        "scope_system_read",
        "execute credential cannot read system readiness",
        scope_ready,
    )

    def scope_analyze() -> None:
        status, _, body = client.call(
            "POST",
            "/api/analyze",
            headers=bearer(tokens["system"]),
            json_body=SAFE_AGGREGATE,
        )
        require(status == 403, "ANALYZE_SCOPE_STATUS")
        require(response_code(body) == "AUTH_INSUFFICIENT_SCOPE", "ANALYZE_SCOPE_CODE")

    check("scope_analyze", "system credential cannot analyze", scope_analyze)

    def scope_execute() -> None:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(tokens["analyze"]),
            json_body=SAFE_AGGREGATE,
        )
        require(status == 403, "EXECUTE_SCOPE_STATUS")
        require(response_code(body) == "AUTH_INSUFFICIENT_SCOPE", "EXECUTE_SCOPE_CODE")

    check("scope_execute", "analyze credential cannot execute", scope_execute)

    def readiness() -> None:
        status, _, body = client.call(
            "GET",
            "/api/ready",
            headers=bearer(tokens["system"]),
        )
        require(status == 200, "READINESS_STATUS")
        payload = parse_json(body)
        require(payload.get("status") == "ok", "READINESS_STATE")
        require(payload.get("mode") == "fixture", "READINESS_MODE")
        require(payload.get("database_ready") is True, "DATABASE_NOT_READY")
        require(payload.get("receipt_store_ready") is True, "RECEIPT_STORE_NOT_READY")

    check(
        "authorized_readiness",
        "authorized readiness reports healthy restricted fixture runtime",
        readiness,
    )

    def oversized_body() -> None:
        payload = dict(SAFE_AGGREGATE)
        payload["task_purpose"] = "X" * 5000
        status, _, body = client.call(
            "POST",
            "/api/analyze",
            headers=bearer(tokens["analyze"]),
            json_body=payload,
        )
        require(status == 413, "BODY_LIMIT_STATUS")
        require(response_code(body) == "REQUEST_BODY_TOO_LARGE", "BODY_LIMIT_CODE")

    check(
        "request_body_limit",
        "oversized body rejected before framework parsing",
        oversized_body,
    )

    def mutation_blocked() -> None:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(tokens["mutation"]),
            json_body=MUTATION,
        )
        require(status == 200, "MUTATION_STATUS")
        payload = parse_json(body)
        require(payload.get("effective_decision") == "BLOCK", "MUTATION_NOT_BLOCKED")
        require((payload.get("receipt") or {}).get("execution") is None, "MUTATION_EXECUTED")

    check(
        "mutation_fail_closed",
        "mutating SQL fails closed with no execution summary",
        mutation_blocked,
    )

    def sensitive_export_blocked() -> None:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(tokens["block"]),
            json_body=BLOCKED_EXPORT,
        )
        require(status == 200, "SENSITIVE_EXPORT_STATUS")
        payload = parse_json(body)
        require(payload.get("effective_decision") == "BLOCK", "SENSITIVE_EXPORT_NOT_BLOCKED")
        require((payload.get("receipt") or {}).get("execution") is None, "SENSITIVE_EXPORT_EXECUTED")

    check(
        "sensitive_export_fail_closed",
        "compositional sensitive export blocked before execution",
        sensitive_export_blocked,
    )

    def safe_execute() -> None:
        nonlocal receipt_id
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(tokens["owner_execute"]),
            json_body=SAFE_AGGREGATE,
        )
        require(status == 200, "SAFE_EXECUTION_STATUS")
        payload = parse_json(body)
        require(payload.get("effective_decision") == "ALLOW", "SAFE_EXECUTION_NOT_ALLOWED")
        receipt = payload.get("receipt") or {}
        execution = receipt.get("execution")
        require(isinstance(execution, dict), "EXECUTION_SUMMARY_MISSING")
        require("rows" not in execution and "preview_rows" not in execution, "RAW_ROWS_IN_RECEIPT")
        candidate = receipt.get("receipt_id")
        require(isinstance(candidate, str) and candidate.startswith("tj_"), "RECEIPT_ID_MISSING")
        receipt_id = candidate

    check(
        "safe_execution_boundary",
        "low-risk aggregate allowed; receipt summarizes execution without raw rows",
        safe_execute,
    )

    def owner_receipt() -> None:
        require(receipt_id is not None, "NO_RECEIPT")
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(tokens["owner_read"]),
        )
        require(status == 200, "OWNER_RECEIPT_STATUS")
        payload = parse_json(body)
        require(payload.get("receipt_id") == receipt_id, "OWNER_RECEIPT_ID")
        require(payload.get("identity", {}).get("principal_id") == "bb:owner", "OWNER_IDENTITY")

    check(
        "receipt_owner_visibility",
        "same-principal reader can retrieve receipt",
        owner_receipt,
    )

    def other_receipt_hidden() -> None:
        require(receipt_id is not None, "NO_RECEIPT")
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(tokens["beta_read"]),
        )
        require(status == 404, "CROSS_PRINCIPAL_STATUS")
        require(response_code(body) == "RECEIPT_NOT_FOUND", "CROSS_PRINCIPAL_CODE")

    check(
        "receipt_cross_principal_isolation",
        "receipt existence hidden from another principal",
        other_receipt_hidden,
    )

    def receipt_permissions() -> None:
        require(receipt_id is not None, "NO_RECEIPT")
        mode = docker_exec(
            container_name,
            "stat",
            "-c",
            "%a",
            f"/var/lib/toxicjoin/receipts/{receipt_id}.json",
        ).stdout.strip()
        require(mode == "600", "RECEIPT_FILE_MODE")

    check(
        "receipt_file_permissions",
        "persisted receipt mode is 0600",
        receipt_permissions,
    )

    def receipt_tamper() -> None:
        require(receipt_id is not None, "NO_RECEIPT")
        code = (
            "import json; from pathlib import Path; "
            f"p=Path('/var/lib/toxicjoin/receipts/{receipt_id}.json'); "
            "d=json.loads(p.read_text()); d['task_purpose']='tampered'; "
            "p.write_text(json.dumps(d, sort_keys=True, indent=2)+'\\n')"
        )
        docker_exec(container_name, "python", "-c", code)
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(tokens["owner_read"]),
        )
        require(status == 409, "TAMPER_STATUS")
        require(response_code(body) == "RECEIPT_INTEGRITY_FAILURE", "TAMPER_CODE")

    check(
        "receipt_tamper_detection",
        "post-persistence receipt modification detected through public API",
        receipt_tamper,
    )

    def unknown_receipt() -> None:
        status, _, body = client.call(
            "GET",
            "/api/receipts/tj_0000000000000000",
            headers=bearer(tokens["owner_read"]),
        )
        require(status == 404, "UNKNOWN_RECEIPT_STATUS")
        require(response_code(body) == "RECEIPT_NOT_FOUND", "UNKNOWN_RECEIPT_CODE")

    check(
        "receipt_unknown_id",
        "unknown opaque receipt id returns stable 404",
        unknown_receipt,
    )

    def malformed_receipt() -> None:
        status, _, body = client.call(
            "GET",
            "/api/receipts/not-a-valid-id",
            headers=bearer(tokens["owner_read"]),
        )
        require(status == 422, "MALFORMED_RECEIPT_STATUS")
        decoded = body.decode("utf-8", errors="replace")
        require("Traceback" not in decoded, "VALIDATION_TRACEBACK")

    check(
        "receipt_id_contract",
        "malformed receipt id rejected without traceback",
        malformed_receipt,
    )

    def rate_limit() -> None:
        for _ in range(8):
            status, _, body = client.call(
                "GET",
                "/api/ready",
                headers=bearer(tokens["rate"]),
            )
            require(status == 200, "RATE_PRELIMIT_STATUS")
            require(parse_json(body).get("status") == "ok", "RATE_PRELIMIT_BODY")
        status, headers, body = client.call(
            "GET",
            "/api/ready",
            headers=bearer(tokens["rate"]),
        )
        require(status == 429, "RATE_LIMIT_STATUS")
        require(response_code(body) == "RATE_LIMIT_EXCEEDED", "RATE_LIMIT_CODE")
        require(int(headers.get("retry-after", "0")) >= 1, "RETRY_AFTER")

    check(
        "rate_limit_enforced",
        "dedicated principal is rejected after the configured sliding-window budget",
        rate_limit,
    )

    def leakage() -> None:
        corpus = "\n".join(client.observed_bodies)
        require(
            all(str(token) not in corpus for token in tokens.values()),
            "CREDENTIAL_IN_HTTP_RESPONSE",
        )
        require("Traceback (most recent call last)" not in corpus, "TRACEBACK_IN_HTTP_RESPONSE")
        require("/app/src/toxicjoin/" not in corpus, "SOURCE_PATH_IN_HTTP_RESPONSE")

    check(
        "response_secret_and_traceback_leakage",
        "observed HTTP responses contain no ephemeral credentials, traceback, or source paths",
        leakage,
    )

    passed_count = sum(1 for item in results if item["passed"])
    failed_count = len(results) - passed_count
    report: dict[str, Any] = {
        "schema_version": "2.0",
        "experiment": "phase-0-current-main-external-blackbox",
        "source_sha": source_sha,
        "test_count": len(results),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "passed": failed_count == 0,
        "tests": results,
    }
    report["report_sha256"] = canonical_hash(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "source_sha": source_sha,
                "test_count": len(results),
                "passed_count": passed_count,
                "failed_count": failed_count,
                "passed": failed_count == 0,
                "report_sha256": report["report_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0 if failed_count == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-auth-files", action="store_true")
    parser.add_argument("--container-env")
    parser.add_argument("--client-secrets")
    parser.add_argument("--base-url")
    parser.add_argument("--container-name")
    parser.add_argument("--source-sha")
    parser.add_argument("--auth-file")
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.write_auth_files:
        if not args.container_env or not args.client_secrets:
            parser.error("--container-env and --client-secrets are required")
        write_auth_files(
            container_env=Path(args.container_env),
            client_secrets=Path(args.client_secrets),
        )
        return

    required = {
        "--base-url": args.base_url,
        "--container-name": args.container_name,
        "--source-sha": args.source_sha,
        "--auth-file": args.auth_file,
        "--output": args.output,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        parser.error("missing required arguments: " + ", ".join(missing))
    raise SystemExit(
        run_blackbox(
            base_url=args.base_url,
            container_name=args.container_name,
            source_sha=args.source_sha,
            auth_file=Path(args.auth_file),
            output=Path(args.output),
        )
    )


if __name__ == "__main__":
    main()
