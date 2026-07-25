from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib import error, parse, request


KEY_ANALYZE = "p5-analyze-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
KEY_EXECUTE = "p5-execute-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
KEY_SYSTEM = "p5-system-cccccccccccccccccccccccccccccccc"
KEY_OWNER_EXECUTE = "p5-owner-execute-dddddddddddddddddddddddddddd"
KEY_OWNER_READ = "p5-owner-read-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
KEY_BETA_READ = "p5-beta-read-ffffffffffffffffffffffffffffffff"
KEY_BLOCK = "p5-block-gggggggggggggggggggggggggggggggg"
KEY_MUTATION = "p5-mutation-hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
KEY_RATE = "p5-rate-iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"

ALL_KEYS = (
    KEY_ANALYZE,
    KEY_EXECUTE,
    KEY_SYSTEM,
    KEY_OWNER_EXECUTE,
    KEY_OWNER_READ,
    KEY_BETA_READ,
    KEY_BLOCK,
    KEY_MUTATION,
    KEY_RATE,
)

CREDENTIALS = [
    {
        "credential_id": "p5-analyze",
        "api_key": KEY_ANALYZE,
        "principal_id": "p5:analyze",
        "scopes": ["analyze"],
    },
    {
        "credential_id": "p5-execute",
        "api_key": KEY_EXECUTE,
        "principal_id": "p5:execute",
        "scopes": ["execute"],
    },
    {
        "credential_id": "p5-system",
        "api_key": KEY_SYSTEM,
        "principal_id": "p5:system",
        "scopes": ["system:read"],
    },
    {
        "credential_id": "p5-owner-execute",
        "api_key": KEY_OWNER_EXECUTE,
        "principal_id": "p5:owner",
        "scopes": ["execute"],
    },
    {
        "credential_id": "p5-owner-read",
        "api_key": KEY_OWNER_READ,
        "principal_id": "p5:owner",
        "scopes": ["receipts:read"],
    },
    {
        "credential_id": "p5-beta-read",
        "api_key": KEY_BETA_READ,
        "principal_id": "p5:beta",
        "scopes": ["receipts:read"],
    },
    {
        "credential_id": "p5-block",
        "api_key": KEY_BLOCK,
        "principal_id": "p5:block",
        "scopes": ["execute"],
    },
    {
        "credential_id": "p5-mutation",
        "api_key": KEY_MUTATION,
        "principal_id": "p5:mutation",
        "scopes": ["execute"],
    },
    {
        "credential_id": "p5-rate",
        "api_key": KEY_RATE,
        "principal_id": "p5:rate",
        "scopes": ["system:read"],
    },
]

SUBJECT_KEY = {
    "dataset": "customers",
    "field_path": "customer_id",
    "alias": "c",
}

SAFE_AGGREGATE = {
    "task_purpose": "P5 black-box safe aggregate",
    "sql": (
        "SELECT o.category, COUNT(*) AS order_count "
        "FROM orders o GROUP BY o.category ORDER BY o.category"
    ),
    "subject_key": SUBJECT_KEY,
    "dialect": "duckdb",
}

BLOCKED_EXPORT = {
    "task_purpose": "P5 black-box sensitive export",
    "sql": (
        "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category "
        "FROM customers c JOIN support_cases s ON c.customer_id = s.customer_id"
    ),
    "subject_key": SUBJECT_KEY,
    "dialect": "duckdb",
}

MUTATION = {
    "task_purpose": "P5 black-box mutation attempt",
    "sql": "DELETE FROM orders",
    "subject_key": SUBJECT_KEY,
    "dialect": "duckdb",
}


class PentestFailure(AssertionError):
    pass


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def assert_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise PentestFailure(f"{message}: expected={expected!r} actual={actual!r}")


def assert_true(value: Any, message: str) -> None:
    if not value:
        raise PentestFailure(message)


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - test harness must preserve diagnostics.
        raise PentestFailure(f"response is not valid JSON: {body[:300]!r}") from exc


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
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                body = response.read()
        except error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            body = exc.read()
        decoded = body.decode("utf-8", errors="replace")
        self.observed_bodies.append(decoded)
        return status, response_headers, body

    def invalid_host(self, path: str = "/api/health") -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=20)
        try:
            connection.request("GET", path, headers={"Host": "evil.example"})
            response = connection.getresponse()
            body = response.read()
            self.observed_bodies.append(body.decode("utf-8", errors="replace"))
            return int(response.status), body
        finally:
            connection.close()


def docker_json(container_name: str) -> dict[str, Any]:
    raw = subprocess.check_output(
        ["docker", "inspect", container_name],
        text=True,
    )
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) != 1:
        raise PentestFailure("docker inspect returned unexpected payload")
    return payload[0]


def docker_exec(container_name: str, *command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container_name, *command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def response_code(body: bytes) -> str | None:
    payload = parse_json(body)
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    if isinstance(detail, dict):
        value = detail.get("code")
        return str(value) if value is not None else None
    return None


def canonical_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def run_pentest(
    *,
    base_url: str,
    container_name: str,
    target_pr: int,
    release_candidate_sha: str,
    output: Path,
) -> int:
    client = Client(base_url)
    results: list[dict[str, Any]] = []
    receipt_id: str | None = None

    def check(name: str, action: Callable[[], str | None]) -> None:
        try:
            detail = action() or "verified"
            results.append({"name": name, "passed": True, "detail": detail})
            print(f"PASS {name}: {detail}")
        except Exception as exc:  # noqa: BLE001 - aggregate all independent probes.
            results.append(
                {
                    "name": name,
                    "passed": False,
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            print(f"FAIL {name}: {type(exc).__name__}: {exc}", file=sys.stderr)

    def container_boundary() -> str:
        inspect = docker_json(container_name)
        config = inspect.get("Config", {})
        host = inspect.get("HostConfig", {})
        network = inspect.get("NetworkSettings", {})
        assert_equal(config.get("User"), "10001:10001", "container user")
        assert_equal(host.get("ReadonlyRootfs"), True, "read-only root filesystem")
        cap_drop = {str(item).upper() for item in host.get("CapDrop") or []}
        assert_true("ALL" in cap_drop, "container must drop all Linux capabilities")
        security_opt = [str(item) for item in host.get("SecurityOpt") or []]
        assert_true(
            any(item.startswith("no-new-privileges") for item in security_opt),
            "container must enable no-new-privileges",
        )
        assert_equal(host.get("PidsLimit"), 128, "PID budget")
        bindings = host.get("PortBindings") or {}
        port_entries = bindings.get("8000/tcp") or []
        assert_true(port_entries, "port 8000 must have an explicit binding")
        assert_true(
            all(entry.get("HostIp") == "127.0.0.1" for entry in port_entries),
            "pentest container must be bound to loopback only",
        )
        assert_true(network.get("Ports") is not None, "container network state missing")
        uid = docker_exec(container_name, "id", "-u").stdout.strip()
        assert_equal(uid, "10001", "runtime UID")

        root_write = docker_exec(
            container_name,
            "python",
            "-c",
            "from pathlib import Path; Path('/app/p5-rootfs-write').write_text('x')",
            check=False,
        )
        assert_true(root_write.returncode != 0, "read-only /app unexpectedly writable")
        runtime_write = docker_exec(
            container_name,
            "python",
            "-c",
            (
                "from pathlib import Path; "
                "p=Path('/var/lib/toxicjoin/p5-runtime-write'); "
                "p.write_text('ok'); p.unlink()"
            ),
        )
        assert_equal(runtime_write.returncode, 0, "runtime tmpfs must remain writable")
        return "non-root, read-only rootfs, cap-drop, no-new-privileges, bounded localhost exposure"

    check("container_boundary", container_boundary)

    def public_liveness() -> str:
        status, headers, body = client.call("GET", "/api/health")
        assert_equal(status, 200, "liveness status")
        assert_equal(parse_json(body), {"status": "ok"}, "public liveness payload")
        assert_equal(headers.get("x-content-type-options"), "nosniff", "nosniff header")
        assert_equal(headers.get("x-frame-options"), "DENY", "frame header")
        assert_true("default-src 'self'" in headers.get("content-security-policy", ""), "CSP")
        assert_equal(headers.get("cache-control"), "no-store, max-age=0", "API cache control")
        assert_true("strict-transport-security" not in headers, "HSTS must not be sent over HTTP")
        return "minimal unauthenticated liveness and security headers verified"

    check("public_liveness_minimal", public_liveness)

    def restricted_root() -> str:
        status, _, body = client.call("GET", "/")
        assert_equal(status, 200, "service root status")
        assert_equal(parse_json(body), {"name": "ToxicJoin"}, "restricted root payload")
        return "restricted root exposes no version, docs, or judge-interface metadata"

    check("restricted_root_minimal", restricted_root)

    def hidden_surface() -> str:
        for path in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/demo/scenarios",
            "/api/benchmark/summary",
            "/assets/index.js",
        ):
            status, _, _ = client.call("GET", path)
            assert_equal(status, 404, f"restricted path {path}")
        return "docs, schema, demo, benchmark, and judge assets are not exposed"

    check("restricted_surface_hidden", hidden_surface)

    def host_header_rejected() -> str:
        status, _ = client.invalid_host()
        assert_equal(status, 400, "untrusted Host header status")
        return "untrusted Host header rejected"

    check("trusted_host_enforced", host_header_rejected)

    def missing_bearer() -> str:
        status, headers, body = client.call("GET", "/api/ready")
        assert_equal(status, 401, "missing bearer status")
        assert_equal(response_code(body), "AUTH_MISSING_BEARER", "missing bearer code")
        assert_equal(headers.get("www-authenticate"), "Bearer", "WWW-Authenticate header")
        return "protected readiness rejects unauthenticated access"

    check("auth_missing_bearer", missing_bearer)

    def invalid_key() -> str:
        status, _, body = client.call(
            "GET",
            "/api/ready",
            headers=bearer("invalid-key-material-xxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        assert_equal(status, 401, "invalid key status")
        assert_equal(response_code(body), "AUTH_INVALID_API_KEY", "invalid key code")
        return "invalid bearer key rejected"

    check("auth_invalid_key", invalid_key)

    def invalid_session() -> str:
        headers = bearer(KEY_SYSTEM)
        headers["X-ToxicJoin-Session"] = "invalid session with spaces"
        status, _, body = client.call("GET", "/api/ready", headers=headers)
        assert_equal(status, 401, "invalid session status")
        assert_equal(response_code(body), "AUTH_INVALID_SESSION", "invalid session code")
        return "malformed session identity rejected"

    check("auth_invalid_session", invalid_session)

    def scope_ready() -> str:
        status, _, body = client.call("GET", "/api/ready", headers=bearer(KEY_EXECUTE))
        assert_equal(status, 403, "wrong-scope readiness status")
        payload = parse_json(body)
        assert_equal(payload["detail"]["code"], "AUTH_INSUFFICIENT_SCOPE", "scope error code")
        assert_equal(payload["detail"]["required_scope"], "system:read", "required scope")
        return "execute credential cannot read system readiness"

    check("scope_system_read", scope_ready)

    def scope_analyze() -> str:
        status, _, body = client.call(
            "POST",
            "/api/analyze",
            headers=bearer(KEY_SYSTEM),
            json_body=SAFE_AGGREGATE,
        )
        assert_equal(status, 403, "wrong-scope analyze status")
        assert_equal(response_code(body), "AUTH_INSUFFICIENT_SCOPE", "analyze scope error")
        return "system credential cannot analyze"

    check("scope_analyze", scope_analyze)

    def scope_execute() -> str:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(KEY_ANALYZE),
            json_body=SAFE_AGGREGATE,
        )
        assert_equal(status, 403, "wrong-scope execute status")
        assert_equal(response_code(body), "AUTH_INSUFFICIENT_SCOPE", "execute scope error")
        return "analyze credential cannot execute"

    check("scope_execute", scope_execute)

    def readiness_authorized() -> str:
        status, _, body = client.call("GET", "/api/ready", headers=bearer(KEY_SYSTEM))
        assert_equal(status, 200, "authorized readiness status")
        payload = parse_json(body)
        assert_equal(payload.get("status"), "ok", "readiness state")
        assert_equal(payload.get("mode"), "fixture", "restricted pentest mode")
        assert_equal(payload.get("database_ready"), True, "database readiness")
        assert_equal(payload.get("receipt_store_ready"), True, "receipt readiness")
        return "authorized readiness reports healthy restricted fixture runtime"

    check("authorized_readiness", readiness_authorized)

    def oversized_body() -> str:
        payload = dict(SAFE_AGGREGATE)
        payload["task_purpose"] = "X" * 5000
        status, _, body = client.call(
            "POST",
            "/api/analyze",
            headers=bearer(KEY_ANALYZE),
            json_body=payload,
        )
        assert_equal(status, 413, "oversized request status")
        assert_equal(response_code(body), "REQUEST_BODY_TOO_LARGE", "oversized request code")
        return "oversized body rejected before framework parsing"

    check("request_body_limit", oversized_body)

    def mutation_blocked() -> str:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(KEY_MUTATION),
            json_body=MUTATION,
        )
        assert_equal(status, 200, "mutation pipeline response status")
        payload = parse_json(body)
        assert_equal(payload.get("effective_decision"), "BLOCK", "mutation decision")
        receipt = payload.get("receipt") or {}
        assert_true(receipt.get("execution") is None, "blocked mutation unexpectedly executed")
        return "mutating SQL fails closed with no execution summary"

    check("mutation_fail_closed", mutation_blocked)

    def sensitive_export_blocked() -> str:
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(KEY_BLOCK),
            json_body=BLOCKED_EXPORT,
        )
        assert_equal(status, 200, "sensitive export response status")
        payload = parse_json(body)
        assert_equal(payload.get("effective_decision"), "BLOCK", "sensitive export decision")
        receipt = payload.get("receipt") or {}
        assert_true(receipt.get("execution") is None, "blocked sensitive export unexpectedly executed")
        return "compositional sensitive export blocked before execution"

    check("sensitive_export_fail_closed", sensitive_export_blocked)

    def safe_execute() -> str:
        nonlocal receipt_id
        status, _, body = client.call(
            "POST",
            "/api/execute-safe",
            headers=bearer(KEY_OWNER_EXECUTE),
            json_body=SAFE_AGGREGATE,
        )
        assert_equal(status, 200, "safe aggregate response status")
        payload = parse_json(body)
        assert_equal(payload.get("effective_decision"), "ALLOW", "safe aggregate decision")
        receipt = payload.get("receipt") or {}
        execution = receipt.get("execution")
        assert_true(isinstance(execution, dict), "allowed execution summary missing")
        assert_true("rows" not in execution, "receipt execution summary contains raw rows")
        assert_true("preview_rows" not in execution, "receipt contains preview rows")
        rid = receipt.get("receipt_id")
        assert_true(isinstance(rid, str) and rid.startswith("tj_"), "receipt id missing")
        receipt_id = rid
        return "low-risk aggregate allowed; receipt contains summary but no result rows"

    check("safe_execution_boundary", safe_execute)

    def receipt_owner_visible() -> str:
        assert_true(receipt_id is not None, "safe execution did not produce a receipt")
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(KEY_OWNER_READ),
        )
        assert_equal(status, 200, "owner receipt lookup status")
        payload = parse_json(body)
        assert_equal(payload.get("receipt_id"), receipt_id, "owner receipt id")
        assert_equal(payload.get("identity", {}).get("principal_id"), "p5:owner", "receipt owner")
        return "same-principal reader can retrieve receipt"

    check("receipt_owner_visibility", receipt_owner_visible)

    def receipt_other_hidden() -> str:
        assert_true(receipt_id is not None, "safe execution did not produce a receipt")
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(KEY_BETA_READ),
        )
        assert_equal(status, 404, "cross-principal receipt lookup status")
        assert_equal(response_code(body), "RECEIPT_NOT_FOUND", "cross-principal receipt code")
        return "receipt existence hidden from another principal"

    check("receipt_cross_principal_isolation", receipt_other_hidden)

    def receipt_permissions() -> str:
        assert_true(receipt_id is not None, "safe execution did not produce a receipt")
        mode = docker_exec(
            container_name,
            "stat",
            "-c",
            "%a",
            f"/var/lib/toxicjoin/receipts/{receipt_id}.json",
        ).stdout.strip()
        assert_equal(mode, "600", "receipt file permissions")
        return "persisted receipt mode is 0600"

    check("receipt_file_permissions", receipt_permissions)

    def receipt_tamper_detected() -> str:
        assert_true(receipt_id is not None, "safe execution did not produce a receipt")
        code = (
            "import json; from pathlib import Path; "
            f"p=Path('/var/lib/toxicjoin/receipts/{receipt_id}.json'); "
            "d=json.loads(p.read_text()); d['task_purpose']='P5 TAMPERED'; "
            "p.write_text(json.dumps(d, sort_keys=True, indent=2)+'\\n')"
        )
        docker_exec(container_name, "python", "-c", code)
        status, _, body = client.call(
            "GET",
            f"/api/receipts/{receipt_id}",
            headers=bearer(KEY_OWNER_READ),
        )
        assert_equal(status, 409, "tampered receipt status")
        assert_equal(response_code(body), "RECEIPT_INTEGRITY_FAILURE", "tamper code")
        return "post-persistence receipt modification detected through public API"

    check("receipt_tamper_detection", receipt_tamper_detected)

    def unknown_receipt() -> str:
        status, _, body = client.call(
            "GET",
            "/api/receipts/tj_0000000000000000",
            headers=bearer(KEY_OWNER_READ),
        )
        assert_equal(status, 404, "unknown receipt status")
        assert_equal(response_code(body), "RECEIPT_NOT_FOUND", "unknown receipt code")
        return "unknown opaque receipt id returns stable 404"

    check("receipt_unknown_id", unknown_receipt)

    def malformed_receipt_id() -> str:
        status, _, body = client.call(
            "GET",
            "/api/receipts/not-a-valid-id",
            headers=bearer(KEY_OWNER_READ),
        )
        assert_equal(status, 422, "malformed receipt id status")
        decoded = body.decode("utf-8", errors="replace")
        assert_true("Traceback" not in decoded, "validation error leaked traceback")
        return "malformed receipt id rejected by route contract without traceback"

    check("receipt_id_contract", malformed_receipt_id)

    def rate_limit() -> str:
        for index in range(4):
            status, _, body = client.call("GET", "/api/ready", headers=bearer(KEY_RATE))
            assert_equal(status, 200, f"rate pre-limit request {index + 1}")
            assert_equal(parse_json(body).get("status"), "ok", "rate pre-limit readiness")
        status, headers, body = client.call("GET", "/api/ready", headers=bearer(KEY_RATE))
        assert_equal(status, 429, "rate-limit status")
        assert_equal(response_code(body), "RATE_LIMIT_EXCEEDED", "rate-limit code")
        assert_true(int(headers.get("retry-after", "0")) >= 1, "Retry-After missing")
        return "per-principal sliding-window rate limit enforced"

    check("rate_limit_enforced", rate_limit)

    def no_secret_or_traceback_leakage() -> str:
        corpus = "\n".join(client.observed_bodies)
        for key in ALL_KEYS:
            assert_true(key not in corpus, "API key material leaked in an HTTP response")
        assert_true("Traceback (most recent call last)" not in corpus, "traceback leaked")
        assert_true("/app/src/toxicjoin/" not in corpus, "internal source path leaked")
        return "observed HTTP responses contain no test credentials, traceback, or source paths"

    check("response_secret_and_traceback_leakage", no_secret_or_traceback_leakage)

    passed_count = sum(1 for item in results if item["passed"])
    failed = [item for item in results if not item["passed"]]
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment": "p5-exact-release-candidate-black-box",
        "target_pr": target_pr,
        "release_candidate_sha": release_candidate_sha,
        "test_count": len(results),
        "passed_count": passed_count,
        "failed_count": len(failed),
        "passed": not failed,
        "tests": results,
    }
    report["report_sha256"] = canonical_hash(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "tests"}, indent=2))
    return 0 if not failed else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-auth-json", action="store_true")
    parser.add_argument("--base-url")
    parser.add_argument("--container-name")
    parser.add_argument("--target-pr", type=int)
    parser.add_argument("--release-candidate-sha")
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.emit_auth_json:
        print(json.dumps(CREDENTIALS, separators=(",", ":")))
        return

    required = {
        "--base-url": args.base_url,
        "--container-name": args.container_name,
        "--target-pr": args.target_pr,
        "--release-candidate-sha": args.release_candidate_sha,
        "--output": args.output,
    }
    missing = [name for name, value in required.items() if value in (None, "")]
    if missing:
        parser.error("missing required arguments: " + ", ".join(missing))

    raise SystemExit(
        run_pentest(
            base_url=args.base_url,
            container_name=args.container_name,
            target_pr=args.target_pr,
            release_candidate_sha=args.release_candidate_sha,
            output=Path(args.output),
        )
    )


if __name__ == "__main__":
    main()
