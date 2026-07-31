"""Bootstrap and index DataHub document tools for Phase 5."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "report_sha256"}
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    import httpx
    from datahub.sdk import DataHubClient, Document

    document_id = "toxicjoin-phase5-document-bootstrap"
    title = "ToxicJoin Phase 5 MCP document bootstrap"
    document = Document.create_document(
        id=document_id,
        title=title,
        text=(
            "Bootstrap document used only to ensure that DataHub's official MCP "
            "document-content tools are registered before the exact-source Phase 5 protocol."
        ),
        subtype="Context",
        show_in_global_context=True,
    )
    DataHubClient.from_env().entities.upsert(document)

    query = """
    query BootstrapDocumentSearch($query: String!) {
      searchAcrossEntities(
        input: {query: $query, count: 1, start: 0, types: [DOCUMENT]}
      ) { total }
    }
    """
    attempts = 0
    for attempts in range(1, 61):
        response = httpx.post(
            "http://127.0.0.1:8080/api/graphql",
            json={"query": query, "variables": {"query": title}},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            raise RuntimeError("DataHub bootstrap GraphQL query failed")
        if payload["data"]["searchAcrossEntities"]["total"] >= 1:
            break
        time.sleep(2)
    else:
        raise RuntimeError("DataHub bootstrap document indexing timed out")

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "created_at": _now(),
        "document_urn": f"urn:li:document:{document_id}",
        "index_attempts": attempts,
        "report_sha256": "0" * 64,
    }
    report["report_sha256"] = _hash(report)
    _write(Path(args.output), report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
