from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from phase8_evidence_common import VerifiedCatalog, VerifiedObject, require_digest, sha256_bytes


def retrieve_object(
    *, catalog: VerifiedCatalog, digest: str, destination: Path
) -> VerifiedObject:
    digest = require_digest(digest, name="retrieval digest")
    matches = [item for item in catalog.objects if item.digest == digest]
    if len(matches) != 1:
        raise ValueError("retrieval digest must identify exactly one retained object")
    item = matches[0]
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        with item.path.open("rb") as source:
            shutil.copyfileobj(source, handle)
    temporary.replace(destination)
    if sha256_bytes(destination.read_bytes()) != item.digest:
        raise ValueError("retrieved object failed post-copy integrity verification")
    return item
