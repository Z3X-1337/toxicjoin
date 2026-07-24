"""Execution-output budgets for bounded result release."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from pydantic import Field, model_validator

from toxicjoin.models import StrictModel


MAX_CELL_BYTES_ENV = "TOXICJOIN_MAX_CELL_BYTES"
MAX_RESULT_BYTES_ENV = "TOXICJOIN_MAX_RESULT_BYTES"


class ExecutionOutputLimits(StrictModel):
    """Bound serialized execution cells and row payloads before release."""

    max_cell_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    max_result_bytes: int = Field(default=256 * 1024, ge=4096, le=4 * 1024 * 1024)

    @model_validator(mode="after")
    def cell_must_fit_result(self) -> "ExecutionOutputLimits":
        if self.max_cell_bytes > self.max_result_bytes:
            raise ValueError("max_cell_bytes cannot exceed max_result_bytes")
        return self

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "ExecutionOutputLimits":
        source: Mapping[str, str] = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        mapping = {
            MAX_CELL_BYTES_ENV: "max_cell_bytes",
            MAX_RESULT_BYTES_ENV: "max_result_bytes",
        }
        for env_name, field_name in mapping.items():
            raw = source.get(env_name)
            if raw is None:
                continue
            try:
                values[field_name] = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{env_name} must be an integer") from exc
        try:
            return cls.model_validate(values)
        except Exception as exc:
            raise ValueError("execution output limit configuration is invalid") from exc
