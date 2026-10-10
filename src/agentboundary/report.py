"""Result types shared by the envelope verifier and the offline verifier CLI.

A verifier must never report a property it did not check. Every check
therefore carries one of three states, and ``not_checked`` always says why.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Status = Literal["pass", "fail", "not_checked"]


@dataclass(frozen=True)
class Check:
    """One verification step.

    ``name`` identifies the step (``cose.signature``, ``receipt_hash``, ...).
    ``code`` is a stable failure identifier, set when ``status == "fail"``.
    """

    name: str
    status: Status
    detail: str
    code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"check": self.name, "status": self.status, "detail": self.detail}
        if self.code is not None:
            out["code"] = self.code
        return out


def passed(name: str, detail: str) -> Check:
    return Check(name, "pass", detail)


def failed(name: str, code: str, detail: str) -> Check:
    return Check(name, "fail", detail, code)


def not_checked(name: str, detail: str) -> Check:
    return Check(name, "not_checked", detail)
