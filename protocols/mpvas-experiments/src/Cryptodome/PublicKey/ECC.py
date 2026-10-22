from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EccKey:
    curve: str = "Ed25519"

    def public_key(self) -> "EccKey":
        return self


def generate(curve: str = "Ed25519") -> EccKey:
    return EccKey(curve=curve)