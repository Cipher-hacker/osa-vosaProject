from __future__ import annotations

from typing import Any

from charm.core.math.pairing import ZR
from charm.toolbox.pairinggroup import PairingGroup


class Hash:
    def __init__(self, pairingElement: PairingGroup) -> None:
        self.group = pairingElement

    def hashToZr(self, *args: Any):
        return self.group.hash(*args, type=ZR)