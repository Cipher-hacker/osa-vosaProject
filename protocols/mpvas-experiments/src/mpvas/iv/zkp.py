from typing import NamedTuple

from charm.core.math.pairing import ZR
from charm.toolbox.hash_module import Hash
from charm.toolbox.pairinggroup import PairingGroup

from mpvas.common.element import Element
from mpvas.common.state import pp


class ZkpEqProof(NamedTuple):
    """A non-interactive zero-knowledge proof of equality."""

    t1: Element
    t2: Element
    s1: Element
    s2: Element
    s3: Element


class ZkpEQ:
    @staticmethod
    def prove(
        group: PairingGroup,
        g1: Element,
        g2: Element,
        h1: Element,
        h2: Element,
        x: Element,
        y: Element,
        z: Element,
    ) -> ZkpEqProof:
        """Creates a zero-knowledge proof of equality between commitments. See the paper for details."""

        S = g1**x * h1**y
        T = g2**x * h2**z
        r1, r2, r3 = group.random(ZR, count=3, seed=pp.rng.next())
        t1 = g1**r1 * h1**r2
        t2 = g2**r1 * h2**r3
        c = Hash(group).hashToZr(S, T, g1, g2, h1, h2, t1, t2)
        s1 = r1 + x * c
        s2 = r2 + y * c
        s3 = r3 + z * c

        return ZkpEqProof(t1, t2, s1, s2, s3)

    @staticmethod
    def verify(
        group: PairingGroup,
        S: Element,
        T: Element,
        g1: Element,
        g2: Element,
        h1: Element,
        h2: Element,
        proof: ZkpEqProof,
    ) -> bool:
        """Verifies a zero-knowledge proof of equality between commitments. See the paper for details."""

        t1, t2, s1, s2, s3 = proof
        c = Hash(group).hashToZr(S, T, g1, g2, h1, h2, t1, t2)
        fst_eq = g1**s1 * h1**s2 == S**c * t1
        snd_eq = g2**s1 * h2**s3 == T**c * t2

        return fst_eq and snd_eq
