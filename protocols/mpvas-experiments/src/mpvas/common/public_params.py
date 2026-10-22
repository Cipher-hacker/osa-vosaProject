import datetime
from argparse import Namespace
from dataclasses import dataclass
from logging import Logger
from typing import Callable, Any, Tuple

from charm.core.math.pairing import G1, G2, GT, ZR
from charm.toolbox.pairinggroup import PairingGroup

from mpvas.common.element import Element
from mpvas.common.enums import Protocol
from mpvas.common.simple_random import SimpleRandom
from mpvas.plus.prob import find_c


@dataclass(frozen=True)
class PublicParams:
    """Public parameters accessible to all parties participating in an instance of mPVAS."""

    protocol: Protocol
    """Protocol type."""
    rng: SimpleRandom
    """Source of randomness."""
    timestamp: str
    """Timestamp of protocol start."""

    N: int
    """Number of users."""
    K: int
    """Number of malicious users."""
    ratio_malicious: float
    """Ratio of malicious users."""
    C: int
    """Group size."""
    num_dropouts: int
    """Maximum number of users who may drop out; may be non-zero only for mPVAS-UD."""

    group: PairingGroup
    """Pairing group to use for signatures and hashes."""
    g1: Element
    """Generator 1 of the pairing group, for signatures."""
    g2: Element
    """Generator 2 of the pairing group, for signatures."""
    gt: Element
    """Generator 3 of the pairing group, for signatures."""
    h1: Element
    """Generator 1 of the pairing group, for hashes. (Generator 2 is not used.)"""
    ht: Element
    """Generator 3 of the pairing group, for hashes. (Generator 2 is not used.)"""
    H: Callable[[Any], Element]
    """
    Hashes the input to an element of the [group], used in initial signatures as a "blinding factor".

    [H] and [H1] are separate hash functions to ensure that exponents cannot move freely between them.
    """
    H1: Callable[[Any], Element]
    """
    Hashes the input to an element of the [group], used after the initial signature.

    [H] and [H1] are separate hash functions to ensure that exponents cannot move freely between them.
    """

    plus_num_groups: int
    """For mPVAS+, the number of groups."""
    plus_remainder: int
    """For mPVAS+, the number of users that cannot fill an entire group."""
    plus_last_group_size: int
    """For mPVAS+, the size of the last group."""


@dataclass(frozen=True)
class SecretParams:
    """The secret parameters known only to the [Dealer]."""

    S: Element
    """The full signing key."""


def parse_params(log: Logger, args: Namespace) -> Tuple[PublicParams, SecretParams]:
    """Creates the parameters (public and private) for a run of the mPVAS family of protocols."""

    N = args.n
    if args.protocol == Protocol.PLUS:
        C = args.c if args.c is not None else find_c(log, N, args.k)
        K = C - 1
    else:
        K = args.k
        C = K + 1

    group = PairingGroup("MNT224")
    rng = SimpleRandom(args.seed)

    pp = PublicParams(
        # General
        protocol=args.protocol,
        rng=rng,
        timestamp=datetime.datetime.now().isoformat(),
        # Users
        N=N,
        K=K,
        ratio_malicious=args.m,
        C=C,
        num_dropouts=args.num_dropouts,
        # Elliptic curves
        group=group,
        g1=group.random(G1, seed=rng.next()),
        g2=group.random(G2, seed=rng.next()),
        gt=group.random(GT, seed=rng.next()),
        h1=group.random(G1, seed=rng.next()),
        ht=group.random(GT, seed=rng.next()),
        H=lambda it: group.hash(it, type=G1),
        H1=lambda it: group.hash(group.hash(it, type=G1), type=G1),
        # mPVAS+
        plus_num_groups=N // C,
        plus_remainder=N % C,
        plus_last_group_size=C + (N % C),
    )

    # Not public!
    sp = SecretParams(S=group.init(ZR, 5380514837702922472717381508437893805221160843969090763906940581649246440121))

    # Return values
    return pp, sp
