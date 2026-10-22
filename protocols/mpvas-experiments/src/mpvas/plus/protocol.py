from dataclasses import dataclass
from itertools import chain
from typing import Tuple, Iterable, Sequence

from charm.core.math.pairing import ZR

from mpvas.common import shamir
from mpvas.common.element import Element
from mpvas.common.protocol import Dealer
from mpvas.common.state import pp, log, sp
from mpvas.plain.protocol import AggregatorPlain, UserPlain, Verifier, VerifierPlain


class VerifierPlus(VerifierPlain):
    """Any party that participates in mPVAS+."""

    def _signing_set_of(self, round: Element, uid: int) -> Iterable[int]:
        """In mPVAS+, signing sets are chunked, so that the first `pp.K + 1` users are each other's signing set."""

        first_user_in_group, first_user_next_group = _first_and_last_user_in_group_of(uid)
        return chain(range(first_user_in_group, uid), range(uid + 1, first_user_next_group))

    def _signing_set_size_of(self, round: Element, uid: int) -> int:
        """In mPVAS+, all groups have the same size, except the last group."""

        if uid >= pp.N - pp.plus_last_group_size:
            return pp.plus_last_group_size - 1
        else:
            return pp.C - 1

    def _find_ek_index(self, round: Element, uid1: int, uid2: int) -> int:
        """Returns the index in the signing set."""

        first_user_in_group, _ = _first_and_last_user_in_group_of(uid1)
        return uid2 - first_user_in_group


class UserPlus(UserPlain, VerifierPlus):
    """A user in mPVAS+."""

    @dataclass(frozen=True)
    class Params(UserPlain.Params, VerifierPlus.Params):
        """Combines parameters from both superclasses."""

        pass

    def __init__(self, params: Params):
        """Initializes an mPVAS+ user."""

        UserPlain.__init__(self, params)
        VerifierPlus.__init__(self, params)

    def _add_secret_share(self, round: Element, sender_uid: int, p_sigma: Element) -> Element:
        """Overrides how secret shares are combined."""

        with self.sign_timer:
            first_user_in_group, first_user_next_group = _first_and_last_user_in_group_of(self.uid)
            p_secret = shamir.partial_secret_plus(
                self.uid + 1, self._share, first_user_in_group + 1, first_user_next_group + 1
            )
            ek_ = self._eks[self._find_ek_index(round, self.uid, sender_uid)]
            return (pp.H1(round) ** ek_) * (p_sigma**p_secret)


class AggregatorPlus(AggregatorPlain, VerifierPlus):
    """An aggregator in mPVAS+."""

    @dataclass(frozen=True)
    class Params(AggregatorPlain.Params, VerifierPlus.Params):
        """Combines parameters from both superclasses."""

        pass

    def __init__(self, params: Params):
        """Initializes an mPVAS+ aggregator."""

        AggregatorPlain.__init__(self, params)
        VerifierPlus.__init__(self, params)


class DealerPlus(Dealer):
    """A dealer in mPVAS+."""

    def setup(self) -> Tuple[Sequence[UserPlus], AggregatorPlus, Sequence[Verifier]]:
        with self.deal_timer:
            log.info("-" * 60)
            log.info("NEW PROTOCOL RUN!")
            log.info(f"SETUP PARAMETERS -> N: {pp.N}, C: {pp.C}")

            # Maps group number to size
            group_size = lambda x: pp.C + (pp.plus_remainder if x == pp.plus_num_groups - 1 else 0)

            # Create parameters
            p = pp.group.order()
            shares = [
                pp.group.init(ZR, j)
                for i in range(pp.plus_num_groups)
                for _, j in shamir.share(int(sp.S), group_size(i), group_size(i), int(p))
            ]
            sks = pp.group.random(ZR, count=pp.N, seed=pp.rng.next())
            vk = (pp.g2 ** (sp.S * sum(sks)), pp.g2**sp.S)
            eks = list(
                pp.group.random(ZR, count=((pp.N - pp.plus_last_group_size) * pp.C + pp.plus_last_group_size**2))
            )
            eks[-1] = -sum(eks[:-1])
            eks = [eks[n : n + pp.C] for n in range(0, len(eks) - (pp.plus_last_group_size**2), pp.C)] + [
                eks[-pp.plus_last_group_size**2 :][n : n + pp.plus_last_group_size]
                for n in range(0, pp.plus_last_group_size**2, pp.plus_last_group_size)
            ]

            users = [UserPlus(UserPlus.Params(i, vk, sks[i], eks[i], shares[i])) for i in range(pp.N)]
            aggregator = AggregatorPlus(AggregatorPlus.Params(vk, users))

            return users, aggregator, [aggregator]


def _first_and_last_user_in_group_of(uid: int) -> Tuple[int, int]:
    """
    Returns the uid of the first user in the group of user [uid], and the uid of the first user in the group directly
    after the group of user [uid].

    Essentially, the returned tuple gives the bounds for which users are in the group of user [uid], with the first
    returned number the lower bound (inclusive) and the second number the upper bound (exclusive).
    """

    group_idx = uid // pp.C

    if uid >= pp.N - pp.plus_remainder:
        first_user_in_group = (uid - pp.plus_remainder) // pp.C * pp.C
    else:
        first_user_in_group = uid // pp.C * pp.C

    if group_idx < pp.plus_num_groups - 1:
        first_user_next_group = first_user_in_group + pp.C
    else:
        first_user_next_group = first_user_in_group + pp.plus_last_group_size

    return first_user_in_group, first_user_next_group
