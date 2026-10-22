from abc import ABC
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Union, Dict, Sequence, Iterable

from charm.core.math.pairing import ZR

from mpvas.common import shamir, utils
from mpvas.common.element import Element, prod
from mpvas.common.message import Sigma, Sigma1, Sigma2, Sigma3, BaseMsg
from mpvas.common.protocol import Dealer, Aggregator, User, Verifier
from mpvas.common.state import log, pp
from mpvas.common.timer import Timer


class VerifierPlain(Verifier, ABC):
    """A verifier in plain mPVAS."""

    def _signing_set_of(self, round: Element, uid: int) -> Iterable[int]:
        """In plain mPVAS, the signing set consists of the next [pp.K] users, modulo [pp.N]."""
        return [(uid + it + 1) % pp.N for it in range(pp.K)]

    def _signing_set_size_of(self, round: Element, uid: int) -> int:
        """In plain mPVAS, this is simply [pp.K]."""
        return pp.K

    def _find_ek_index(self, round: Element, uid1: int, uid2: int) -> int:
        """
        In plain mPVAS, the 0th index is for user [uid1] itself, and the remaining `pp.K` indices are for the previous
        `pp.K` users.
        """
        return (pp.N + uid1 - uid2) % pp.N


class UserPlain(User, VerifierPlain):
    """A user for plain mPVAS."""

    @dataclass(frozen=True)
    class Params(User.Params, VerifierPlain.Params):
        sk: Element
        eks: List[Element]
        share: Element

    _sk: Element
    """Signature key."""
    _eks: List[Element]
    """List of "encryption" keys of this user, one for each other user."""
    _share: Element
    """Share of the signing key."""

    _inputs: Dict[Element, Element]
    """History of inputs sent to the aggregator."""
    _sigmas: Dict[Element, Element]
    """Complete final signatures created by this user."""

    def __init__(self, params: Params) -> None:
        """Initializes an mPVAS user."""

        User.__init__(self, params)
        VerifierPlain.__init__(self, params)

        self._sk = params.sk
        self._eks = params.eks
        self._share = params.share

        self._inputs = {}
        self._sigmas = {}

    def submit(self, round: Element, plain_value: Union[int, None] = None) -> None:
        if plain_value is None:
            plain_value = self.uid

        # Map to curve
        value = pp.group.init(ZR, plain_value)
        self._inputs[round] = value

        # Sign
        utils.log_progress("Sign progress", self.uid)
        with self.sign_timer:
            message: BaseMsg

            if pp.K == 0:
                sigma = (pp.H1(round) ** (self._eks[0])) * ((pp.H(round) ** self._sk * pp.g1**value) ** self._share)
                message = Sigma(self.uid, self.uid, round, sigma)
            else:
                sigma1 = (pp.H(round) ** self._sk) * pp.g1**value
                message = Sigma1(self.uid, self.uid, round, sigma1)

        # Send
        self._send(message)

    def sign_vector_k0(
        self, rounds: Sequence[Element], plain_values: Sequence[int]
    ) -> List[Element]:
        """Signs every coordinate using the exact K=0 mPVAS equation.

        Each coordinate uses a distinct round/domain element. Only algebraic
        user-key factors are reused across coordinates.
        """

        if pp.K != 0:
            raise ValueError("sign_vector_k0 requires K=0")
        if len(rounds) != len(plain_values):
            raise ValueError("round and plaintext vector lengths differ")

        with self.sign_timer:
            value_base = pp.g1 ** self._share
            sk_share = self._sk * self._share
            return [
                (pp.H1(round) ** self._eks[0])
                * (pp.H(round) ** sk_share)
                * (value_base ** pp.group.init(ZR, value))
                for round, value in zip(rounds, plain_values)
            ]

    def receive(self, message: BaseMsg) -> None:
        """Implements responses to all messages required for plain mPVAS."""

        if isinstance(message, Sigma1):
            sigma2 = self._add_secret_share(message.round, message.origin, message.payload)
            self._send(Sigma2(message.origin, self.uid, message.round, sigma2))

        elif isinstance(message, Sigma3):
            sigma = self._compute_final_signature(message.round, message.payload)
            self._send(Sigma(message.origin, self.uid, message.round, sigma))

        else:
            raise ValueError("Missing or invalid message type.")

    def _add_secret_share(self, round: Element, sender_uid: int, p_sigma: Element) -> Element:
        """Adds this user's secret share in the exponent of the given signature [p_sigma]."""

        with self.sign_timer:
            log.debug(
                f"User {self.uid}: Combining signature of user {sender_uid} with key "
                f"{self._find_ek_index(round, self.uid, sender_uid)}."
            )

            p_secret = shamir.partial_secret(self.uid + 1, self._share, sender_uid + 1)
            ek_ = self._eks[self._find_ek_index(round, self.uid, sender_uid)]
            return (pp.H1(round) ** ek_) * p_sigma**p_secret

    def _compute_final_signature(self, round: Element, sigma3: Element) -> Element:
        """Computes the final user signature by this user for the summed signature [sigma3] in the given [round]."""

        with self.sign_timer:
            sigma0 = (pp.H(round) ** self._sk) * (pp.g1 ** self._inputs[round])
            sigma = sigma3 * self._add_secret_share(round, self.uid, sigma0)

        self._sigmas[round] = sigma
        return sigma


class AggregatorPlain(Aggregator, VerifierPlain):
    """An aggregator for plain mPVAS."""

    @dataclass(frozen=True)
    class Params(Aggregator.Params, VerifierPlain.Params):
        """Combines parameters from both superclasses."""

        pass

    _sigmas1: Dict[Element, Dict[int, Element]]
    """Maps rounds to map of uid to initial signatures `sigma1`."""
    _sigmas2: Dict[Element, Dict[int, List[Element]]]
    """Maps rounds to map of uid to list of partial signatures `sigma2`."""
    _sigmas3: Dict[Element, Dict[int, Element]]
    """Maps rounds to map of uid to summed signatures `sigma3`."""
    _sigmas: Dict[Element, List[Element]]
    """Maps rounds to list of signatures `sigma`."""

    def __init__(self, params: Params) -> None:
        """Initializes an mPVAS aggregator."""

        Aggregator.__init__(self, params)
        VerifierPlain.__init__(self, params)

        self._sigmas1 = defaultdict(dict)
        self._sigmas2 = defaultdict(lambda: defaultdict(list))
        self._sigmas3 = defaultdict(dict)
        self._sigmas = defaultdict(list)

    def receive(self, message: BaseMsg) -> None:
        """Implements responses to all messages required for plain mPVAS."""

        if isinstance(message, Sigma1):
            round = message.round
            origin = message.origin
            self._sigmas1[round][origin] = message.payload

            signing_set = self._signing_set_of(round, origin)
            self._send(signing_set, message)

        elif isinstance(message, Sigma2):
            round = message.round
            origin = message.origin
            remaining = self._signing_set_size_of(round, origin) - len(self._sigmas2[round][origin])

            if remaining > 0:
                self._sigmas2[round][origin].append(message.payload)
            if remaining == 1:  # If true, remaining is now zero
                sigma3 = self._sum_secret_shares(round, origin)
                self._sigmas3[round][origin] = sigma3
                self._send(origin, Sigma3(origin, self.uid, round, sigma3))

        elif isinstance(message, Sigma):
            round = message.round
            remaining = pp.N - len(self._sigmas[round])

            if remaining > 0:
                self._sigmas[round].append(message.payload)
            if remaining == 1:  # If true, remaining is now zero
                self.signatures[round] = self._aggregate_sigs(round)

        else:
            raise ValueError(f"Missing or invalid message type '{message.type}'.")

    def _sum_secret_shares(self, round: Element, sender_uid: int) -> Element:
        """Combines partial signatures (`sigma2`) into a summed secret share (`sigma3`)."""

        with self.sign_timer:
            return prod(self._sigmas2[round][sender_uid])

    def _aggregate_sigs(self, round: Element) -> Element:
        """Aggregates final user signatures into an aggregated signature."""

        with self.sign_timer:
            return prod(self._sigmas[round])


class DealerPlain(Dealer):
    """A dealer for plain mPVAS."""

    def setup(self) -> Tuple[Sequence[User], Aggregator, Sequence[Verifier]]:
        with self.deal_timer:
            log.info("-" * 60)
            log.info("NEW PROTOCOL RUN!")
            log.info(f"SETUP PARAMETERS -> N: {pp.N}, K: {pp.K}")

            p, shares, sks, vk, eks = self._setup_basic_params()

            users = [UserPlain(UserPlain.Params(i, vk, sks[i], eks[i], shares[i])) for i in range(pp.N)]
            aggregator = AggregatorPlain(AggregatorPlain.Params(vk, users))

            return users, aggregator, [aggregator]

    def _setup_basic_params(
        self,
    ) -> Tuple[int, List[Element], List[Element], Tuple[Element, Element], List[List[Element]]]:
        """Creates basic parameters, as reused in various sub-implementations."""

        p = pp.group.order()
        shares = [pp.group.init(ZR, j) for _, j in shamir.share(int(self.sp.S), pp.K + 1, pp.N, int(p))]
        sks = pp.group.random(ZR, count=pp.N, seed=pp.rng.next())
        vk = (pp.g2 ** (self.sp.S * sum(sks)), pp.g2**self.sp.S)
        eks = list(pp.group.random(ZR, count=pp.N * (pp.K + 1), seed=pp.rng.next()))
        eks[-1] = -sum(eks[:-1])
        eks = [eks[n : n + pp.K + 1] for n in range(0, len(eks), pp.K + 1)]

        return p, shares, sks, vk, eks
