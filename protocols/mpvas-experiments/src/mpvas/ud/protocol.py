from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Union, Dict, Set, Sequence, Iterable

from Cryptodome.PublicKey import ECC
from charm.core.math.pairing import ZR, pair

from mpvas.common import shamir, utils
from mpvas.common.element import Element, prod
from mpvas.common.message import Dropout, Sigma, Sigma1, BaseMsg
from mpvas.common.state import pp, log
from mpvas.plain.protocol import AggregatorPlain, UserPlain, Verifier, VerifierPlain, DealerPlain


class VerifierUD(VerifierPlain):
    """A verifier in mPVAS-UD."""

    @dataclass(frozen=True)
    class Params(Verifier.Params):
        dpks: List[ECC.EccKey]
        EK: List[Element]

    _dpks: List[ECC.EccKey]
    """Public keys (unused)."""
    _EK: List[Element]
    """Dropout key for each user."""

    _dropped_out_users: Dict[Element, Set[int]]
    """Maps rounds to the set of users that dropped out"""
    _dropped_out_rks: Dict[Element, List[Element]]
    """Maps rounds to missing signing keys."""

    def __init__(self, params: Params) -> None:
        """Initializes an mPVAS-UD verifier."""

        super().__init__(params)

        self._dpks = params.dpks
        self._EK = params.EK

        self._dropped_out_users = defaultdict(set)
        self._dropped_out_rks = defaultdict(list)

    def register_dropout(self, message: Dropout) -> None:
        """Records the fact that a [User] has dropped out, as described in the given [message]."""

        # start = time.time()
        # hashed_msg = SHA512.new(str(recovery_msg.origin).encode() + str(recovery_msg.round).encode() + group.serialize(recovery_msg.payload.rk_it))
        # try:
        #     eddsa.new(self.dpks[recovery_msg.origin], 'rfc8032').verify(hashed_msg, recovery_msg.payload.signature)
        # except ValueError:
        #     log.info("Verifier: Invalid signature")
        # self.time_ver += time.time() - start

        self._dropped_out_users[message.round].add(message.origin)
        self._dropped_out_rks[message.round].append(message.payload.rk_it)

    def verify(self, round: Element, my_sum_plain: int, signature: Element) -> bool:
        """Modifies the verification function to use the dropout key material."""

        my_sum = pp.group.init(ZR, my_sum_plain)
        with self.verify_timer:
            rk_prod = prod(self._dropped_out_rks[round])
            EK_prod = prod(g2_ek for i, g2_ek in enumerate(self._EK) if i not in self._dropped_out_users[round])

            left = pair(pp.g1**my_sum, self._vk[1]) * pair(pp.H(round), self._vk[0]) * rk_prod
            right = pair(signature, pp.g2) / pair(pp.H1(round), EK_prod)

            is_valid = left == right

        return is_valid

    def verify_vector_k0(
        self,
        rounds: Sequence[Element],
        plain_sums: Sequence[int],
        signatures: Sequence[Element],
        dropped_user_ids: Set[int],
        recovery_products: Sequence[Element],
    ) -> bool:
        """Verifies domain-separated scalar instances with real pairings."""

        if pp.K != 0:
            raise ValueError("verify_vector_k0 requires K=0")
        if not (
            len(rounds)
            == len(plain_sums)
            == len(signatures)
            == len(recovery_products)
        ):
            raise ValueError("mPVAS vector lengths differ")

        with self.verify_timer:
            EK_prod = prod(
                g2_ek for i, g2_ek in enumerate(self._EK) if i not in dropped_user_ids
            )
            sum_pair_base = pair(pp.g1, self._vk[1])

            for round, plain_sum, signature, recovery_product in zip(
                rounds, plain_sums, signatures, recovery_products
            ):
                left = (
                    (sum_pair_base ** pp.group.init(ZR, plain_sum))
                    * pair(pp.H(round), self._vk[0])
                    * recovery_product
                )
                right = pair(signature, pp.g2) / pair(pp.H1(round), EK_prod)
                if left != right:
                    return False
        return True

    def _signing_set_of(self, round: Element, uid: int) -> Iterable[int]:
        """Similar to plain mPVAS, but skips over the users that dropped out."""

        return utils.next_k(uid, pp.K, pp.N, ignore=self._dropped_out_users[round])

    def _find_ek_index(self, round: Element, uid1: int, uid2: int) -> int:
        """Similar to plain mPVAS, but skips over the users that dropped out."""

        skip = self._dropped_out_users[round]

        idx = 0
        itr = uid2
        while itr != uid1:
            idx += 1

            itr = (itr + 1) % pp.N
            while itr in skip:
                itr = (itr + 1) % pp.N

        return idx


class UserUD(UserPlain, VerifierUD):
    """A user in mPVAS-UD."""

    @dataclass(frozen=True)
    class Params(UserPlain.Params, VerifierUD.Params):
        dsk: Union[ECC.EccKey, None]

    _dsk: Union[ECC.EccKey, None]
    """Private key (unused)."""

    def __init__(self, params: Params):
        """Initializes an mPVAS-UD user."""

        UserPlain.__init__(self, params)
        VerifierUD.__init__(self, params)

        self._dsk = params.dsk

    def receive(self, message: BaseMsg) -> None:
        """Adds handling of [Dropout] messages."""

        if isinstance(message, Dropout):
            self.register_dropout(message)
        else:
            super().receive(message)

    def _add_secret_share(self, round: Element, sender_uid: int, p_sigma: Element) -> Element:
        """Calculates [p_secret] differently to account for the users that dropped out."""

        with self.sign_timer:
            p_secret = shamir.partial_secret(self.uid + 1, self._share, sender_uid + 1, self._dropped_out_users[round])
            ek_ = self._eks[self._find_ek_index(round, self.uid, sender_uid)]
            return (pp.H1(round) ** ek_) * p_sigma**p_secret


class UserUDDropsOut(UserUD):
    """A user in mPVAS-UD that drops out of every round."""

    def submit(self, round: Element, plain_value: Union[int, None] = None) -> None:
        """Drops out after sending necessary recovery material."""

        log.info(f"User {self.uid}: Dropping out.")

        self._send(self.prepare_dropout(round))

    def prepare_dropout(self, round: Element) -> Dropout:
        """Creates the real recovery message without choosing a transport."""

        with self.sign_timer:
            rk_it = pair(pp.H(round) ** (-self._sk), self._vk[1])
            # hashed_msg = SHA512.new(str(self.uid).encode() + str(t).encode() + group.serialize(rk_it))
            # signature = eddsa.new(self.dsk, 'rfc8032').sign(hashed_msg)

        return Dropout(self.uid, self.uid, round, Dropout.Recovery(rk_it))

    def prepare_dropout_vector(self, rounds: Sequence[Element]) -> List[Element]:
        """Creates one real domain-separated recovery value per coordinate."""

        with self.sign_timer:
            return [pair(pp.H(round) ** (-self._sk), self._vk[1]) for round in rounds]

    def receive(self, message: BaseMsg) -> None:
        """Does nothing, since the user has dropped out."""
        pass


class AggregatorUD(AggregatorPlain, VerifierUD):
    """An aggregator in mPVAS-UD."""

    @dataclass(frozen=True)
    class Params(AggregatorPlain.Params, VerifierUD.Params):
        """Combines parameters from both superclasses."""

        pass

    def __init__(self, params: Params) -> None:
        """Initializes an mPVAS-UD aggregator."""

        AggregatorPlain.__init__(self, params)
        VerifierUD.__init__(self, params)

    def receive(self, message: BaseMsg) -> None:
        """Adds support for [Dropout] messages and alters handling of [Sigma1] and [Sigma] messages."""

        if isinstance(message, Dropout):
            self.register_dropout(message)
            self._send([it.uid for it in self.users], message)

        elif isinstance(message, Sigma1):
            round = message.round
            origin = message.origin

            self._sigmas1[round][origin] = message.payload
            self._send(self._signing_set_of(round, origin), message)

        elif isinstance(message, Sigma):
            round = message.round

            remaining = pp.N - len(self._dropped_out_users[round]) - len(self._sigmas[round])
            if remaining > 0:
                self._sigmas[round].append(message.payload)
            if remaining == 1:  # If true, remaining is now zero
                self.signatures[round] = self._aggregate_sigs(round)

        else:
            super().receive(message)


class DealerUD(DealerPlain):
    """A dealer in mPVAS-UD."""

    def setup(self) -> Tuple[Sequence[UserUD], AggregatorUD, Sequence[VerifierUD]]:
        with self.deal_timer:
            log.info("-" * 60)
            log.info("NEW PROTOCOL RUN!")
            log.info(f"SETUP PARAMETERS -> N: {pp.N}, K: {pp.K}, Dropouts: {pp.num_dropouts}")

            # Create regular parameters
            p, shares, sks, vk, eks = self._setup_basic_params()
            EK = [prod(pp.g2**it for it in ek) for ek in eks]

            # Create signing keys
            # dsks = [ECC.generate(curve="Ed25519") for _ in range(pp.N)]
            # dpks = [it.public_key() for it in dsks]

            # Create parties
            users = []
            for i in range(pp.N):
                # Dropped-out users come first, so that they announce their departure before the round really starts
                params = UserUD.Params(i, vk, [], EK, sks[i], eks[i], shares[i], None)
                users.append(UserUDDropsOut(params) if i < pp.num_dropouts else UserUD(params))
            aggregator = AggregatorUD(AggregatorUD.Params(vk, [], EK, users))

            # Return parties
            log.info(
                f"Users {[i for i, user in enumerate(users) if isinstance(user, UserUDDropsOut)]} will drop out of "
                f"the protocol."
            )
            return users, aggregator, [aggregator]
