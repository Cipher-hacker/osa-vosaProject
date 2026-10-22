from abc import ABC
from dataclasses import dataclass
from typing import List, Tuple, Sequence, Set

from charm.core.math.pairing import ZR, G1, pair

from mpvas.common import shamir, state
from mpvas.common.element import Element
from mpvas.common.message import ProofReq, ProofRes, Report, Sigma, Sigma3, BaseMsg
from mpvas.common.state import pp, log, sp
from mpvas.iv.zkp import ZkpEQ
from mpvas.plain.protocol import UserPlain, AggregatorPlain, Verifier, DealerPlain


class VerifierIV(Verifier, ABC):
    """
    A verifier in mPVAS-IV.

    A [VerifierIV] cannot detect malicious users because that is an interactive process. Instead, to do so, one use an
    [AggregatorIV] instead.
    """

    def _find_ek_index(self, round: Element, uid1: int, uid2: int) -> int:
        """Calculates the key index for mPVAS-IV."""

        if uid1 in range(0, pp.K):
            if uid2 in range(0, pp.K):
                return uid2
            else:
                return uid2 - (pp.N - pp.K) + 1
        else:
            return uid2 - (uid1 - pp.K)


class UserIV(UserPlain, VerifierIV, ABC):
    """A user in mPVAS-IV."""

    @dataclass(frozen=True)
    class Params(UserPlain.Params, VerifierIV.Params):
        r: Element
        EK: List[List[Element]]

    _r: Element
    """The blinding exponent used in `SK` to hide the signing key from the aggregator."""
    _EK: List[List[Element]]
    """Exponentiated "encryption" keys of all users. """

    def __init__(self, params: Params) -> None:
        """Initializes an mPVAS-IV user."""

        UserPlain.__init__(self, params)
        VerifierIV.__init__(self, params)

        self._r = params.r
        self._EK = params.EK

    def receive(self, message: BaseMsg) -> None:
        """Adds handling for [ProofReq]s and changes how [Sigma3] is handled."""

        if isinstance(message, Sigma3):
            sigma = self._compute_final_signature(message.round, message.payload)

            if sigma is not None:
                self._send(Sigma(message.origin, self.uid, message.round, sigma))

        elif isinstance(message, ProofReq):
            round = message.round
            self._send(ProofRes(message.origin, self.uid, round, self._make_proofs(round)))

        else:
            super().receive(message)

    def _compute_final_signature(self, round: Element, sigma3: Element) -> Element:
        """Computes the user's final signature."""

        with self.sign_timer:
            sigma0 = pp.H(round) ** self._sk * pp.g1 ** self._inputs[round]
            sigma = sigma3 * self._add_secret_share(round, self.uid, sigma0)
            sig_valid = self._verify_user_sig(round, sigma)

        if not sig_valid:
            log.info(f"User {self.uid}: Invalid final signature detected, reporting to aggregator.")
            state.tampered_now = False
            self._send(Report(self.uid, self.uid, round))

        return sigma

    def _verify_user_sig(self, round: Element, sigma: Element) -> bool:
        """Validates the final user signature to see if another user tampered with it."""

        with self.sign_timer:
            part1 = pair(pp.H1(round), self._compute_masking_exponents(round))
            part2 = pair(pp.H(round) ** self._sk, self._vk[1])
            part3 = pair(pp.g1 ** self._inputs[round], self._vk[1])

            return part1 * part2 * part3 == pair(sigma, pp.g2)

    def _compute_masking_exponents(self, round: Element) -> Element:
        """Computes the masking components that other users should have added (hidden under exponentiation)."""

        patch = self._EK[self.uid][self._find_ek_index(round, self.uid, self.uid)]

        for uid in self._signing_set_of(round, self.uid):
            patch *= self._EK[uid][self._find_ek_index(round, uid, self.uid)]

        return patch

    def _make_proofs(self, round: Element) -> ProofRes.Proofs:
        """Creates zero-knowledge proofs to prove that this user did not tamper with signatures."""

        with self.sign_timer:
            r = pp.group.random(ZR)
            x_comm = pp.h1**r * pp.g1 ** self._inputs[round]

            proof_eq_x_comm = ZkpEQ.prove(
                group=pp.group,
                g1=pair(pp.g1, pp.g2),
                g2=pp.g1,
                h1=pair(pp.H(round), pp.g2),
                h2=pp.h1,
                x=self._inputs[round],
                y=self._sk,
                z=r,
            )

            proof_eq_sk = ZkpEQ.prove(
                group=pp.group,
                g1=pair(pp.H(round), pp.g2),
                g2=pp.gt,
                h1=pair(pp.g1, pp.g2),
                h2=pp.ht,
                x=self._sk,
                y=self._inputs[round],
                z=self._r,
            )

        return ProofRes.Proofs(x_comm, proof_eq_x_comm, proof_eq_sk)


class UserIVTamperPartial(UserIV):
    """A user in mPVAS-IV that tampers with the partial signature."""

    def _add_secret_share(self, round: Element, sender_uid: int, p_sigma: Element) -> Element:
        """Either acts normally, or acts malicious by returning a random value instead."""

        if sender_uid == self.uid or state.num_partial_tampers_left <= 0 or state.tampered_now == True:
            return super()._add_secret_share(round, sender_uid, p_sigma)

        log.debug(f"User {self.uid}: Sending a random value instead of a partial signature.")
        state.num_partial_tampers_left -= 1
        state.tampered_now = True
        state.tampered_ever = True

        with self.sign_timer:
            return pp.group.random(G1, seed=pp.rng.next())


class UserIVTamperFinal(UserIV):
    """A user in mPVAS-IV that tampers with the final signature."""

    def _compute_final_signature(self, round: Element, sigma3: Element) -> Element:
        """Instead of computing a final user signature, always returns a random value."""

        log.debug(f"User {self.uid}: Sending a random value instead of a final signature.")
        state.tampered_now = True
        state.tampered_ever = True

        with self.sign_timer:
            return pp.group.random(G1, seed=pp.rng.next())


class AggregatorIV(AggregatorPlain, VerifierIV):
    """An aggregator in mPVAS-IV."""

    @dataclass(frozen=True)
    class Params(AggregatorPlain.Params, VerifierIV.Params):
        SS: List[Element]
        SK: List[Element]
        EK: List[List[Element]]
        EKS: List[List[Element]]
        v: Element

    _SS: List[Element]
    """Exponentiated secret shares of all users."""
    _SK: List[Element]
    """Blinded signature keys of all users."""
    _EK: List[List[Element]]
    """Exponentiated "encryption" keys of all users. """
    _EKS: List[List[Element]]
    """Exponentiated inverted "encryption" keys of all users."""
    _v: Element
    """Exponentiated inverted signature key."""

    _reported_users: Set[int]
    """The users that have been detected as tampering with signatures."""

    def __init__(self, params: Params):
        """Initializes an mPVAS-IV aggregator."""

        AggregatorPlain.__init__(self, params)
        VerifierIV.__init__(self, params)

        self._SS = params.SS
        self._SK = params.SK
        self._EKS = params.EKS
        self._EK = params.EK
        self._v = params.v

        self._reported_users = set()

    def receive(self, message: BaseMsg) -> None:
        """Adds handling for [Report]s and [ProofRes]'s."""

        if isinstance(message, Report):
            self._detect_partial(message.round, message.origin)

        elif isinstance(message, ProofRes):
            self._detect_final(message.round, message.sender, message.payload)

        else:
            super().receive(message)

    def verify(self, round: Element, my_sum: int, signature: Element) -> bool:
        """Adds detection of malicious users."""

        if len(self._reported_users) > 0:
            log.info(f"Aggr: Verification failed because these users were reported: {sorted(self._reported_users)}.")
            return False

        is_valid = super().verify(round, my_sum, self.signatures[round])
        if not is_valid:
            self._send([it.uid for it in self.users], ProofReq(self.uid, self.uid, round))
            log.info(
                f"Aggr: Verification failed because these users failed to prove correctness: "
                f"{sorted(self._reported_users)}."
            )

        return is_valid

    def _detect_partial(self, round: Element, origin: int) -> None:
        """
        Validates the partial signatures of all users after receiving user [origin] reported their final signature had
        been tampered with.
        """

        with self.sign_timer:
            sigma1 = self._sigmas1[round][origin]
            h1t = pp.H1(round)

            for idx, uid in enumerate(self._signing_set_of(round, origin)):
                coeff_ui = shamir.lagrange_coeff(uid + 1, origin + 1)
                g2_s_ui = self._SS[uid] ** coeff_ui
                ek_index = self._find_ek_index(round, uid, origin)
                g2_ek = self._EK[uid][ek_index]
                sigma2_star = pair(h1t, g2_ek) * pair(sigma1, g2_s_ui)

                if sigma2_star == pair(self._sigmas2[round][origin][idx], pp.g2):
                    log.debug(f"Aggr: User {uid} was not malicious.")
                else:
                    log.info(f"Aggr: User {uid} tampered with the partial signature of user {origin}.")
                    self._reported_users.add(uid)

    def _detect_final(self, round: Element, sender: int, proofs: ProofRes.Proofs) -> None:
        """Validates the received proofs, and records the [sender] as malicious if the proof does not check out."""

        final_sig_patch = self._compute_final_sig_patch(round, sender)

        with self.sign_timer:
            S = pair(self._sigmas[round][sender], self._v) / (pair(pp.H1(round), final_sig_patch))
            f1 = pair(pp.H(round), pp.g2)
            f2 = pair(pp.g1, pp.g2)

            valid_sig = ZkpEQ.verify(
                group=pp.group,
                S=S,
                T=self._SK[sender],
                g1=f1,
                g2=pp.gt,
                h1=f2,
                h2=pp.ht,
                proof=proofs.proof_eq_sk,
            )
            valid_bp_comm = ZkpEQ.verify(
                group=pp.group,
                S=S,
                T=proofs.x_comm,
                g1=f2,
                g2=pp.g1,
                h1=f1,
                h2=pp.h1,
                proof=proofs.proof_eq_x_comm,
            )

        if valid_sig and valid_bp_comm:
            log.debug(f"Aggr: User {sender} was not malicious.")
        else:
            self._reported_users.add(sender)
            log.info(f"Aggr: User {sender} tampered with its final signature!")

    def _compute_final_sig_patch(self, round: Element, origin: int) -> Element:
        """Computes the "patch" that removes the "encryption" keys from the signature when multiplied with it."""

        with self.sign_timer:
            ek_index = self._find_ek_index(round, origin, origin)
            patch = self._EKS[origin][ek_index]

            for uid in self._signing_set_of(round, origin):
                ek_index = self._find_ek_index(round, uid, origin)
                patch *= self._EKS[uid][ek_index]

        return patch


class DealerIV(DealerPlain, ABC):
    """A dealer in mPVAS-IV."""

    def _setup_iv_params(self) -> Tuple[
        int,
        List[Element],
        List[Element],
        Tuple[Element, Element],
        List[List[Element]],
        List[Element],
        List[Element],
        List[Element],
        List[List[Element]],
        List[List[Element]],
        Element,
    ]:
        """Creates basic parameters, as reused in various sub-implementations."""

        # Generic
        p, shares, sks, vk, eks = self._setup_basic_params()

        # User-specific
        rs1 = pp.group.random(ZR, count=pp.N, seed=pp.rng.next())

        # Aggregator-specific
        SS = [pp.g2**share for share in shares]
        SK = [pp.ht ** (rs1[i]) * pp.gt ** (sks[i]) for i in range(pp.N)]
        EK = [[pp.g2**ek_ for ek_ in eks_] for eks_ in eks]
        EKS = [[pp.g2 ** (ek_ / sp.S) for ek_ in eks_] for eks_ in eks]
        v = pp.g2 ** (1 / sp.S)

        return p, shares, sks, vk, eks, rs1, SS, SK, EK, EKS, v


class DealerIVTamperPartial(DealerIV):
    """A dealer in mPVAS-IV that includes users who tamper with partial signatures."""

    def setup(self) -> Tuple[Sequence[UserIV], AggregatorIV, Sequence[Verifier]]:
        with self.deal_timer:
            log.info("-" * 60)
            log.info("NEW PROTOCOL RUN!")
            log.info(f"SETUP PARAMETERS -> N: {pp.N}, K: {pp.K}")

            # Generate parameters
            p, shares, sks, vk, eks, r, SS, SK, EK, EKS, v = self._setup_iv_params()

            # Create parties
            users = []
            for i in range(pp.N):
                params = UserIV.Params(i, vk, sks[i], eks[i], shares[i], r[i], EK)
                users.append(UserIVTamperPartial(params) if pp.K != 0 and i % pp.K == 0 else UserIV(params))
            aggregator = AggregatorIV(AggregatorIV.Params(vk, users, SS, SK, EK, EKS, v))

            # Return parties
            log.info(
                f"Users {[i for i, user in enumerate(users) if isinstance(user, UserIVTamperPartial)]} will "
                f"(potentially) tamper with other users' partial signatures."
            )
            return users, aggregator, [aggregator]


class DealerIVTamperFinal(DealerIV):
    """A dealer in mPVAS-IV that includes users who tamper with final signatures."""

    def setup(self) -> Tuple[Sequence[UserIV], AggregatorIV, Sequence[Verifier]]:
        with self.deal_timer:
            log.info("-" * 60)
            log.info("NEW PROTOCOL RUN!")
            log.info(f"SETUP PARAMETERS -> N: {pp.N}, K: {pp.K}")

            # Generate parameters
            p, shares, sks, vk, eks, r, SS, SK, EK, EKS, v = self._setup_iv_params()

            # Create parties
            users = []
            for i in range(pp.N):
                params = UserIV.Params(i, vk, sks[i], eks[i], shares[i], r[i], EK)
                users.append(UserIVTamperFinal(params) if i < pp.K else UserIV(params))
            aggregator = AggregatorIV(AggregatorIV.Params(vk, users, SS, SK, EK, EKS, v))

            # Return parties
            log.info(
                f"Users {[i for i, user in enumerate(users) if isinstance(user, UserIVTamperFinal)]} will tamper with "
                f"their final signatures."
            )
            return users, aggregator, [aggregator]
