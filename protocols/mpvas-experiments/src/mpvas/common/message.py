from dataclasses import dataclass
from typing import Union

from mpvas.common.element import Element
from mpvas.iv.zkp import ZkpEqProof


@dataclass(frozen=True)
class BaseMsg:
    """A message sent between a [User] and an [Aggregator]."""

    origin: int
    """The original sender of the message."""
    sender: int
    """The sender or forwarder of the message."""
    round: Element
    """The round in which the message was sent."""

    @property
    def type(self) -> str:
        """The type of message."""
        return self.__class__.__name__


@dataclass(frozen=True)
class Sigma1(BaseMsg):
    """
    A message containing an initial signature created by a [User].

    The [origin] and [sender] are the same.
    """

    payload: Element
    """The initial signature."""


@dataclass(frozen=True)
class Sigma2(BaseMsg):
    """
    A message containing a partial signature created by another [User].

    The [origin] indicates who created the initial signature, and the [sender] indicates who turned it into a partial
    signature.
    """

    payload: Element
    """The partial signature."""


@dataclass(frozen=True)
class Sigma3(BaseMsg):
    """
    A message containing a summed signature created by the [Aggregator].

    The [origin] indicates who created the initial signature, and the [sender] is always -1 since it was sent by the
    [Aggregator].
    """

    payload: Element
    """The summed signature."""


@dataclass(frozen=True)
class Sigma(BaseMsg):
    """
    A message containing a final user signature created by a [User].

    The [origin] and [sender] are the same.
    """

    payload: Element
    """The final signature."""


@dataclass(frozen=True)
class Report(BaseMsg):
    """
    A report indicating that a [User] has detected that another (unidentified) user has tampered with a signature.

    The [origin] and [sender] are the same, and do NOT indicate who tampered.
    """

    pass


@dataclass(frozen=True)
class ProofReq(BaseMsg):
    """
    A request by the [Aggregator] for a [User] to prove they did not tamper with signatures.

    The [origin] and [sender] are always -1 because this message is sent by the [Aggregator].
    """

    pass


@dataclass(frozen=True)
class ProofRes(BaseMsg):
    """
    A [User]'s answer to an [Aggregator]'s [ProofReq] containing the requested proofs.

    The [origin] is always -1 because that is the [Party] requesting the proof, and the [sender] is the [User] that
    created and sends this proof.
    """

    @dataclass(frozen=True)
    class Proofs:
        """The requested proof material."""

        x_comm: Element
        """A commitment."""

        proof_eq_x_comm: "ZkpEqProof"
        """A zero-knowledge proof of equality against the commitment [x_comm]."""

        proof_eq_sk: "ZkpEqProof"
        """A zero-knowledge proof of equality against the sending [User]'s signing key."""

    payload: Proofs
    """The requested proof material."""


@dataclass(frozen=True)
class Dropout(BaseMsg):
    """
    An announcement by a [User] that they are dropping out of the current round.

    The [payload] contains relevant key material to allow continuing the protocol during the user's absence.

    The [origin] and [sender] are always the same.
    """

    @dataclass(frozen=True)
    class Recovery:
        """The recovery material."""

        rk_it: Element
        """The recovery material that a [Verifier] can use to complete verification."""

        signature: Union[bytes, None] = None
        """A signature over the key material [rk_it], to prove authenticity. (Unused, and therefore `None`.)"""

    payload: Recovery
    """The recovery material."""
