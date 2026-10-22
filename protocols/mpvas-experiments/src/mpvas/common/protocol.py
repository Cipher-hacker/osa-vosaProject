from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Union, Tuple, Dict, Iterable, Sequence

from charm.core.math.pairing import pair, ZR

from mpvas.common import state
from mpvas.common.element import Element
from mpvas.common.message import BaseMsg
from mpvas.common.public_params import SecretParams
from mpvas.common.state import pp, log
from mpvas.common.timer import Timer

VerificationKey = Tuple[Element, Element]


def _measure_value_bytes(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, int):
        return 8
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, Element):
        return len(pp.group.serialize(value))
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, dict):
        return sum(_measure_value_bytes(k) + _measure_value_bytes(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(_measure_value_bytes(item) for item in value)
    fields = getattr(value, "__dataclass_fields__", None)
    if fields is not None:
        return sum(_measure_value_bytes(getattr(value, name)) for name in fields)
    return 0


def _message_bytes(message: BaseMsg) -> int:
    return _measure_value_bytes(message)


class Verifier(ABC):
    """Something that can verify signatures."""

    @dataclass(frozen=True)
    class Params:
        vk: VerificationKey

    verify_timer: Timer
    """Measures time spent verifying."""

    _vk: VerificationKey
    """The verification key."""

    def __init__(self, params: Params) -> None:
        """Initializes a verifier."""

        self.verify_timer = Timer()
        self._vk = params.vk

    def verify(self, round: Element, my_sum_plain: int, signature: Element) -> bool:
        """
        Verifies that [signature] is the correct signature of plaintext value [my_sum_plain] for the given [round].
        """

        my_sum = pp.group.init(ZR, my_sum_plain)

        with self.verify_timer:
            return pair(pp.H(round), self._vk[0]) * pair(pp.g1**my_sum, self._vk[1]) == pair(signature, pp.g2)

    @abstractmethod
    def _signing_set_of(self, round: Element, uid: int) -> Iterable[int]:
        """
        Returns the set of uids that should help complete the partial signature of user [uid] in the given [round], i.e.
        excluding user [uid] themselves.
        """
        pass

    @abstractmethod
    def _signing_set_size_of(self, round: Element, uid: int) -> int:
        """
        The number of users in the signing set of user [uid] in the given [round], i.e. excluding user [uid] themselves.
        """
        pass

    @abstractmethod
    def _find_ek_index(self, round: Element, uid1: int, uid2: int) -> int:
        """
        Returns the index of the "encryption key" that user [uid1] uses to amend the partial signature of user [uid2] in
        the given [round].
        """
        pass


class Party(ABC):
    """
    Something that actively participates in mPVAS.
    """

    @dataclass(frozen=True)
    class Params(ABC):
        """Initialization parameters for this party."""

        uid: int

    uid: int
    """The unique identifier for this user."""

    def __init__(self, params: Params) -> None:
        """Initializes a party."""

        super().__init__()

        self.uid = params.uid


class User(Verifier, Party, ABC):
    """A user with data. All users can verify signatures."""

    @dataclass(frozen=True)
    class Params(Verifier.Params, Party.Params):
        """Combines parameters from both superclasses."""

        pass

    sign_timer: Timer
    """Measures time spent signing."""

    _aggregator: "Aggregator"
    """The aggregator to communicate with. Should be set with [set_aggregator] before sending messages to this user."""

    def __init__(self, params: Params) -> None:
        """Initializes a user."""

        Verifier.__init__(self, params)
        Party.__init__(self, params)

        self.sign_timer = Timer()

    def set_aggregator(self, aggregator: "Aggregator") -> None:
        """Tells this user who the aggregator is."""
        self._aggregator = aggregator

    @abstractmethod
    def submit(self, round: Element, plain_value: Union[int, None] = None) -> None:
        """
        Signs the plaintext [plain_value] and submits this to the aggregator. If [plain_value] is `None`, it is set to
        [uid].

        The [round] must be a group element.
        """
        pass

    def _send(self, message: BaseMsg) -> None:
        """Sends the given [message] to the aggregator."""

        log.debug(msg=f"User {self.uid} -> {message.type}(User {message.origin}) -> Aggr")
        state.client_to_server_bytes += _message_bytes(message)
        self._aggregator.receive(message)

    @abstractmethod
    def receive(self, message: BaseMsg) -> None:
        """Sends the given [message] to this user, possibly causing a chain of messages to be sent to other parties."""
        pass


class Aggregator(Verifier, Party, ABC):
    """A party that aggregates signatures of users."""

    @dataclass(frozen=True)
    class Params(Verifier.Params, Party.Params):
        users: Sequence[User]
        uid: int = field(default=-1, init=False)  # Cannot be set in constructor

    users: Sequence[User]
    """The list of users involved in the protocol."""
    sign_timer: Timer
    """Measures time spent working with signatures."""
    signatures: Dict[Element, Element]
    """
    Maps rounds to obtained aggregate signatures. This is the list of signatures verifiable signatures published by the
    aggregator.
    """

    def __init__(self, params: Params) -> None:
        """Initializes an aggregator, telling it which users are to be aggregated over."""

        Verifier.__init__(self, params)
        Party.__init__(self, params)

        self.users = params.users
        self.sign_timer = Timer()
        self.signatures = {}

        for user in self.users:
            user.set_aggregator(self)

    def _send(self, uid: Union[int, Iterable[int]], message: BaseMsg) -> None:
        """Sends the given [message] to the user(s) with the given [uid](s)."""

        if isinstance(uid, int):
            log.debug(f"Aggr -> {message.type}(User {message.origin}) -> User {uid}")
            state.server_to_client_bytes += _message_bytes(message)
            self.users[uid].receive(message)
        else:
            for i in uid:
                log.debug(f"Aggr -> {message.type}(User {message.origin}) -> User {i}")
                state.server_to_client_bytes += _message_bytes(message)
                self.users[i].receive(message)

    @abstractmethod
    def receive(self, message: BaseMsg) -> None:
        """
        Sends the given [message] to this aggregator, possibly causing a chain of messages to be sent to other parties.
        """
        pass


class Dealer(ABC):
    """A dealer that initializes the other parties."""

    deal_timer: Timer
    """Measures time spent dealing."""
    sp: SecretParams
    """The secret parameters known only to the dealer."""

    def __init__(self, sp: SecretParams) -> None:
        """Initializes a dealer."""

        self.deal_timer = Timer()
        self.sp = sp

    @abstractmethod
    def setup(self) -> Tuple[Sequence[User], Aggregator, Sequence[Verifier]]:
        """Initializes the users, an aggregator, and verifiers."""
        pass