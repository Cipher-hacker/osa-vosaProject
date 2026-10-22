import math
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    # If currently type checking, import `Element` typing stub
    # noinspection PyUnresolvedReferences
    from charm.core.math.pairing import Element
else:
    # If not type checking, pretending this is an `int` is good enough
    Element = int


# Simple type wrapper
def prod(elements: Iterable[Element]) -> Element:
    return math.prod(elements)  # type: ignore
