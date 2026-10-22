import random
from typing import Union, MutableSequence, Any


class SimpleRandom:
    """Simple wrapper for a seeded random instance."""

    __rng: random.Random

    def __init__(self, seed: Union[int, str]) -> None:
        """Initializes a `SimpleRandom` instance."""
        self.__rng = random.Random(seed)

    def next(self, a: int = -(2**31), b: int = 2**31 - 1) -> int:
        """Returns the next random integer between [a] (inclusive) and [b] (inclusive)."""
        return self.__rng.randint(a, b)

    def shuffle(self, sequence: MutableSequence[Any]) -> None:
        """Shuffles the [sequence] in place."""
        self.__rng.shuffle(sequence)
