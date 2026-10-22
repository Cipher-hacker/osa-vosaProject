from typing import Iterator, Union, Set

from mpvas.common.state import pp, log


def next_k(start: int, amount: int, mod: int, ignore: Union[Set[int], None] = None) -> Iterator[int]:
    """
    Returns [amount] consecutive integers starting at [start] (exclusive), ignoring entries in [ignore], and wrapping
    back to zero when [mod] is reached (thus never returning [mod] itself).

    For example, `next_k(start=4, amount=5, mod=7, ignore={1})` returns `[5, 6, 0, 2, 3]`.
    """

    if ignore is None:
        ignore = set()

    count = 0
    current = start

    while count != amount:
        current = (current + 1) % mod
        while current in ignore:
            current = (current + 1) % mod

        yield current
        count += 1


def log_progress(message: str, progress: int, granularity: int = 25) -> None:
    """
    Logs the progress of [message] as being [progress] relative to [pp.n]. Does not actually log except if [progress] is
    a multiple of [granularity] or if [progress] equals [pp.n], to prevent an overly full log.
    """

    if progress % granularity == 0 or progress == pp.N - 1:
        log.info(f"--- {message}: {progress / (pp.N - 1) * 100:,.2f}%")
