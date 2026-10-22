from contextlib import AbstractContextManager
from time import perf_counter_ns
from typing import Union, Literal, Callable


class Timer(AbstractContextManager):
    """
    Keeps track of time.

    Use this context in a `with` block, and the timer will measure how long it takes until the block has completed
    executing. If the block raises an error, the timer stops, too, without catching that error.

    For example:
    ```python
    from time import sleep

    # [...]

    timer = Timer()
    with timer:
        # Execute my fancy code
        sleep(10)
    print(timer.elapsed)
    ```
    will print (approximately) `10`.

    You can safely nest several `with` blocks that use the same `Timer`. The `Timer` will stop only when the outermost
    block has finished.
    """

    nanoseconds: int = 0
    """The cumulative number of measured nanoseconds."""

    __start: Union[int, None] = None
    """The nanosecond time at which the timer has started, or `None` if the timer has never been started."""

    __depth: int = 0
    """
    The number of nested contexts this timer is currently in. A value of zero indicates that the timer is not currently
    running.
    """

    __timer: Callable[[], int] = perf_counter_ns
    """A function that returns the current with nanosecond precision."""

    def __enter__(self) -> "Timer":
        """Enters a context, starting the timer if it had not been started yet."""

        self.__depth = self.__depth + 1
        self.__start = self.__timer()
        return self

    def __exit__(self, _, __, ___) -> Literal[False]:
        """Ends the context with this timer.."""

        assert self.__depth >= 1, "Timer cannot be stopped because it hasn't started."

        self.__depth = self.__depth - 1
        if self.__depth == 0:
            assert self.__start is not None, "Timer did not record starting time."
            self.nanoseconds += self.__timer() - self.__start

        return False
