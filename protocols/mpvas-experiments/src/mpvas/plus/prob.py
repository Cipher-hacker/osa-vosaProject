import math
from logging import Logger


def __find_prob(n: int, k: int, c: int) -> float:
    """Calculates the probability of failure given [n], [k], and [c]."""

    d = math.floor(n / c)
    R = math.floor(k / c)

    def rep(r_: int) -> int:
        a = math.comb(n - r_ * c, k - r_ * c)
        b = 0
        for i in range(r_ + 1, R + 1):
            b += math.comb(d - r_, i - r_) * rep(i)
        return a - b

    repl = 0
    for r in range(2, R + 1):
        repl += (r - 1) * math.comb(d, r) * rep(r)

    num = d * math.comb(n - c, k - c) - repl
    den = math.comb(n, k)
    return num / den


def find_c(log: Logger, n: int, k: int, threshold: float = 0.00001) -> int:
    """Finds and returns `c` such that the probability of failure is less than [threshold], given [n] and [k]."""

    log.info(f"Finding c such that prob <= {threshold:.5f}, for n={n} and k={k}.")

    result = k + 1
    prob: float = 0
    for c in range(k, 1, -1):
        _prob = __find_prob(n, k, c)
        if _prob > threshold:
            result = c + 1
            break
        prob = _prob

    log.info(f"Found c = {result}, with prob = {prob:.10f}.")
    return result
