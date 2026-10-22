"""
The following Python implementation of Shamir's secret sharing is released into the Public Domain under the terms of CC0
and OWFa:
https://creativecommons.org/publicdomain/zero/1.0/
http://www.openwebfoundation.org/legal/the-owf-1-0-agreements/owfa-1-0

Modified version of the Public Domain implementation from https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing.
"""

from math import prod
from typing import Union, Tuple, List, Set, Sequence

from charm.core.math.pairing import ZR

from mpvas.common.element import Element
from mpvas.common.state import pp
from mpvas.common.utils import next_k


def share(secret: int, threshold: int, amount: int, prime: int) -> List[Tuple[int, int]]:
    """
    Generates [threshold]-out-of-[amount] Shamir secret shares of the [secret], modulo [prime].

    Each share consists of
    """

    if threshold > amount:
        raise ValueError(f"Threshold (value: {threshold}) must be less than the number of shares (value: {amount}).")

    poly = [secret] + [pp.rng.next(0, prime - 1) for _ in range(threshold - 1)]
    points = [(i, _eval_at(poly, i, prime)) for i in range(1, amount + 1)]

    return points


def recover(shares: List[Tuple[int, int]], prime: int) -> int:
    """
    Recovers the secret from the given [shares] modulo the given [prime].

    Each share is a point consisting of an x-coordinate and a y-coordinate.
    """

    if len(shares) < 3:
        raise ValueError(f"Reconstruction requires at least 3 shares, but only {len(shares)} shares were given.")

    x_s: List[int]
    y_s: List[int]
    x_s, y_s = zip(*shares)  # type: ignore
    return _lagrange_interpolate(0, x_s, y_s, prime)


def _eval_at(polynomial: Sequence[int], x: int, modulo: int) -> int:
    """
    Evaluates the given [polynomial] at [x] under the given [modulo].

    The polynomial is interpreted as the list of coefficients, starting at the lowest order. For example, the polynomial
    `8x^2 + 3x + 5` is written as `[5, 3, 8]`.
    """

    acc = 0
    for coeff in reversed(polynomial):
        acc *= x
        acc += coeff
        acc %= modulo

    return acc


def _lagrange_interpolate(x: int, x_s: List[int], y_s: List[int], prime: int) -> int:
    """
    Given a list of points, infers a polynomial, and evaluates the polynomial at [y] under modulo [prime].

    The polynomial is described by a list of `k` x-coordinates in [x_s] and `k` y-coordinates in [y_s], which fits a
    unique polynomial of order `k - 1`.
    """

    k = len(x_s)
    assert k == len(set(x_s)), "Points must be distinct."

    numers = []  # Avoid inexact division
    denoms = []

    for i in range(k):
        numers.append(prod(x - it for it in x_s if it != x_s[i]))
        denoms.append(prod(x_s[i] - it for it in x_s if it != x_s[i]))

    denom = prod(denoms)
    numer = sum([_div_mod(numers[i] * denom * y_s[i] % prime, denoms[i], prime) for i in range(k)])

    return (_div_mod(numer, denom, prime) + prime) % prime


def _div_mod(numer: int, denom: int, prime: int) -> int:
    """
    Computes the modular division of [numer] over [denom] under the given [prime].

    In other words, `_div_mod(numer, denom, prime) * denom` equals `numer` under modulo `prime`.
    """

    inv, _ = _gcd(denom, prime)
    return (numer * inv) % prime


def _gcd(a: int, b: int) -> Tuple[int, int]:
    """Finds the greatest common divisor of [a] and [b] using the extended Euclidian algorithm."""

    x = 0
    last_x = 1
    y = 1
    last_y = 0

    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y

    return last_x, last_y


def lagrange_coeff(x_i: int, x_orig: int, ignore: Union[Set[int], None] = None) -> Element:
    """


    x_i: the x coordinate of this user (1 <= x_i <= n)
    x_orig: the x coordinate of the origin user
    """

    x_i_ = pp.group.init(ZR, x_i)
    coeff = pp.group.init(ZR, 1)

    for x_j in (pp.group.init(ZR, i + 1) for i in next_k(x_orig - 2, pp.K + 1, pp.N, ignore=ignore)):
        if not (x_i_ == x_j):
            coeff *= x_j / (x_j - x_i_)

    return coeff


def partial_secret(x_i: int, y_i: Element, x_orig: int, ignore: Union[Set[int], None] = None) -> Element:
    """
    x_i: the x coordinate of this user (1 <= x_i <= n)
    y_i: the y coordinate of this user
    x_orig: the x coordinate of the origin user
    """

    return y_i * lagrange_coeff(x_i, x_orig, ignore)


def lagrange_coeff_plus(x_i_plain: int, x_first: int, x_last: int) -> Element:
    """
    x_i: the x-coordinate of this user (1 <= x_i <= C)
    x_orig: the x-coordinate of the origin user
    """

    x_i = pp.group.init(ZR, x_i_plain - x_first) + 1
    coeff = pp.group.init(ZR, 1)

    for x_j in (pp.group.init(ZR, i) for i in range(1, x_last - x_first + 1)):
        if x_i != x_j:
            coeff *= x_j / (x_j - x_i)

    return coeff


def partial_secret_plus(x_i: int, y_i: Element, x_first: int, x_last: int) -> Element:
    """
    x_i: the x-coordinate of this user (1 <= x_i <= n)
    y_i: the y-coordinate of this user
    x_orig: the x-coordinate of the origin user
    """

    coeff = lagrange_coeff_plus(x_i, x_first, x_last)
    secret_i = coeff * y_i
    return secret_i
