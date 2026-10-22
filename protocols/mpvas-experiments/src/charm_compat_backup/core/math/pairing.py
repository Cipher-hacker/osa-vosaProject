from __future__ import annotations

import importlib.util
import site
import sys
from dataclasses import dataclass
from pathlib import Path


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    seen: set[str] = set()
    raw_entries = list(sys.path)
    try:
        raw_entries.extend(site.getsitepackages())
    except Exception:
        pass
    try:
        raw_entries.append(site.getusersitepackages())
    except Exception:
        pass

    for entry in raw_entries:
        if not entry:
            continue
        text = str(entry)
        if text in seen:
            continue
        seen.add(text)
        roots.append(Path(text))
    return roots


def _load_real_pairing_module():
    patterns = [
        'charm/core/math/pairing*.so',
        'Charm_Crypto-*.egg/charm/core/math/pairing*.so',
    ]
    for root in _candidate_roots():
        for pattern in patterns:
            for candidate in root.glob(pattern):
                if candidate.is_file():
                    spec = importlib.util.spec_from_file_location('pairing', candidate)
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return module
    return None


_real = _load_real_pairing_module()

if _real is not None:
    pairing = _real.pairing
    pc_element = _real.pc_element
    Element = pc_element
    ZR = _real.ZR
    G1 = _real.G1
    G2 = _real.G2
    GT = _real.GT
    init = _real.init
    pair = _real.pair
    hashPair = _real.hashPair
    H = _real.H
    random = _real.random
    serialize = _real.serialize
    deserialize = _real.deserialize
    ismember = _real.ismember
    order = _real.order
else:
    pairing = None
    hashPair = None
    H = None
    random = None
    serialize = None
    deserialize = None
    ismember = None
    order = None
    init = None
    ZR = 'ZR'
    G1 = 'G1'
    G2 = 'G2'
    GT = 'GT'

    @dataclass(frozen=True)
    class Element:
        order: int
        kind: str
        value: int

        def __post_init__(self) -> None:
            object.__setattr__(self, 'value', self.value % self.order)

        def _coerce_scalar(self, other: object) -> int:
            if isinstance(other, Element):
                if other.order != self.order:
                    raise ValueError('Element orders do not match.')
                return other.value
            if isinstance(other, int):
                return other % self.order
            raise TypeError(f'Unsupported operand type: {type(other)!r}')

        def _coerce_same_group(self, other: object) -> 'Element':
            if not isinstance(other, Element):
                raise TypeError(f'Unsupported operand type: {type(other)!r}')
            if other.order != self.order or other.kind != self.kind:
                raise ValueError('Elements must belong to the same group.')
            return other

        def __int__(self) -> int:
            return self.value

        def __repr__(self) -> str:
            return f'{self.kind}({self.value})'

        def __hash__(self) -> int:
            return hash((self.order, self.kind, self.value))

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, Element):
                return False
            return self.order == other.order and self.kind == other.kind and self.value == other.value

        def __add__(self, other: object) -> 'Element':
            if self.kind != ZR:
                raise TypeError('Addition is only defined for ZR elements.')
            return Element(self.order, ZR, self.value + self._coerce_scalar(other))

        def __radd__(self, other: object) -> 'Element':
            if other == 0:
                return self
            return self.__add__(other)

        def __sub__(self, other: object) -> 'Element':
            if self.kind != ZR:
                raise TypeError('Subtraction is only defined for ZR elements.')
            return Element(self.order, ZR, self.value - self._coerce_scalar(other))

        def __rsub__(self, other: object) -> 'Element':
            if self.kind != ZR:
                raise TypeError('Subtraction is only defined for ZR elements.')
            return Element(self.order, ZR, self._coerce_scalar(other) - self.value)

        def __neg__(self) -> 'Element':
            return Element(self.order, self.kind, -self.value)

        def __mul__(self, other: object) -> 'Element':
            if self.kind == ZR:
                return Element(self.order, ZR, self.value * self._coerce_scalar(other))
            if other == 1:
                return self
            same = self._coerce_same_group(other)
            return Element(self.order, self.kind, self.value + same.value)

        def __rmul__(self, other: object) -> 'Element':
            if self.kind == ZR:
                return self.__mul__(other)
            if other == 1:
                return self
            raise TypeError('Group elements only support multiplication by elements from the same group.')

        def __truediv__(self, other: object) -> 'Element':
            if self.kind == ZR:
                other_val = self._coerce_scalar(other)
                if other_val == 0:
                    raise ZeroDivisionError('division by zero')
                return Element(self.order, ZR, self.value * pow(other_val, -1, self.order))
            same = self._coerce_same_group(other)
            return Element(self.order, self.kind, self.value - same.value)

        def __rtruediv__(self, other: object) -> 'Element':
            if self.kind != ZR:
                raise TypeError('Right division is only defined for ZR elements.')
            if self.value == 0:
                raise ZeroDivisionError('division by zero')
            return Element(self.order, ZR, self._coerce_scalar(other) * pow(self.value, -1, self.order))

        def __pow__(self, exponent: object) -> 'Element':
            exp_val = self._coerce_scalar(exponent)
            if self.kind == ZR:
                return Element(self.order, ZR, pow(self.value, exp_val, self.order))
            return Element(self.order, self.kind, self.value * exp_val)

    pc_element = Element

    def pair(left: Element, right: Element) -> Element:
        if left.kind != G1 or right.kind != G2:
            raise TypeError('pair() expects a G1 element and a G2 element.')
        if left.order != right.order:
            raise ValueError('Pairing operands must have the same order.')
        return Element(left.order, GT, left.value * right.value)