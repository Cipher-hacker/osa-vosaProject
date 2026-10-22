from enum import Enum


class Protocol(Enum):
    """The different mPVAS variants."""

    PLAIN = 1
    """Plain mPVAS."""

    PLUS = 2
    """mPVAS+."""

    IV = 3
    """mPVAS-IV."""

    UD = 4
    """mPVAS-UD."""

    @staticmethod
    def get(string: str) -> "Protocol":
        """
        Returns the [Protocol] described by the [string], matching either by the enum's integer value or the enum's
        case-insensitive name.
        """

        if string.isdigit():
            return Protocol(int(string))
        else:
            return Protocol[string.upper()]

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"mpvas-{self.name}".upper()
