import sys
from argparse import ArgumentTypeError, Namespace, ArgumentParser
from math import ceil
from typing import Any

from mpvas.common.enums import Protocol


def _range_limited_float_type(argument: Any) -> float:
    """Type function for `argparse`, defining a float between 0 and 1."""

    try:
        number = float(argument)
    except ValueError:
        raise ArgumentTypeError(f"Argument must be a floating point number, but was '{argument}'.")

    if number < 0 or number > 1:
        raise ArgumentTypeError(f"Argument must be between 0 and 1, but was {number}.")

    return number


def parse_args() -> Namespace:
    """Parses command-line arguments for running mPVAS experiments."""

    # Define
    parser = ArgumentParser()
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["1", "2", "3", "4", "plain", "plus", "iv", "ud"],
        default="1",
        required=True,
        dest="protocol_str",
        help="which mPVAS variant to run",
    )
    parser.add_argument("-s", "--seed", default="17", help="the string to seed the random number generator with")
    parser.add_argument("-n", type=int, required=True, help="number of users")
    parser.add_argument("-m", type=_range_limited_float_type, default=0, help="ratio of malicious users")
    parser.add_argument("-k", type=int, help="number of malicious users, overrides -m")
    parser.add_argument("-c", type=int, help="(mPVAS+ only) group size")
    parser.add_argument(
        "-t",
        "--tamper-type",
        choices=["partial", "final"],
        dest="tamper_type",
        help="(mPVAS-IV only) type of signature malicious users will tamper with",
    )
    parser.add_argument(
        "--tamper-ratio",
        type=_range_limited_float_type,
        dest="tamper_ratio",
        help="(mPVAS-IV only) (partial tampers only) ratio of users that will tamper with signatures",
    )
    parser.add_argument(
        "-d",
        "--dropout-ratio",
        type=_range_limited_float_type,
        dest="dropout_ratio",
        help="(mPVAS-UD only) ratio of users that will drop out of the protocol",
    )
    parser.add_argument(
        "--suppress-writes",
        default=False,
        dest="suppress_writes",
        action="store_true",
        help="Disable all writing to the filesystem, such as output data or logs.",
    )

    # Parse
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()  # Exits the program entirely

    args = parser.parse_args()  # Exits the program entirely if arguments are invalid
    args.protocol = Protocol.get(args.protocol_str)

    # Validate and normalize
    if args.n < 1:
        parser.error(f"Number of users must be at least 1, but was {args.n}.")

    if args.k is None:
        args.k = ceil(args.n * args.m)
    else:
        if args.k < 0 or args.k > args.n:
            parser.error(
                f"Number of malicious users must be between 0 and the number of users (which is {args.n}), "
                f"but was {args.k}."
            )
        args.m = args.k / args.n

    if args.protocol == Protocol.PLUS:
        if args.c is not None and (args.c < 1 or args.c > args.n):
            parser.error(
                f"Group size 'c' must be between 1 and the number of users (which is {args.n}), but was " f"{args.c}."
            )
    else:
        if args.c is not None:
            parser.error("Group size 'c' must not be specified for protocol variants other than mPVAS+.")

    if args.protocol == Protocol.IV:
        if args.tamper_type is None:
            parser.error("Flag '-t' or '--tamper-type' is required to run the mPVAS-IV protocol.")

        if args.tamper_type == "partial":
            if args.tamper_ratio is None:
                parser.error("Flag '--tamper-ratio' is required for mPVAS-IV when '--tamper-type' is 'partial'.")
            else:
                args.num_tampers = ceil(args.tamper_ratio * args.n)
        else:
            if args.tamper_ratio is not None:
                parser.error("Flag '--tamper-ratio' is forbidden for mPVAS-IV when '--tamper-type' is not 'partial'.")

            args.num_tampers = -1
    else:
        if args.tamper_type is not None:
            parser.error("Tamper type must not be specified for protocol variants other than mPVAS-IV.")
        if args.tamper_ratio is not None:
            parser.error("Tamper ratio must not be specified for protocol variants other than mPVAS-IV.")

        args.num_tampers = -1

    if args.protocol == Protocol.UD:
        if args.dropout_ratio is None:
            args.num_dropouts = 0
        else:
            args.num_dropouts = ceil(args.n * args.dropout_ratio)
    else:
        if args.dropout_ratio is not None:
            parser.error("Dropout ratio must not be specified for protocol variants other than mPVAS-UD.")

        args.num_dropouts = 0

    # Return
    return args
