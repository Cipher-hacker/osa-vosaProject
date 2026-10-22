from argparse import Namespace
from logging import Logger

from mpvas.common.logger import create_logger
from mpvas.common.parse_args import parse_args
from mpvas.common.public_params import PublicParams, parse_params, SecretParams

args: Namespace
"""The parsed command-line arguments."""
log: Logger
"""The [Logger] to log with."""
pp: PublicParams
"""The public parameters, which may be known by anyone."""
sp: SecretParams
"""
The secret parameters.

This value is intended for the [Dealer] only, but is useful to keep around for debugging purposes.
"""

num_partial_tampers_left: int
"""
The number of partial signatures the malicious users still want to tamper with.

This global value is used as a workaround for setting up separate communication channels for malicious users.
"""
tampered_now: bool
"""
`True` if and only if a malicious [User] has tampered with the signature currently being signed, so that other malicious
users know they need not tamper with it anymore.

Gets set by malicious users after tampering, and gets unset by honest users after detecting said tampering. Obviously,
honest users do not read this variable as part of their tampering detection mechanism; that would be cheating!

This global value is used as a workaround for setting up separate communication channels for malicious users.
"""
tampered_ever: bool
"""
Similar to [tampered_now], except that it does not get unset by honest users.

This global value is used to determine at the end whether verification is expected to fail.
"""
client_to_server_bytes: int
"""Cumulative bytes sent from users to the aggregator."""
server_to_client_bytes: int
"""Cumulative bytes sent from the aggregator to users."""


def init() -> None:
    """Initializes global objects characterizing the current mPVAS instance."""

    global args
    global log
    global pp
    global sp

    global num_partial_tampers_left
    global tampered_now
    global tampered_ever
    global client_to_server_bytes
    global server_to_client_bytes

    args = parse_args()
    log = create_logger(args.protocol, write_to_file=not args.suppress_writes)
    pp, sp = parse_params(log, args)

    num_partial_tampers_left = args.num_tampers
    tampered_now = False
    tampered_ever = False
    client_to_server_bytes = 0
    server_to_client_bytes = 0