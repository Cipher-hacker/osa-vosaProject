import datetime
import logging
import sys
from logging import Logger
from pathlib import Path

from mpvas.common.enums import Protocol


def create_logger(protocol: Protocol, write_to_file: bool = True) -> Logger:
    """Creates a logger configured for mPVAS experiments."""

    logger = logging.getLogger(str(protocol))
    logger.setLevel(logging.INFO)

    # Write to stdout
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.INFO)
    c_handler.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
    logger.addHandler(c_handler)

    # Write to file
    if write_to_file:
        logs_path = Path.cwd() / "../out/logs"  # Must be run from `src/`!
        logs_path.mkdir(parents=True, exist_ok=True)
        logger_level = logging.getLevelName(logger.level).lower()
        date = "{:%Y-%m-%d}".format(datetime.datetime.now())
        f_debug_handler = logging.FileHandler(logs_path / f"{logger_level}_{date}.log")
        f_debug_handler.setLevel(logging.DEBUG)
        f_debug_handler.setFormatter(logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s"))
        logger.addHandler(f_debug_handler)

    return logger
