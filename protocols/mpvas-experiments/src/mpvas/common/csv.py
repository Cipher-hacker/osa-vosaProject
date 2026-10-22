from pathlib import Path
from statistics import mean
from typing import Sequence

from mpvas.common.protocol import User, Aggregator, Verifier, Dealer
from mpvas.common.state import args, pp
from mpvas.ud.protocol import UserUDDropsOut


def write_csv(dealer: Dealer, users: Sequence[User], aggregator: Aggregator, verifier: Verifier, filename: str) -> None:
    """Writes CSV-formatted experiment outputs to file."""

    if args.suppress_writes:
        return

    # Calculate statistics
    tampers_num = max(0, args.num_tampers)

    remaining_users = [user for user in users if not isinstance(user, UserUDDropsOut)]
    remaining_user_time = mean(user.sign_timer.nanoseconds for user in remaining_users)

    dropped_out_users = [user for user in users if isinstance(user, UserUDDropsOut)]
    dropout_user_time = 0 if not dropped_out_users else mean(user.sign_timer.nanoseconds for user in dropped_out_users)

    # Format statistics
    data = {
        "timestamp": pp.timestamp,
        "users_num": pp.N,
        "malicious_ratio": pp.ratio_malicious,
        "malicious_num": pp.K,
        "group_size": pp.C,
        "tampers_num": tampers_num,
        "tampers_ratio": tampers_num / pp.N,
        "dropouts_num": pp.num_dropouts,
        "dropouts_ratio": pp.num_dropouts / pp.N,
        "deal_time": dealer.deal_timer.nanoseconds,
        "user_time": remaining_user_time,
        "user_times": '"' + ",".join([str(user.sign_timer.nanoseconds) for user in remaining_users]) + '"',
        "aggr_time": aggregator.sign_timer.nanoseconds,
        "veri_time": verifier.verify_timer.nanoseconds,
        "dropout_user_time": dropout_user_time,
    }
    header = ",".join(data.keys()) + "\n"
    line = ",".join(str(it) for it in data.values()) + "\n"

    # Write statistics
    data_path = Path.cwd() / "../out/data"  # Must be run from `src/`!
    data_path.mkdir(parents=True, exist_ok=True)

    with open(data_path / filename, "a") as file:
        if file.tell() == 0:
            file.write(header)

        file.write(line)
