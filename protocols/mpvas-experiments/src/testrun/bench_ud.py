from charm.core.math.pairing import ZR

from mpvas.common import state
from mpvas.common.enums import Protocol
from mpvas.ud.protocol import DealerUD, UserUDDropsOut


state.init()
if state.pp.protocol != Protocol.UD:
    raise ValueError("bench_ud.py must be run with -p ud")

dealer = DealerUD(state.sp)
users, aggregator, verifiers = dealer.setup()
verifier = verifiers[0]

round_element = state.pp.group.init(type=ZR, value=0)
true_sum = state.pp.N - state.pp.num_dropouts
for user in users:
    user.submit(round_element, 1)

assert round_element in aggregator.signatures, "Aggregator did not publish an aggregate signature."
is_valid = verifier.verify(round_element, true_sum, aggregator.signatures[round_element])
assert is_valid, "mPVAS-UD verification failed in benchmark run."

active_users = [user for user in users if not isinstance(user, UserUDDropsOut)]
dropped_users = [user for user in users if isinstance(user, UserUDDropsOut)]
client_total_ns = sum(user.sign_timer.nanoseconds for user in users)
active_client_total_ns = sum(user.sign_timer.nanoseconds for user in active_users)
dropout_client_total_ns = sum(user.sign_timer.nanoseconds for user in dropped_users)

total_bytes = state.client_to_server_bytes + state.server_to_client_bytes
print(
    "protocol=mPVAS-UD "
    f"n_clients={state.pp.N} "
    f"active_clients={len(active_users)} "
    f"dropouts={len(dropped_users)} "
    f"client_compute_s={client_total_ns / 1e9:.6f} "
    f"active_client_compute_s={active_client_total_ns / 1e9:.6f} "
    f"dropout_client_compute_s={dropout_client_total_ns / 1e9:.6f} "
    f"server_compute_s={aggregator.sign_timer.nanoseconds / 1e9:.6f} "
    f"verifier_compute_s={verifier.verify_timer.nanoseconds / 1e9:.6f} "
    f"client_to_server_bytes={state.client_to_server_bytes} "
    f"server_to_client_bytes={state.server_to_client_bytes} "
    f"server_to_verifier_bytes=0 "
    f"total_bytes={total_bytes}"
)