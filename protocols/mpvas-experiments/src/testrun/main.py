from typing import Type

from charm.core.math.pairing import ZR

from mpvas.common import state
from mpvas.common.csv import write_csv
from mpvas.common.enums import Protocol
from mpvas.common.protocol import Dealer
from mpvas.common.state import args, pp, sp, log
from mpvas.iv.protocol import DealerIVTamperFinal, DealerIVTamperPartial
from mpvas.plain.protocol import DealerPlain
from mpvas.plus.protocol import DealerPlus
from mpvas.ud.protocol import DealerUD

# Create parties
dealer_fn: Type[Dealer]
if pp.protocol == Protocol.PLAIN:
    dealer_fn = DealerPlain
elif pp.protocol == Protocol.IV:
    if args.tamper_type == "partial":
        dealer_fn = DealerIVTamperPartial
    elif args.tamper_type == "final":
        dealer_fn = DealerIVTamperFinal
    else:
        raise ValueError(f"Unknown tamper type '{args.tamper_type}'.")
elif pp.protocol == Protocol.UD:
    dealer_fn = DealerUD
elif pp.protocol == Protocol.PLUS:
    dealer_fn = DealerPlus
else:
    raise ValueError(f"Unknown protocol type '{pp.protocol}'.")

dealer = dealer_fn(sp)
users, aggregator, verifiers = dealer.setup()
verifier = verifiers[0]

# Run mPVAS
true_sum = pp.N - pp.num_dropouts

round = pp.group.init(type=ZR, value=0)
for user in users:
    user.submit(round, 1)
assert round in aggregator.signatures, "Aggregator did not publish an aggregate signature."

is_valid = verifier.verify(round, true_sum, aggregator.signatures[round])
assert is_valid != state.tampered_ever, (
    f"Verification {'passed' if is_valid else 'failed'}, but signatures were "
    f"{'not ' if not state.tampered_now else ''}tampered with."
)
log.info(f"Verifier: Verification {'passed' if is_valid else 'failed'}, as intended and expected.")

# Write statistics
if args.tamper_type is None:
    filename = f"data-{str(pp.protocol).lower()}.csv"
else:
    filename = f"data-{str(pp.protocol).lower()}-tamper-{args.tamper_type}.csv"

write_csv(dealer, users, aggregator, verifier, filename)
