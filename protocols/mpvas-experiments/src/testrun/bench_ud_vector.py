"""Real-pairing, verification-only vector benchmark for mPVAS-UD.

The released protocol authenticates one Zp scalar. This benchmark executes the
same K=0 equation under a distinct domain for every vector coordinate. Every
online group element is serialized and parsed.
"""

import base64
import multiprocessing
import os
import shutil
import struct
import sys
import tempfile
from time import perf_counter
from pathlib import Path
from typing import List, Sequence, Tuple

from charm.core.math.pairing import ZR, pair

from mpvas.common import state
from mpvas.common.enums import Protocol
from mpvas.ud.protocol import DealerUD, UserUDDropsOut, VerifierUD


MAGIC = b"MPVV"
VERSION = 1
SIGNATURE_VECTOR_KIND = 1
DROPOUT_KIND = 2
PUBLICATION_KIND = 3
RECOVERY_AGGREGATE_KIND = 4

_WORKER_USERS = []
_WORKER_ROUNDS = []
_WORKER_ITERATION = 0
_WORKER_VECTOR_LEN = 0
_WORKER_SPOOL_DIR = ""
_WORKER_WARMED = False


def _vector_value(uid: int, coordinate: int) -> int:
    return ((uid + 1) * 131 + (coordinate + 1) * 17) % 1024 + 1


def _encode_header(kind: int) -> bytearray:
    return bytearray(MAGIC + bytes((VERSION, kind)))


def _read_header(data: bytes, kind: int) -> int:
    if len(data) < 6 or data[:4] != MAGIC or data[4] != VERSION or data[5] != kind:
        raise ValueError("invalid mPVAS vector wire header")
    return 6


def _take(data: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    end = offset + length
    if length < 0 or end > len(data):
        raise ValueError("truncated mPVAS vector message")
    return data[offset:end], end


def _element_to_wire(element: object) -> bytes:
    """Removes Charm's Base64 transport wrapper from its real serialization."""

    encoded = state.pp.group.serialize(element, compression=True)
    tag, base64_payload = encoded.split(b":", 1)
    element_type = int(tag)
    if not 0 <= element_type <= 255:
        raise ValueError("Charm element type does not fit the binary wire tag")
    return bytes((element_type,)) + base64.b64decode(base64_payload, validate=True)


def _element_from_wire(encoded: bytes):
    if len(encoded) < 2:
        raise ValueError("truncated binary Charm element")
    charm_encoded = (
        str(encoded[0]).encode("ascii") + b":" + base64.b64encode(encoded[1:])
    )
    return state.pp.group.deserialize(charm_encoded, compression=True)


def _serialize_signature_vector(
    iteration: int, uid: int, signatures: Sequence[object]
) -> bytes:
    serialized = [_element_to_wire(signature) for signature in signatures]
    element_size = len(serialized[0]) if serialized else 0
    if any(len(value) != element_size for value in serialized):
        raise ValueError("variable-length G1 serialization is unsupported")
    out = _encode_header(SIGNATURE_VECTOR_KIND)
    out.extend(struct.pack("<QIIH", iteration, uid, len(signatures), element_size))
    for value in serialized:
        out.extend(value)
    return bytes(out)


def _parse_signature_vector(data: bytes, expected_iteration: int, expected_length: int):
    offset = _read_header(data, SIGNATURE_VECTOR_KIND)
    fixed, offset = _take(data, offset, struct.calcsize("<QIIH"))
    iteration, uid, count, element_size = struct.unpack("<QIIH", fixed)
    if iteration != expected_iteration or count != expected_length or element_size == 0:
        raise ValueError("invalid mPVAS signature vector shape")
    signatures = []
    for _ in range(count):
        encoded, offset = _take(data, offset, element_size)
        signatures.append(_element_from_wire(encoded))
    if offset != len(data):
        raise ValueError("trailing bytes in mPVAS signature vector")
    return uid, signatures


def _serialize_dropout_vector(
    iteration: int, uid: int, recoveries: Sequence[object]
) -> bytes:
    recovery_bytes = [_element_to_wire(value) for value in recoveries]
    element_size = len(recovery_bytes[0]) if recovery_bytes else 0
    if any(len(value) != element_size for value in recovery_bytes):
        raise ValueError("variable-length GT serialization is unsupported")
    out = _encode_header(DROPOUT_KIND)
    out.extend(struct.pack("<QIIH", iteration, uid, len(recoveries), element_size))
    for value in recovery_bytes:
        out.extend(value)
    return bytes(out)


def _parse_dropout_vector(data: bytes, expected_iteration: int, expected_length: int):
    offset = _read_header(data, DROPOUT_KIND)
    fixed, offset = _take(data, offset, struct.calcsize("<QIIH"))
    iteration, uid, count, element_size = struct.unpack("<QIIH", fixed)
    if iteration != expected_iteration or count != expected_length or element_size == 0:
        raise ValueError("invalid mPVAS dropout vector shape")
    recoveries = []
    for _ in range(count):
        recovery_bytes, offset = _take(data, offset, element_size)
        recoveries.append(_element_from_wire(recovery_bytes))
    if offset != len(data):
        raise ValueError("trailing bytes in mPVAS dropout message")
    return uid, recoveries


def _serialize_recovery_aggregate(
    iteration: int, recoveries: Sequence[object]
) -> bytes:
    serialized = [_element_to_wire(value) for value in recoveries]
    element_size = len(serialized[0]) if serialized else 0
    if any(len(value) != element_size for value in serialized):
        raise ValueError("variable-length GT serialization is unsupported")
    out = _encode_header(RECOVERY_AGGREGATE_KIND)
    out.extend(struct.pack("<QIH", iteration, len(recoveries), element_size))
    for value in serialized:
        out.extend(value)
    return bytes(out)


def _parse_recovery_aggregate(
    data: bytes, expected_iteration: int, expected_length: int
):
    offset = _read_header(data, RECOVERY_AGGREGATE_KIND)
    fixed, offset = _take(data, offset, struct.calcsize("<QIH"))
    iteration, count, element_size = struct.unpack("<QIH", fixed)
    if iteration != expected_iteration or count != expected_length or element_size == 0:
        raise ValueError("invalid mPVAS recovery aggregate shape")
    recoveries = []
    for _ in range(count):
        encoded, offset = _take(data, offset, element_size)
        recoveries.append(_element_from_wire(encoded))
    if offset != len(data):
        raise ValueError("trailing bytes in mPVAS recovery aggregate")
    return recoveries


def _serialize_publication(
    iteration: int,
    active_ids: Sequence[int],
    plain_sums: Sequence[int],
    signatures: Sequence[object],
) -> bytes:
    if len(plain_sums) != len(signatures):
        raise ValueError("publication vector lengths differ")
    serialized = [_element_to_wire(signature) for signature in signatures]
    element_size = len(serialized[0]) if serialized else 0
    out = _encode_header(PUBLICATION_KIND)
    out.extend(
        struct.pack(
            "<QIIH", iteration, len(active_ids), len(signatures), element_size
        )
    )
    for uid in active_ids:
        out.extend(struct.pack("<I", uid))
    for value in plain_sums:
        if not 0 <= value <= (1 << 64) - 1:
            raise ValueError("aggregate value does not fit the benchmark wire type")
        out.extend(struct.pack("<Q", value))
    for value in serialized:
        out.extend(value)
    return bytes(out)


def _parse_publication(data: bytes, expected_iteration: int, expected_length: int):
    offset = _read_header(data, PUBLICATION_KIND)
    fixed, offset = _take(data, offset, struct.calcsize("<QIIH"))
    iteration, active_count, count, element_size = struct.unpack("<QIIH", fixed)
    if iteration != expected_iteration or count != expected_length or element_size == 0:
        raise ValueError("invalid mPVAS publication shape")
    active_ids = []
    for _ in range(active_count):
        encoded, offset = _take(data, offset, 4)
        active_ids.append(struct.unpack("<I", encoded)[0])
    plain_sums = []
    for _ in range(count):
        encoded, offset = _take(data, offset, 8)
        plain_sums.append(struct.unpack("<Q", encoded)[0])
    signatures = []
    for _ in range(count):
        encoded, offset = _take(data, offset, element_size)
        signatures.append(_element_from_wire(encoded))
    if offset != len(data):
        raise ValueError("trailing bytes in mPVAS publication")
    return active_ids, plain_sums, signatures


def _aggregate_in_place(aggregate: List[object], signatures: Sequence[object]) -> None:
    if not aggregate:
        aggregate.extend(signatures)
        return
    if len(aggregate) != len(signatures):
        raise ValueError("mPVAS aggregate signature length mismatch")
    for index, signature in enumerate(signatures):
        aggregate[index] *= signature


def _worker_warmup() -> None:
    global _WORKER_WARMED
    if _WORKER_WARMED:
        return
    warmup_user = next(
        user for user in _WORKER_USERS if not isinstance(user, UserUDDropsOut)
    )
    values = [_vector_value(warmup_user.uid, 0)]
    signatures = warmup_user.sign_vector_k0(_WORKER_ROUNDS[:1], values)
    encoded = _serialize_signature_vector(
        _WORKER_ITERATION, warmup_user.uid, signatures
    )
    _, parsed = _parse_signature_vector(encoded, _WORKER_ITERATION, 1)
    pair(parsed[0], state.pp.g2)
    _WORKER_WARMED = True


def _compute_client_message(uid: int):
    _worker_warmup()
    user = _WORKER_USERS[uid]
    if isinstance(user, UserUDDropsOut):
        start = perf_counter()
        recoveries = user.prepare_dropout_vector(_WORKER_ROUNDS)
        encoded = _serialize_dropout_vector(_WORKER_ITERATION, uid, recoveries)
        client_seconds = perf_counter() - start
        path = Path(_WORKER_SPOOL_DIR) / f"{uid:04d}-dropout.bin"
        path.write_bytes(encoded)
        return "dropout", uid, str(path), len(encoded), client_seconds

    values = [_vector_value(uid, coordinate) for coordinate in range(_WORKER_VECTOR_LEN)]
    start = perf_counter()
    signatures = user.sign_vector_k0(_WORKER_ROUNDS, values)
    encoded = _serialize_signature_vector(_WORKER_ITERATION, uid, signatures)
    client_seconds = perf_counter() - start
    path = Path(_WORKER_SPOOL_DIR) / f"{uid:04d}-active.bin"
    path.write_bytes(encoded)
    return "active", uid, str(path), len(encoded), client_seconds


def main() -> None:
    state.init()
    if state.pp.protocol != Protocol.UD or state.pp.K != 0:
        raise ValueError("bench_ud_vector.py requires '-p ud -m 0'")

    vector_len = int(os.environ.get("MPVAS_VECTOR_LEN", "10000"))
    progress_every = int(os.environ.get("MPVAS_PROGRESS_EVERY", "25"))
    threads = int(os.environ.get("MPVAS_THREADS", "8"))
    if vector_len <= 0:
        raise ValueError("MPVAS_VECTOR_LEN must be positive")
    if threads <= 0:
        raise ValueError("MPVAS_THREADS must be positive")

    setup_start = perf_counter()
    dealer = DealerUD(state.sp)
    users, aggregator, _ = dealer.setup()
    verifier = VerifierUD(
        VerifierUD.Params(vk=aggregator._vk, dpks=aggregator._dpks, EK=aggregator._EK)
    )
    iteration = 1
    rounds = [
        state.pp.group.init(type=ZR, value=(iteration << 32) + coordinate + 1)
        for coordinate in range(vector_len)
    ]
    dropped_users = [user for user in users if isinstance(user, UserUDDropsOut)]
    active_users = [user for user in users if not isinstance(user, UserUDDropsOut)]
    setup_seconds = perf_counter() - setup_start

    if not active_users:
        raise ValueError("at least one active user is required")

    client_to_server_bytes = 0
    active_client_to_server_bytes = 0
    dropout_client_to_server_bytes = 0
    server_to_verifier_bytes = 0
    server_compute_seconds = 0.0
    active_client_seconds = []
    dropout_client_seconds = []
    aggregate_recovery_products: List[object] = []
    dropped_ids = set()

    aggregate_sums = [0] * vector_len
    aggregate_signatures: List[object] = []
    active_ids = []
    for user in active_users:
        for coordinate in range(vector_len):
            value = _vector_value(user.uid, coordinate)
            aggregate_sums[coordinate] += value

    global _WORKER_USERS, _WORKER_ROUNDS, _WORKER_ITERATION, _WORKER_VECTOR_LEN, _WORKER_SPOOL_DIR
    _WORKER_USERS = users
    _WORKER_ROUNDS = rounds
    _WORKER_ITERATION = iteration
    _WORKER_VECTOR_LEN = vector_len
    spool_root = os.environ.get("MPVAS_SPOOL_ROOT")
    spool_dir = Path(
        tempfile.mkdtemp(prefix="mpvas-vector-wire-", dir=spool_root or None)
    )
    _WORKER_SPOOL_DIR = str(spool_dir)
    client_records = []
    processed = 0
    client_batch_start = perf_counter()
    context = multiprocessing.get_context("fork")
    with context.Pool(processes=min(threads, len(users))) as pool:
        for kind, uid, path, message_bytes, client_seconds in pool.imap_unordered(
            _compute_client_message, range(len(users)), chunksize=1
        ):
            client_to_server_bytes += message_bytes
            if kind == "active":
                active_client_to_server_bytes += message_bytes
            elif kind == "dropout":
                dropout_client_to_server_bytes += message_bytes
            client_records.append((uid, kind, Path(path), message_bytes, client_seconds))
            processed += 1
            if progress_every > 0 and processed % progress_every == 0:
                print(
                    f"mpvas_vector_progress={processed}/{len(users)}",
                    file=sys.stderr,
                    flush=True,
                )
    client_batch_wall_seconds = perf_counter() - client_batch_start

    for processed, (uid, kind, path, message_bytes, client_seconds) in enumerate(
        sorted(client_records), start=1
    ):
        encoded = path.read_bytes()
        if len(encoded) != message_bytes:
            raise ValueError("mPVAS spooled message length mismatch")
        start = perf_counter()
        if kind == "dropout":
            parsed_uid, parsed_recoveries = _parse_dropout_vector(
                encoded, iteration, vector_len
            )
            if parsed_uid != uid:
                raise ValueError("mPVAS dropout user ID mismatch")
            if not aggregate_recovery_products:
                aggregate_recovery_products.extend(parsed_recoveries)
            else:
                for coordinate, recovery in enumerate(parsed_recoveries):
                    aggregate_recovery_products[coordinate] *= recovery
            dropped_ids.add(uid)
            dropout_client_seconds.append(client_seconds)
        elif kind == "active":
            parsed_uid, parsed_signatures = _parse_signature_vector(
                encoded, iteration, vector_len
            )
            if parsed_uid != uid:
                raise ValueError("mPVAS client ID mismatch")
            _aggregate_in_place(aggregate_signatures, parsed_signatures)
            active_ids.append(uid)
            active_client_seconds.append(client_seconds)
        else:
            raise ValueError("unknown mPVAS client task kind")
        server_compute_seconds += perf_counter() - start
        path.unlink()
        if progress_every > 0 and processed % progress_every == 0:
            print(
                f"mpvas_server_progress={processed}/{len(client_records)}",
                file=sys.stderr,
                flush=True,
            )
    shutil.rmtree(spool_dir)

    active_ids.sort()
    if active_ids != [user.uid for user in active_users]:
        raise ValueError("mPVAS server active set mismatch")

    recovery_publication = b""
    if aggregate_recovery_products:
        start = perf_counter()
        recovery_publication = _serialize_recovery_aggregate(
            iteration, aggregate_recovery_products
        )
        server_compute_seconds += perf_counter() - start
        server_to_verifier_bytes += len(recovery_publication)

    start = perf_counter()
    publication = _serialize_publication(
        iteration, active_ids, aggregate_sums, aggregate_signatures
    )
    server_compute_seconds += perf_counter() - start
    server_to_verifier_bytes += len(publication)

    verifier_start = perf_counter()
    recovery_products = (
        _parse_recovery_aggregate(recovery_publication, iteration, vector_len)
        if recovery_publication
        else [1] * vector_len
    )
    parsed_ids, parsed_sums, parsed_signatures = _parse_publication(
        publication, iteration, vector_len
    )
    if parsed_ids != active_ids:
        raise ValueError("mPVAS verifier active set mismatch")
    if not verifier.verify_vector_k0(
        rounds, parsed_sums, parsed_signatures, dropped_ids, recovery_products
    ):
        raise AssertionError("mPVAS-UD vector verification failed")
    verifier_compute_seconds = perf_counter() - verifier_start

    tampered_signatures = list(parsed_signatures)
    tampered_signatures[0] *= state.pp.g1
    if verifier.verify_vector_k0(
        rounds, parsed_sums, tampered_signatures, dropped_ids, recovery_products
    ):
        raise AssertionError("forged mPVAS-UD vector unexpectedly verified")

    active_client_mean = sum(active_client_seconds) / len(active_client_seconds)
    dropout_client_mean = (
        sum(dropout_client_seconds) / len(dropout_client_seconds)
        if dropout_client_seconds
        else 0.0
    )
    total_bytes = client_to_server_bytes + server_to_verifier_bytes
    active_client_bytes_mean = active_client_to_server_bytes / len(active_users)
    dropout_client_bytes_mean = (
        dropout_client_to_server_bytes / len(dropped_users) if dropped_users else 0.0
    )
    signature_size = len(_element_to_wire(aggregate_signatures[0]))
    recovery_size = (
        len(_element_to_wire(recovery_products[0]))
        if dropped_users
        else 0
    )
    print(
        "protocol=mPVAS-UD-verification-only-real-pairing-vector "
        "curve=MNT224 security_bits=112 k=0 vector_domain_separation=per_coordinate "
        f"n_clients={state.pp.N} active_clients={len(active_users)} "
        f"dropouts={len(dropped_users)} vector_len={vector_len} "
        f"setup_s={setup_seconds:.6f} client_threads={min(threads, len(users))} "
        f"warmup_coordinates_per_worker=1 repetitions=1 "
        f"active_client_compute_mean_s={active_client_mean:.9f} "
        f"dropout_client_compute_mean_s={dropout_client_mean:.9f} "
        "committee_compute_s=0.000000000 "
        f"server_compute_s={server_compute_seconds:.9f} "
        f"verifier_compute_s={verifier_compute_seconds:.9f} "
        f"client_batch_wall_s={client_batch_wall_seconds:.9f} "
        f"client_to_server_bytes={client_to_server_bytes} "
        f"active_client_to_server_bytes={active_client_to_server_bytes} "
        f"dropout_client_to_server_bytes={dropout_client_to_server_bytes} "
        f"active_client_bytes_mean={active_client_bytes_mean:.3f} "
        f"dropout_client_bytes_mean={dropout_client_bytes_mean:.3f} "
        f"client_to_verifier_bytes=0 server_to_verifier_bytes={server_to_verifier_bytes} "
        "committee_bytes=0 "
        f"server_receive_bytes={client_to_server_bytes} "
        f"server_send_bytes={server_to_verifier_bytes} "
        f"verifier_receive_bytes={server_to_verifier_bytes} "
        f"total_bytes={total_bytes} g1_serialized_bytes={signature_size} "
        f"gt_serialized_bytes={recovery_size} honest_correctness=pass "
        "forged_server_rejection=pass timing_scope=verification_increment_only "
        "wire=actual_charm_compressed_binary_without_base64_transport"
    )


if __name__ == "__main__":
    main()
