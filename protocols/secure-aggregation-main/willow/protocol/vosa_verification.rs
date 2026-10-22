// Copyright 2026
//
// Verification-only implementation of VOSA Figure 2. Common OSA secure-
// aggregation work is supplied as precomputed aggregate input and digest mask.

use kahe_traits::KaheBase;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::{Parse, Serialize};
use shell_ciphertexts_rust_proto::ShellKaheCiphertext;
use shell_kahe::{Ciphertext, ShellKahe};
use single_thread_hkdf::SingleThreadHkdfPrng;
use std::collections::{BTreeSet, HashMap};

const WIRE_MAGIC: &[u8; 4] = b"VOSA";
const WIRE_VERSION: u8 = 1;
const CLIENT_RANDOMNESS_KIND: u8 = 1;
const CLIENT_COMMITMENT_KIND: u8 = 2;
const SERVER_OPENING_KIND: u8 = 3;

#[derive(Debug, Clone)]
pub struct VosaClientMessages {
    pub to_server: Vec<u8>,
    pub to_verifier: Vec<u8>,
}

#[derive(Debug)]
struct ClientRandomnessMessage {
    iteration: u64,
    client_id: u64,
    randomness: Vec<Vec<i64>>,
}

struct ClientCommitmentMessage {
    iteration: u64,
    client_id: u64,
    commitment: Ciphertext,
}

#[derive(Debug)]
struct ServerOpeningMessage {
    iteration: u64,
    active_client_ids: Vec<u64>,
    aggregate_input: Vec<u64>,
    aggregate_ring_mask_limbs: Vec<u64>,
    aggregate_randomness: Vec<Vec<i64>>,
}

/// Creates the two online messages added by VOSA for one client.
pub fn create_client_messages(
    iteration: u64,
    client_id: u64,
    plaintext: &HashMap<&str, &[u64]>,
    ring_mask_limbs: &[u64],
    kahe: &ShellKahe,
    rng: &mut SingleThreadHkdfPrng,
) -> Result<VosaClientMessages, status::StatusError> {
    let result = kahe.vosa_commit(plaintext, ring_mask_limbs, rng)?;
    let to_server = serialize_client_randomness(iteration, client_id, &result.randomness)?;
    let to_verifier =
        serialize_client_commitment(iteration, client_id, &result.commitment, kahe)?;
    Ok(VosaClientMessages { to_server, to_verifier })
}

/// Aggregates the client openings and serializes the server-to-verifier message.
/// The aggregate input and digest mask are outputs of the common OSA path and
/// are intentionally not recomputed here.
pub fn create_server_opening(
    iteration: u64,
    active_client_ids: &[u64],
    client_randomness_messages: &[Vec<u8>],
    aggregate_input: &[u64],
    aggregate_ring_mask_limbs: &[u64],
    expected_randomness_polynomials: usize,
    expected_coefficients_per_polynomial: usize,
) -> Result<Vec<u8>, status::StatusError> {
    validate_sorted_unique_ids(active_client_ids)?;
    if active_client_ids.len() != client_randomness_messages.len() {
        return Err(status::invalid_argument(
            "active set and client randomness message counts differ",
        ));
    }

    let expected_ids = active_client_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut received_ids = BTreeSet::new();
    let mut aggregate_randomness = vec![
        vec![0_i64; expected_coefficients_per_polynomial];
        expected_randomness_polynomials
    ];

    for bytes in client_randomness_messages {
        let message = parse_client_randomness(
            bytes,
            expected_randomness_polynomials,
            expected_coefficients_per_polynomial,
        )?;
        if message.iteration != iteration {
            return Err(status::failed_precondition("client iteration mismatch"));
        }
        if !received_ids.insert(message.client_id) {
            return Err(status::failed_precondition("duplicate client randomness message"));
        }
        for (aggregate_poly, client_poly) in
            aggregate_randomness.iter_mut().zip(message.randomness.iter())
        {
            for (aggregate, client) in aggregate_poly.iter_mut().zip(client_poly.iter()) {
                *aggregate = aggregate.checked_add(*client).ok_or_else(|| {
                    status::out_of_range("aggregate VOSA randomness overflows i64")
                })?;
            }
        }
    }
    if received_ids != expected_ids {
        return Err(status::failed_precondition(
            "client randomness messages do not match the active set",
        ));
    }

    serialize_server_opening(&ServerOpeningMessage {
        iteration,
        active_client_ids: active_client_ids.to_vec(),
        aggregate_input: aggregate_input.to_vec(),
        aggregate_ring_mask_limbs: aggregate_ring_mask_limbs.to_vec(),
        aggregate_randomness,
    })
}

/// Verifies the selected set, aggregate randomness bound, and the VOSA ring
/// equation `sum(ct_i) = a * sum(r_i) + sum(x_i) + sum(H(dig_i))`.
pub fn verify_server_opening(
    expected_iteration: u64,
    vector_id: &str,
    client_commitment_messages: &[Vec<u8>],
    server_opening_bytes: &[u8],
    aggregate_randomness_abs_bound: u64,
    kahe: &ShellKahe,
) -> Result<(), status::StatusError> {
    let opening = parse_server_opening(
        server_opening_bytes,
        kahe.public_polynomial_count(),
        kahe.ring_coefficient_count(),
    )?;
    if opening.iteration != expected_iteration {
        return Err(status::failed_precondition("server iteration mismatch"));
    }
    validate_sorted_unique_ids(&opening.active_client_ids)?;
    if opening.aggregate_ring_mask_limbs.len() != kahe.packed_coefficient_count() * 4 {
        return Err(status::invalid_argument("aggregate ring mask length mismatch"));
    }
    for coefficient in opening.aggregate_randomness.iter().flatten() {
        if coefficient.unsigned_abs() > aggregate_randomness_abs_bound {
            return Err(status::failed_precondition(
                "aggregate VOSA randomness exceeds the protocol norm bound",
            ));
        }
    }

    if client_commitment_messages.is_empty() {
        return Err(status::invalid_argument("at least one client commitment is required"));
    }
    let expected_ids = opening.active_client_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut received_ids = BTreeSet::new();
    let mut commitment_sum: Option<Ciphertext> = None;
    for bytes in client_commitment_messages {
        let message = parse_client_commitment(bytes, kahe)?;
        if message.iteration != expected_iteration {
            return Err(status::failed_precondition("client commitment iteration mismatch"));
        }
        if !received_ids.insert(message.client_id) {
            return Err(status::failed_precondition("duplicate client commitment message"));
        }
        if let Some(sum) = commitment_sum.as_mut() {
            kahe.add_ciphertexts_in_place(&message.commitment, sum)?;
        } else {
            commitment_sum = Some(message.commitment);
        }
    }
    if received_ids != expected_ids {
        return Err(status::failed_precondition(
            "client commitment messages do not match the server active set",
        ));
    }

    let plaintext = HashMap::from([(vector_id, opening.aggregate_input.as_slice())]);
    let expected = kahe.vosa_opening_rhs(
        &plaintext,
        &opening.aggregate_ring_mask_limbs,
        &opening.aggregate_randomness,
    )?;
    let actual_bytes = commitment_sum
        .expect("non-empty commitment list checked above")
        .to_proto(kahe)?
        .serialize()
        .map_err(|error| status::internal(&format!("serialize commitment sum: {error}")))?;
    let expected_bytes = expected
        .to_proto(kahe)?
        .serialize()
        .map_err(|error| status::internal(&format!("serialize expected commitment: {error}")))?;
    if actual_bytes != expected_bytes {
        return Err(status::failed_precondition("VOSA commitment equation failed"));
    }
    Ok(())
}

fn serialize_client_randomness(
    iteration: u64,
    client_id: u64,
    randomness: &[Vec<i64>],
) -> Result<Vec<u8>, status::StatusError> {
    let mut out = begin_message(CLIENT_RANDOMNESS_KIND);
    push_u64(&mut out, iteration);
    push_u64(&mut out, client_id);
    push_randomness(&mut out, randomness)?;
    Ok(out)
}

fn serialize_client_commitment(
    iteration: u64,
    client_id: u64,
    commitment: &Ciphertext,
    kahe: &ShellKahe,
) -> Result<Vec<u8>, status::StatusError> {
    let proto_bytes = commitment
        .to_proto(kahe)?
        .serialize()
        .map_err(|error| status::internal(&format!("serialize VOSA commitment: {error}")))?;
    let mut out = begin_message(CLIENT_COMMITMENT_KIND);
    push_u64(&mut out, iteration);
    push_u64(&mut out, client_id);
    push_blob(&mut out, &proto_bytes)?;
    Ok(out)
}

fn serialize_server_opening(
    opening: &ServerOpeningMessage,
) -> Result<Vec<u8>, status::StatusError> {
    let mut out = begin_message(SERVER_OPENING_KIND);
    push_u64(&mut out, opening.iteration);
    push_u32(&mut out, checked_u32(opening.active_client_ids.len(), "active client count")?);
    for client_id in &opening.active_client_ids {
        push_u64(&mut out, *client_id);
    }
    push_u32(&mut out, checked_u32(opening.aggregate_input.len(), "input length")?);
    for value in &opening.aggregate_input {
        push_u64(&mut out, *value);
    }
    push_u32(
        &mut out,
        checked_u32(opening.aggregate_ring_mask_limbs.len(), "ring mask length")?,
    );
    for limb in &opening.aggregate_ring_mask_limbs {
        push_u64(&mut out, *limb);
    }
    push_randomness(&mut out, &opening.aggregate_randomness)?;
    Ok(out)
}

fn parse_client_randomness(
    bytes: &[u8],
    expected_polynomials: usize,
    expected_coefficients: usize,
) -> Result<ClientRandomnessMessage, status::StatusError> {
    let mut reader = Reader::new(bytes, CLIENT_RANDOMNESS_KIND)?;
    let iteration = reader.read_u64()?;
    let client_id = reader.read_u64()?;
    let randomness = reader.read_randomness(expected_polynomials, expected_coefficients)?;
    reader.finish()?;
    Ok(ClientRandomnessMessage { iteration, client_id, randomness })
}

fn parse_client_commitment(
    bytes: &[u8],
    kahe: &ShellKahe,
) -> Result<ClientCommitmentMessage, status::StatusError> {
    let mut reader = Reader::new(bytes, CLIENT_COMMITMENT_KIND)?;
    let iteration = reader.read_u64()?;
    let client_id = reader.read_u64()?;
    let proto_bytes = reader.read_blob()?;
    reader.finish()?;
    let proto = ShellKaheCiphertext::parse(proto_bytes)
        .map_err(|error| status::data_loss(&format!("parse VOSA commitment: {error}")))?;
    let commitment = Ciphertext::from_proto(proto, kahe)?;
    Ok(ClientCommitmentMessage { iteration, client_id, commitment })
}

fn parse_server_opening(
    bytes: &[u8],
    expected_polynomials: usize,
    expected_coefficients: usize,
) -> Result<ServerOpeningMessage, status::StatusError> {
    let mut reader = Reader::new(bytes, SERVER_OPENING_KIND)?;
    let iteration = reader.read_u64()?;
    let active_count = reader.read_count_for_fixed_items(8, "active client count")?;
    let mut active_client_ids = Vec::with_capacity(active_count);
    for _ in 0..active_count {
        active_client_ids.push(reader.read_u64()?);
    }
    let input_count = reader.read_count_for_fixed_items(8, "input length")?;
    let mut aggregate_input = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        aggregate_input.push(reader.read_u64()?);
    }
    let mask_count = reader.read_count_for_fixed_items(8, "ring mask length")?;
    let mut aggregate_ring_mask_limbs = Vec::with_capacity(mask_count);
    for _ in 0..mask_count {
        aggregate_ring_mask_limbs.push(reader.read_u64()?);
    }
    let aggregate_randomness =
        reader.read_randomness(expected_polynomials, expected_coefficients)?;
    reader.finish()?;
    Ok(ServerOpeningMessage {
        iteration,
        active_client_ids,
        aggregate_input,
        aggregate_ring_mask_limbs,
        aggregate_randomness,
    })
}

fn begin_message(kind: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(WIRE_MAGIC);
    out.push(WIRE_VERSION);
    out.push(kind);
    out
}

fn push_randomness(
    out: &mut Vec<u8>,
    randomness: &[Vec<i64>],
) -> Result<(), status::StatusError> {
    push_u32(out, checked_u32(randomness.len(), "randomness polynomial count")?);
    for polynomial in randomness {
        push_u32(out, checked_u32(polynomial.len(), "randomness coefficient count")?);
        for coefficient in polynomial {
            push_var_u64(out, zigzag_encode(*coefficient));
        }
    }
    Ok(())
}

fn push_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), status::StatusError> {
    push_u32(out, checked_u32(value.len(), "blob length")?);
    out.extend_from_slice(value);
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn zigzag_encode(value: i64) -> u64 {
    ((value as u64) << 1) ^ ((value >> 63) as u64)
}

fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn checked_u32(value: usize, label: &str) -> Result<u32, status::StatusError> {
    u32::try_from(value).map_err(|_| status::out_of_range(&format!("{label} exceeds u32")))
}

fn validate_sorted_unique_ids(ids: &[u64]) -> Result<(), status::StatusError> {
    if ids.is_empty() {
        return Err(status::invalid_argument("active client set cannot be empty"));
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(status::invalid_argument(
            "active client IDs must be strictly increasing",
        ));
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], expected_kind: u8) -> Result<Self, status::StatusError> {
        if bytes.len() < 6 || &bytes[..4] != WIRE_MAGIC {
            return Err(status::data_loss("invalid VOSA wire magic"));
        }
        if bytes[4] != WIRE_VERSION {
            return Err(status::data_loss("unsupported VOSA wire version"));
        }
        if bytes[5] != expected_kind {
            return Err(status::data_loss("unexpected VOSA message kind"));
        }
        Ok(Self { bytes, offset: 6 })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], status::StatusError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| status::data_loss("VOSA message offset overflow"))?;
        if end > self.bytes.len() {
            return Err(status::data_loss("truncated VOSA message"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn read_u32(&mut self) -> Result<u32, status::StatusError> {
        let mut encoded = [0_u8; 4];
        encoded.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(encoded))
    }

    fn read_u64(&mut self) -> Result<u64, status::StatusError> {
        let mut encoded = [0_u8; 8];
        encoded.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(encoded))
    }

    fn read_var_u64(&mut self) -> Result<u64, status::StatusError> {
        let start = self.offset;
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = self.read_exact(1)?[0];
            if shift == 63 && byte > 1 {
                return Err(status::data_loss("VOSA varint overflows u64"));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if self.offset - start != var_u64_len(value) {
                    return Err(status::data_loss("non-canonical VOSA varint"));
                }
                return Ok(value);
            }
        }
        Err(status::data_loss("unterminated VOSA varint"))
    }

    fn read_blob(&mut self) -> Result<&'a [u8], status::StatusError> {
        let length = self.read_u32()? as usize;
        self.read_exact(length)
    }

    fn read_count_for_fixed_items(
        &mut self,
        item_bytes: usize,
        label: &str,
    ) -> Result<usize, status::StatusError> {
        let count = self.read_u32()? as usize;
        if count > self.bytes.len().saturating_sub(self.offset) / item_bytes {
            return Err(status::data_loss(&format!("invalid {label}")));
        }
        Ok(count)
    }

    fn read_randomness(
        &mut self,
        expected_polynomials: usize,
        expected_coefficients: usize,
    ) -> Result<Vec<Vec<i64>>, status::StatusError> {
        let polynomials = self.read_u32()? as usize;
        if polynomials != expected_polynomials {
            return Err(status::data_loss("VOSA randomness polynomial count mismatch"));
        }
        let mut result = Vec::with_capacity(polynomials);
        for _ in 0..polynomials {
            let coefficients = self.read_u32()? as usize;
            if coefficients != expected_coefficients {
                return Err(status::data_loss("VOSA randomness coefficient count mismatch"));
            }
            if coefficients > self.bytes.len().saturating_sub(self.offset) {
                return Err(status::data_loss("truncated VOSA randomness"));
            }
            let mut polynomial = Vec::with_capacity(coefficients);
            for _ in 0..coefficients {
                polynomial.push(zigzag_decode(self.read_var_u64()?));
            }
            result.push(polynomial);
        }
        Ok(result)
    }

    fn finish(self) -> Result<(), status::StatusError> {
        if self.offset != self.bytes.len() {
            return Err(status::data_loss("trailing bytes in VOSA message"));
        }
        Ok(())
    }
}

fn var_u64_len(mut value: u64) -> usize {
    let mut result = 1;
    while value >= 0x80 {
        value >>= 7;
        result += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahe::PackedVectorConfig;
    use prng_traits::SecurePrng;
    use shell_testing_parameters::make_kahe_config_for;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use std::collections::BTreeMap;

    const VECTOR_ID: &str = "default";
    const CONTEXT: &[u8] = b"vosa_verification_test_v1";

    fn make_test_kahe() -> ShellKahe {
        let packed = BTreeMap::from([(
            VECTOR_ID.to_string(),
            PackedVectorConfig { base: 100, dimension: 2, num_packed_coeffs: 2, length: 4 },
        )]);
        ShellKahe::new(make_kahe_config_for(17, packed).unwrap(), CONTEXT).unwrap()
    }

    #[test]
    fn honest_opening_passes_and_tampering_fails() {
        let kahe = make_test_kahe();
        let inputs = [vec![1_u64, 2, 3, 4], vec![4_u64, 3, 2, 1]];
        let mut masks = [
            vec![0_u64; kahe.packed_coefficient_count() * 4],
            vec![0_u64; kahe.packed_coefficient_count() * 4],
        ];
        for coefficient in masks[0].chunks_exact_mut(4) {
            coefficient[0] = 10;
        }
        for coefficient in masks[1].chunks_exact_mut(4) {
            coefficient[0] = 20;
        }
        let mut messages = Vec::new();
        for (index, input) in inputs.iter().enumerate() {
            let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
            let mut rng = SingleThreadHkdfPrng::create(&seed).unwrap();
            let plaintext = HashMap::from([(VECTOR_ID, input.as_slice())]);
            messages.push(
                create_client_messages(
                    7,
                    index as u64 + 1,
                    &plaintext,
                    &masks[index],
                    &kahe,
                    &mut rng,
                )
                .unwrap(),
            );
        }
        let active_ids = vec![1_u64, 2];
        let aggregate_input = vec![5_u64; 4];
        let mut aggregate_mask = vec![0_u64; kahe.packed_coefficient_count() * 4];
        for coefficient in aggregate_mask.chunks_exact_mut(4) {
            coefficient[0] = 30;
        }
        let to_server = messages.iter().map(|message| message.to_server.clone()).collect::<Vec<_>>();
        let to_verifier =
            messages.iter().map(|message| message.to_verifier.clone()).collect::<Vec<_>>();
        let opening = create_server_opening(
            7,
            &active_ids,
            &to_server,
            &aggregate_input,
            &aggregate_mask,
            kahe.public_polynomial_count(),
            kahe.ring_coefficient_count(),
        )
        .unwrap();
        verify_server_opening(7, VECTOR_ID, &to_verifier, &opening, 2 * 37, &kahe).unwrap();

        let tampered_opening = create_server_opening(
            7,
            &active_ids,
            &to_server,
            &[6_u64, 5, 5, 5],
            &aggregate_mask,
            kahe.public_polynomial_count(),
            kahe.ring_coefficient_count(),
        )
        .unwrap();
        assert!(
            verify_server_opening(
                7,
                VECTOR_ID,
                &to_verifier,
                &tampered_opening,
                2 * 37,
                &kahe,
            )
            .is_err()
        );

        let mut tampered_commitments = to_verifier.clone();
        let last = tampered_commitments[0].len() - 1;
        tampered_commitments[0][last] ^= 1;
        assert!(
            verify_server_opening(
                7,
                VECTOR_ID,
                &tampered_commitments,
                &opening,
                2 * 37,
                &kahe,
            )
            .is_err()
        );
    }

    #[test]
    fn randomness_codec_rejects_noncanonical_varint() {
        let mut encoded = begin_message(CLIENT_RANDOMNESS_KIND);
        push_u64(&mut encoded, 1);
        push_u64(&mut encoded, 1);
        push_u32(&mut encoded, 1);
        push_u32(&mut encoded, 1);
        encoded.extend_from_slice(&[0x80, 0x00]);
        assert!(parse_client_randomness(&encoded, 1, 1).is_err());
    }
}
