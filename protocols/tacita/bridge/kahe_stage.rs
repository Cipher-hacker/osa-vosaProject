// Shell KAHE API and mask arithmetic adapted from the user's Apache-2.0
// secure-aggregation-main project. This is an in-process benchmark fixture.
use aggregation_config::AggregationConfig;
use kahe_traits::{KaheBase, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto};
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use shell_ciphertexts_rust_proto::ShellKaheCiphertext;
use shell_kahe::{Ciphertext, ShellKahe};
use shell_parameters::create_shell_configs;
use shell_parameters_generation::{divide_and_roundup, generate_packing_config};
use single_thread_hkdf::SingleThreadHkdfPrng;
use std::{
    collections::HashMap,
    env, fs,
    io::{self, BufRead, Write},
    time::Instant,
};

fn mask(seed: &[u8], count: usize, bits: usize) -> Vec<u64> {
    let mut h = Shake256::default();
    h.update(b"TACITA_STE_KAHE_RING_MASK_V1");
    h.update(seed);
    let mut reader = h.finalize_xof();
    let mut out = vec![0; count * 4];
    for coefficient in out.chunks_exact_mut(4) {
        for limb in coefficient.iter_mut() {
            let mut b = [0; 8];
            reader.read(&mut b);
            *limb = u64::from_le_bytes(b);
        }
        truncate(coefficient, bits);
    }
    out
}
fn truncate(v: &mut [u64], bits: usize) {
    for (i, x) in v.iter_mut().enumerate() {
        let keep = bits.saturating_sub(i * 64).min(64);
        if keep == 0 {
            *x = 0;
        } else if keep < 64 {
            *x &= (1u64 << keep) - 1;
        }
    }
}
fn add_mask(a: &mut [u64], b: &[u64], bits: usize) {
    assert_eq!(a.len(), b.len());
    for (a, b) in a.chunks_exact_mut(4).zip(b.chunks_exact(4)) {
        let mut carry = false;
        for i in 0..4 {
            let (s, c) = a[i].overflowing_add(b[i]);
            let (s2, c2) = s.overflowing_add(carry as u64);
            a[i] = s2;
            carry = c || c2;
        }
        truncate(a, bits);
    }
}
fn nums<T: std::str::FromStr>(s: &str) -> Vec<T>
where
    T::Err: std::fmt::Debug,
{
    s.split_whitespace().map(|x| x.parse().unwrap()).collect()
}
fn main() {
    let args: Vec<_> = env::args().collect();
    assert!(args.len() == 8 || (args.len() == 9 && args[8] == "--fixed-profile"),
        "usage: kahe_stage N ACTIVE L M T mask_seeds.txt keys.txt [--fixed-profile]");
    let fixed = args.len() == 9;
    let n: usize = args[1].parse().unwrap();
    let active: usize = args[2].parse().unwrap();
    let len: usize = args[3].parse().unwrap();
    let m: usize = args[4].parse().unwrap();
    let t: usize = args[5].parse().unwrap();
    assert!(active > 0 && active <= n && len > 0 && t > 0 && t <= m);
    let seeds: Vec<Vec<u8>> = fs::read_to_string(&args[6])
        .unwrap()
        .lines()
        .map(nums)
        .collect();
    assert_eq!(seeds.len(), active);
    assert!(seeds.iter().all(|s| s.len() == 32));
    let start = Instant::now();
    let config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([("default".into(), (len as isize, 255))]),
        max_number_of_clients: n as i64,
        max_number_of_decryptors: m as i64,
        max_decryptor_dropouts: (m - t) as i64,
        key_id: b"tacita-ste-kahe".to_vec(),
    };
    let (config, _) = if fixed {
        assert!(len <= 100_000 && n <= 10_000_000 && m <= 100,
            "fixed upstream 100K profile requires L<=100000, N<=10000000, m<=100");
        // Select the existing upstream parameter row once. Repack the
        // actual vector, not a padded 100K vector; ring and noise are unchanged.
        let profile = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([("default".into(), (100_000, 255))]),
            max_number_of_clients: config.max_number_of_clients,
            max_number_of_decryptors: config.max_number_of_decryptors,
            max_decryptor_dropouts: config.max_decryptor_dropouts,
            key_id: config.key_id.clone(),
        };
        let (mut chosen, ahe) = create_shell_configs(&profile).unwrap();
        chosen.packed_vector_configs = generate_packing_config(chosen.log_t, &config).unwrap();
        let count: usize = chosen.packed_vector_configs.values().map(|p| p.num_packed_coeffs as usize).sum();
        chosen.num_public_polynomials = divide_and_roundup(count, 1 << chosen.log_n);
        (chosen, ahe)
    } else { create_shell_configs(&config).unwrap() };
    let log_n = config.log_n;
    let log_t = config.log_t;
    let moduli = config.moduli.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
    let kahe = ShellKahe::new(config, b"tacita-ste-kahe-stage-v1").unwrap();
    let setup = start.elapsed().as_secs_f64();
    let mut messages = Vec::new();
    let mut keys = Vec::new();
    let mut client_times = Vec::new();
    for i in 0..active {
        let values = if fixed { (0..len).map(|j| ((i * 73 + j * 19 + 11) % 256) as u64).collect() }
            else { vec![if i < 7 { 1u64 } else { 0 }; len] };
        let pt = HashMap::from([("default", values.as_slice())]);
        let start = Instant::now();
        let mut rng =
            SingleThreadHkdfPrng::create(&SingleThreadHkdfPrng::generate_seed().unwrap()).unwrap();
        let key = kahe.key_gen(&mut rng).unwrap();
        let mask = mask(
            &seeds[i],
            kahe.packed_coefficient_count(),
            kahe.plaintext_modulus_bits(),
        );
        let ct = kahe
            .encrypt_with_ring_mask(&pt, &key, &mask, &mut rng)
            .unwrap();
        let bytes = ct.to_proto(&kahe).unwrap().serialize().unwrap().to_vec();
        let key = kahe.try_secret_key_into(key).unwrap();
        client_times.push(start.elapsed().as_secs_f64());
        messages.push(bytes);
        keys.push(key);
    }
    let mut keyfile = fs::File::create(&args[7]).unwrap();
    for key in &keys {
        writeln!(
            keyfile,
            "{}",
            key.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        )
        .unwrap();
    }
    drop(keyfile);
    drop(keys);
    let client_bytes: usize = messages.iter().map(Vec::len).sum();
    let start = Instant::now();
    let mut sum: Option<Ciphertext> = None;
    for bytes in messages {
        let proto = ShellKaheCiphertext::parse(&bytes).unwrap();
        let ct = Ciphertext::from_proto(proto, &kahe).unwrap();
        match &mut sum {
            Some(s) => kahe.add_ciphertexts_in_place(&ct, s).unwrap(),
            None => sum = Some(ct),
        }
    }
    let server_pre = start.elapsed().as_secs_f64();
    println!("ready setup_s={setup} client_mean_s={} client_serial_wall_s={} server_pre_s={server_pre} client_bytes={client_bytes} profile={} log_n={log_n} log_t={log_t} moduli={moduli} packed_coefficients={} public_polynomials={}",client_times.iter().sum::<f64>()/active as f64,client_times.iter().sum::<f64>(), if fixed { "fixed-upstream-100k" } else { "legacy-auto" }, kahe.packed_coefficient_count(), kahe.public_polynomial_count());
    io::stdout().flush().unwrap();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let key: Vec<i64> = nums(&lines.next().expect("missing recovered key").unwrap());
    let recovered: Vec<Vec<u8>> = (0..active)
        .map(|_| nums(&lines.next().expect("missing recovered mask seed").unwrap()))
        .collect();
    assert!(recovered.iter().all(|s| s.len() == 32));
    let start = Instant::now();
    let key = kahe.try_secret_key_from(key).unwrap();
    let mut masks = vec![0u64; kahe.packed_coefficient_count() * 4];
    for seed in recovered {
        add_mask(
            &mut masks,
            &mask(
                &seed,
                kahe.packed_coefficient_count(),
                kahe.plaintext_modulus_bits(),
            ),
            kahe.plaintext_modulus_bits(),
        );
    }
    let result = kahe
        .decrypt_with_ring_mask(&sum.unwrap(), &key, &masks)
        .unwrap();
    let final_s = start.elapsed().as_secs_f64();
    let values = result.get("default").unwrap();
    assert_eq!(values.len(), len);
    for (j, value) in values.iter().enumerate() {
        let expected = if fixed { (0..active).map(|i| ((i * 73 + j * 19 + 11) % 256) as u64).sum() }
            else { active.min(7) as u64 };
        assert_eq!(*value, expected, "KAHE aggregate mismatch at coordinate {j}");
    }
    println!("done server_finalize_s={final_s} correctness=pass");
}
