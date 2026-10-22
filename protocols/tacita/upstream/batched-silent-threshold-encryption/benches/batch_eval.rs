use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_batched_threshold_encryption::bte::{
    batch_eval, crs::CRS, fft_batch_eval, naive_batch_eval, PRF, PPRF,
};

type E = ark_bls12_381::Bls12_381;

fn bench_batch_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_eval");
    group.sample_size(10);
    let mut rng = ark_std::test_rng();

    for &batch_size in &[8usize, 32, 128] {
        let crs = CRS::<E>::new(batch_size, &mut rng);

        let prfs: Vec<PRF<E>> = (0..batch_size)
            .map(|_| PRF::<E>::new(&mut rng))
            .collect();
        let pprfs: Vec<PPRF<E>> = prfs
            .iter()
            .enumerate()
            .map(|(i, p)| p.puncture(i, &crs))
            .collect();

        let k_agg_scalar = prfs.iter().map(|p| p.key).fold(
            <E as ark_ec::pairing::Pairing>::ScalarField::from(0u64),
            |acc, k| acc + k,
        );
        let k_agg = PRF::<E>::from_key(k_agg_scalar);

        // Single-output cost (for reference)
        let input = batch_size / 2;
        group.bench_with_input(
            BenchmarkId::new("naive_batch_eval (1 output)", batch_size),
            &batch_size,
            |b, _| b.iter(|| naive_batch_eval(&pprfs, input, &crs)),
        );
        group.bench_with_input(
            BenchmarkId::new("batch_eval (1 output)", batch_size),
            &batch_size,
            |b, _| b.iter(|| batch_eval(&pprfs, input, &crs)),
        );

        // Full-loop cost — what decryption actually does
        // batch_eval_loop: B multi-pairings (current decrypt path, O(B²) pairings total)
        group.bench_with_input(
            BenchmarkId::new("batch_eval_loop (B outputs)", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    (0..batch_size)
                        .map(|i| k_agg.eval(i, &crs) - batch_eval(&pprfs, i, &crs))
                        .collect::<Vec<_>>()
                })
            },
        );

        // fft_batch_eval: 1 FFT pass (new path, O(B log B) group ops + O(B) pairings)
        group.bench_with_input(
            BenchmarkId::new("fft_batch_eval (B outputs)", batch_size),
            &batch_size,
            |b, _| b.iter(|| fft_batch_eval(&k_agg, &pprfs, &crs)),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_batch_eval);
criterion_main!(benches);
