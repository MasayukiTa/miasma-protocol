use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use miasma_core::crypto::{
    aead::{decrypt, encrypt_with_key},
    hash::ContentId,
    rs::{rs_decode, rs_encode, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS},
    sss::{sss_combine, sss_split},
};

const MB_100: usize = 100 * 1024 * 1024;

fn bench_blake3(c: &mut Criterion) {
    let data = vec![0x5Au8; MB_100];
    let mut g = c.benchmark_group("BLAKE3");
    g.throughput(Throughput::Bytes(MB_100 as u64));
    // SLO: 100MB ≤ 150ms on ARM64
    g.bench_function("100MB MID compute", |b| {
        b.iter(|| ContentId::compute(black_box(&data), b"k=10,n=20,v=1"))
    });
    g.finish();
}

fn bench_aes_gcm(c: &mut Criterion) {
    let data = vec![0x42u8; MB_100];
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let ciphertext = encrypt_with_key(&data, &key, &nonce).unwrap();

    let mut g = c.benchmark_group("AES-256-GCM");
    g.throughput(Throughput::Bytes(MB_100 as u64));
    // SLO: 100MB ≤ 200ms on ARM64
    g.bench_function("100MB encrypt", |b| {
        b.iter(|| encrypt_with_key(black_box(&data), &key, &nonce).unwrap())
    });
    g.bench_function("100MB decrypt", |b| {
        b.iter(|| decrypt(black_box(&ciphertext), &key, &nonce).unwrap())
    });
    g.finish();
}

fn bench_reed_solomon(c: &mut Criterion) {
    let data = vec![0x5Au8; MB_100];
    let shards = rs_encode(&data, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
    let indexed: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();

    let mut g = c.benchmark_group("Reed-Solomon");
    g.throughput(Throughput::Bytes(MB_100 as u64));
    // SLO: 100MB ≤ 300ms on ARM64
    g.bench_function("100MB encode", |b| {
        b.iter(|| rs_encode(black_box(&data), DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap())
    });
    g.bench_function("100MB decode (all shards)", |b| {
        b.iter(|| {
            rs_decode(
                black_box(&indexed),
                DEFAULT_DATA_SHARDS,
                DEFAULT_TOTAL_SHARDS,
                data.len(),
            )
            .unwrap()
        })
    });
    g.finish();
}

fn bench_sss(c: &mut Criterion) {
    let secret = [0xABu8; 32];
    let k = 10u8;
    let n = 20u8;
    let shares = sss_split(&secret, k, n).unwrap();

    let mut g = c.benchmark_group("SSS");
    g.bench_function("split k=10 n=20", |b| {
        b.iter(|| sss_split(black_box(&secret), k, n).unwrap())
    });
    g.bench_function("combine k=10 from 10 shares", |b| {
        b.iter(|| sss_combine(black_box(&shares[..10]), k).unwrap())
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_blake3,
    bench_aes_gcm,
    bench_reed_solomon,
    bench_sss
);
criterion_main!(benches);
