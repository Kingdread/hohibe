use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use hohibe::hibe::{Hibe, BonehBoyenGoh};

fn rng() -> impl Rng {
    ChaChaRng::from_seed([0; 32])
}

fn setup(c: &mut Criterion) {
    let mut rng = rng();
    let bbg = BonehBoyenGoh::new(32);
    c.bench_function("BonehBoyenGoh::setup(32)", |b| {
        b.iter(|| bbg.setup(&mut rng));
    });
}

fn generate_key(c: &mut Criterion) {
    let mut rng = rng();
    let bbg = BonehBoyenGoh::new(32);
    let identity = &[0u32.into(), 1u32.into(), 2u32.into()];
    let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
    c.bench_function("BonehBoyenGoh::generate_key(32)", |b| {
        b.iter(|| bbg.generate_key(&mut rng, &public_key, &master_key, identity).unwrap());
    });
}

fn derive_key(c: &mut Criterion) {
    let mut rng = rng();
    let bbg = BonehBoyenGoh::new(32);
    let identity = &[0u32.into(), 1u32.into(), 2u32.into()];
    let (public_key, master_key) = bbg.setup(&mut rng).unwrap();
    let key = bbg.generate_key(&mut rng, &public_key, &master_key, identity).unwrap();
    c.bench_function("BonehBoyenGoh::derive_key(32)", |b| {
        b.iter(|| bbg.derive_key(&mut rng, &public_key, &key, identity, &3u32.into()).unwrap());
    });
}

criterion_group!(benches, setup, generate_key, derive_key);
criterion_main!(benches);
