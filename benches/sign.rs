use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fafrost::keygen::generate_with_dealer;
use fafrost::sign::{SignatureShare, SigningPackage, aggregate, commit, sign};
use fafrost::utils::encode_commitments;
use rand_core::OsRng;
use std::collections::BTreeMap;

const CONFIGS: &[(u16, u16)] = &[(4, 32), (8, 32), (16, 32), (32, 64), (48, 64), (64, 128)];

struct Setup {
    signing_package: SigningPackage,
    key_package: fafrost::keygen::KeyPackage,
    nonce: fafrost::sign::SigningNonces,
    pubkeys: fafrost::keygen::PublicKeyPackage,
    signature_shares: BTreeMap<Identifier, SignatureShare>,
    ids: Vec<u16>,
    commitments_bytes: Vec<u8>,
    message: [u8; 32],
}

type Identifier = u16;

fn make_setup(min_signers: u16, max_signers: u16) -> Setup {
    let mut rng = OsRng;
    let (shares, pubkeys) = generate_with_dealer(max_signers, min_signers, &mut rng);

    let signer_ids: Vec<Identifier> = (1..=min_signers).collect();
    let message = [42u8; 32];

    let mut commitments = BTreeMap::new();
    let mut nonces_map = BTreeMap::new();
    for &id in &signer_ids {
        let (nonce, commitment) = commit(&mut rng);
        nonces_map.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let commitments_bytes = encode_commitments(&commitments);

    let signing_package = SigningPackage {
        message,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();
    for &id in &signer_ids {
        let share = sign(&signing_package, &nonces_map[&id], &shares[&id], &pubkeys);
        signature_shares.insert(id, share);
    }

    let key_package = shares[&signer_ids[0]].clone();
    let nonce = nonces_map.remove(&signer_ids[0]).unwrap();

    Setup {
        signing_package,
        key_package,
        nonce,
        pubkeys,
        signature_shares,
        ids: signer_ids,
        commitments_bytes,
        message,
    }
}

fn bench_commit(c: &mut Criterion) {
    let mut rng = OsRng;
    c.bench_function("commit", |b| b.iter(|| commit(&mut rng)));
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");

    for &(min, max) in CONFIGS {
        let s = make_setup(min, max);
        group.bench_with_input(
            BenchmarkId::new("full", format!("{min}/{max}")),
            &(),
            |b, _| b.iter(|| sign(&s.signing_package, &s.nonce, &s.key_package, &s.pubkeys)),
        );
    }

    group.finish();
}

fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate");

    for &(min, max) in CONFIGS {
        let s = make_setup(min, max);
        group.bench_with_input(
            BenchmarkId::new("full", format!("{min}/{max}")),
            &(),
            |b, _| b.iter(|| aggregate(&s.signing_package, &s.signature_shares)),
        );
    }

    group.finish();
}

fn bench_blinding(c: &mut Criterion) {
    let mut group = c.benchmark_group("blinding_scalar");

    for &(min, max) in CONFIGS {
        let s = make_setup(min, max);
        group.bench_with_input(
            BenchmarkId::new("blinding", format!("{min}/{max}")),
            &(),
            |b, _| {
                b.iter(|| {
                    s.key_package
                        .blinding_scalar(&s.ids, &s.commitments_bytes, &s.message)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_commit,
    bench_sign,
    bench_aggregate,
    bench_blinding
);
criterion_main!(benches);
