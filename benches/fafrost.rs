use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fafrost::ia::{IA1Message, IA2Decision, decide, ia1, ia2};
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

struct IASetup {
    signing_package: SigningPackage,
    shares: BTreeMap<Identifier, fafrost::keygen::KeyPackage>,
    pubkeys: fafrost::keygen::PublicKeyPackage,
    signature_shares: BTreeMap<Identifier, SignatureShare>,
    ia1_messages: BTreeMap<Identifier, IA1Message>,
    ia2_decisions: BTreeMap<Identifier, IA2Decision>,
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

fn make_ia_setup(min_signers: u16, max_signers: u16) -> IASetup {
    let mut rng = OsRng;
    let (shares, pubkeys) = generate_with_dealer(max_signers, min_signers, &mut rng);

    let signer_ids: Vec<Identifier> = (1..=min_signers).collect();
    let message = [42u8; 32];

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in &signer_ids {
        let (nonce, commitment) = commit(&mut rng);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let signing_package = SigningPackage {
        message,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();
    for &id in &signer_ids {
        let share = sign(&signing_package, &nonces[&id], &shares[&id], &pubkeys);
        signature_shares.insert(id, share);
    }

    let mut ia1_messages = BTreeMap::new();
    for &id in &signer_ids {
        let msg = ia1(
            &signing_package,
            &signature_shares[&id],
            &shares[&id],
            &pubkeys,
            &signature_shares,
            &mut rng,
        );
        ia1_messages.insert(id, msg);
    }

    let mut ia2_decisions = BTreeMap::new();
    for &id in &signer_ids {
        let decision = ia2(&shares[&id], &signing_package, &ia1_messages);
        ia2_decisions.insert(id, decision);
    }

    IASetup {
        signing_package,
        shares,
        pubkeys,
        signature_shares,
        ia1_messages,
        ia2_decisions,
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

fn bench_ia1(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("ia1");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup(min, max);
        let id = *s.shares.keys().next().unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{min}/{max}")),
            &(),
            |b, _| {
                b.iter(|| {
                    ia1(
                        &s.signing_package,
                        &s.signature_shares[&id],
                        &s.shares[&id],
                        &s.pubkeys,
                        &s.signature_shares,
                        &mut rng,
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_ia2(c: &mut Criterion) {
    let mut group = c.benchmark_group("ia2");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup(min, max);
        let id = *s.shares.keys().next().unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{min}/{max}")),
            &(),
            |b, _| {
                b.iter(|| ia2(&s.shares[&id], &s.signing_package, &s.ia1_messages))
            },
        );
    }

    group.finish();
}

fn bench_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("decide");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup(min, max);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{min}/{max}")),
            &(),
            |b, _| {
                b.iter(|| {
                    decide(
                        &s.signing_package,
                        &s.pubkeys,
                        &s.signature_shares,
                        &s.ia1_messages,
                        &s.ia2_decisions,
                    )
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
    bench_blinding,
    bench_ia1,
    bench_ia2,
    bench_decide,
);
criterion_main!(benches);
