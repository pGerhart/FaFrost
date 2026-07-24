use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fafrost::ia::{IA1Message, IA2Decision, decide, ia1, ia2};
use fafrost::keygen::generate_with_dealer;
use fafrost::sign::{SignatureShare, SigningPackage, aggregate, commit, sign};
use fafrost::utils::encode_commitments;
use fafrost::{Ciphersuite, Ed25519, Secp256k1Bip340};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use std::collections::BTreeMap;

const CONFIGS: &[(u16, u16)] = &[
    (4, 256),
    (8, 256),
    (16, 256),
    (32, 256),
    (48, 256),
    (64, 256),
];

type Identifier = u16;

struct Setup<C: Ciphersuite> {
    signing_package: SigningPackage<C>,
    key_package: fafrost::keygen::KeyPackage<C>,
    nonce: fafrost::sign::SigningNonces<C>,
    pubkeys: fafrost::keygen::PublicKeyPackage<C>,
    signature_shares: BTreeMap<Identifier, SignatureShare<C>>,
    ids: Vec<u16>,
    commitments_bytes: Vec<u8>,
    message: [u8; 32],
}

struct IASetup<C: Ciphersuite> {
    signing_package: SigningPackage<C>,
    shares: BTreeMap<Identifier, fafrost::keygen::KeyPackage<C>>,
    pubkeys: fafrost::keygen::PublicKeyPackage<C>,
    signature_shares: BTreeMap<Identifier, SignatureShare<C>>,
    ia1_messages: BTreeMap<Identifier, IA1Message<C>>,
    ia2_decisions: BTreeMap<Identifier, IA2Decision>,
}

fn make_setup<C: Ciphersuite>(min_signers: u16, max_signers: u16) -> Setup<C> {
    let mut rng = UnwrapErr(SysRng);
    let (shares, pubkeys) = generate_with_dealer::<C, _>(max_signers, min_signers, &mut rng);

    let signer_ids: Vec<Identifier> = (1..=min_signers).collect();
    let message = [42u8; 32];

    let mut commitments = BTreeMap::new();
    let mut nonces_map = BTreeMap::new();
    for &id in &signer_ids {
        let (nonce, commitment) = commit::<C, _>(&mut rng);
        nonces_map.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let commitments_bytes = encode_commitments::<C>(&commitments);

    let signing_package = SigningPackage {
        message,
        signing_commitments: commitments,
        partial_verification_keys: pubkeys.partial_verification_keys.clone(),
    };

    let mut signature_shares = BTreeMap::new();
    for &id in &signer_ids {
        let share = sign(&signing_package, &nonces_map[&id], &shares[&id], &pubkeys).unwrap();
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

fn make_ia_setup<C: Ciphersuite>(min_signers: u16, max_signers: u16) -> IASetup<C> {
    let mut rng = UnwrapErr(SysRng);
    let (shares, pubkeys) = generate_with_dealer::<C, _>(max_signers, min_signers, &mut rng);

    let signer_ids: Vec<Identifier> = (1..=min_signers).collect();
    let message = [42u8; 32];

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in &signer_ids {
        let (nonce, commitment) = commit::<C, _>(&mut rng);
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
        let share = sign(&signing_package, &nonces[&id], &shares[&id], &pubkeys).unwrap();
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
        )
        .unwrap();
        ia1_messages.insert(id, msg);
    }

    let mut ia2_decisions = BTreeMap::new();
    for &id in &signer_ids {
        let decision = ia2(&shares[&id], &signing_package, &ia1_messages).unwrap();
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

fn bench_commit<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut rng = UnwrapErr(SysRng);
    c.bench_function(&format!("commit/{curve}"), |b| {
        b.iter(|| commit::<C, _>(&mut rng))
    });
}

fn bench_sign<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group("sign");

    for &(min, max) in CONFIGS {
        let s = make_setup::<C>(min, max);
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
            &(),
            |b, _| b.iter(|| sign(&s.signing_package, &s.nonce, &s.key_package, &s.pubkeys)),
        );
    }

    group.finish();
}

fn bench_aggregate<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group("aggregate");

    for &(min, max) in CONFIGS {
        let s = make_setup::<C>(min, max);
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
            &(),
            |b, _| b.iter(|| aggregate(&s.signing_package, &s.signature_shares)),
        );
    }

    group.finish();
}

fn bench_blinding<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group("blinding_scalar");

    for &(min, max) in CONFIGS {
        let s = make_setup::<C>(min, max);
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
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

fn bench_ia1<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut rng = UnwrapErr(SysRng);
    let mut group = c.benchmark_group("ia1");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup::<C>(min, max);
        let id = *s.shares.keys().next().unwrap();
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
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

fn bench_ia2<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group("ia2");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup::<C>(min, max);
        let id = *s.shares.keys().next().unwrap();
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
            &(),
            |b, _| b.iter(|| ia2(&s.shares[&id], &s.signing_package, &s.ia1_messages)),
        );
    }

    group.finish();
}

fn bench_decide<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group("decide");

    for &(min, max) in CONFIGS {
        let s = make_ia_setup::<C>(min, max);
        group.bench_with_input(
            BenchmarkId::new(curve, format!("{min}/{max}")),
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

fn benches_for<C: Ciphersuite>(c: &mut Criterion, curve: &str) {
    bench_commit::<C>(c, curve);
    bench_sign::<C>(c, curve);
    bench_aggregate::<C>(c, curve);
    bench_blinding::<C>(c, curve);
    bench_ia1::<C>(c, curve);
    bench_ia2::<C>(c, curve);
    bench_decide::<C>(c, curve);
}

fn all_curves(c: &mut Criterion) {
    benches_for::<Secp256k1Bip340>(c, "secp256k1");
    benches_for::<Ed25519>(c, "ed25519");
}

criterion_group!(benches, all_curves);
criterion_main!(benches);
