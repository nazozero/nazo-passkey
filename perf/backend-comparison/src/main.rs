use std::{hint::black_box, time::Instant};

fn measure(name: &str, mut verify: impl FnMut()) {
    for _ in 0..200 {
        verify();
    }
    let mut samples = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let start = Instant::now();
        verify();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    println!(
        "{}",
        serde_json::json!({"case":name,"iterations":5000,"p50_ns":samples[2500],"p95_ns":samples[4750],"p99_ns":samples[4950]})
    );
}

fn main() {
    use p256::ecdsa::signature::{Signer, Verifier};
    let message = [23; 69];
    let es = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let point = es.verifying_key().to_sec1_point(false);
    let signature: p256::ecdsa::Signature = es.sign(&message);
    let der = signature.to_der();
    let aws_es = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        point.as_bytes(),
    );
    measure("es256.rustcrypto.parse_and_verify", || {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(black_box(point.as_bytes())).unwrap();
        let sig = p256::ecdsa::Signature::from_der(black_box(der.as_bytes())).unwrap();
        vk.verify(black_box(&message), &sig).unwrap();
    });
    measure("es256.aws_lc.parse_and_verify", || {
        aws_es
            .verify(black_box(&message), black_box(der.as_bytes()))
            .unwrap()
    });
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let sig = ed25519_dalek::Signer::sign(&ed, &message).to_bytes();
    let pk = ed.verifying_key().to_bytes();
    let aws_ed = aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, pk);
    measure("ed25519.rustcrypto.parse_and_verify_strict", || {
        let key = ed25519_dalek::VerifyingKey::from_bytes(black_box(&pk)).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(black_box(&sig)).unwrap();
        key.verify_strict(black_box(&message), &sig).unwrap();
    });
    measure("ed25519.aws_lc.parse_and_verify", || {
        aws_ed.verify(black_box(&message), black_box(&sig)).unwrap()
    });
    // Establish elementary negative behavior without claiming full backend parity.
    let mut wrong = message;
    wrong[0] ^= 1;
    assert!(aws_es.verify(&wrong, der.as_bytes()).is_err());
    assert!(aws_ed.verify(&wrong, &sig).is_err());
    let mut weak = [0; 32];
    weak[0] = 1;
    let mut forged = [0; 64];
    forged[0] = 1;
    let weak_result =
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, weak)
            .verify(&message, &forged);
    println!(
        "{}",
        serde_json::json!({"aws_lc_rejects_small_order_forgery":weak_result.is_err()})
    );
}
