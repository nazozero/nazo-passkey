//! Reproducible production-API benchmark. See docs/performance.md.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use nazo_passkey::{AuthenticationResponse, Challenge, RegistrationResponse, Webauthn};
use p256::ecdsa::{Signature as EsSignature, SigningKey as EsSigningKey, signature::Verifier as _};
use sha2::{Digest, Sha256};

struct Allocator;
static TRACK: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

// Optional allocation-only profiling with glibc's documented malloc tracer.
// Timed comparisons never load libc_malloc_debug or enable PERF_MTRACE.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe extern "C" {
    fn mtrace();
    fn muntrace();
}

// SAFETY: every allocation and deallocation is forwarded unchanged to System;
// the counters hold no memory or ownership state and do not allocate.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(size as u64, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn measure<T>(name: &str, n: usize, mut f: impl FnMut() -> T) {
    let selected = std::env::var("PERF_CASE").ok();
    if selected.as_deref().is_some_and(|case| case != name) {
        return;
    }
    let native_trace = std::env::var_os("PERF_MTRACE").is_some();
    assert!(
        !native_trace || selected.is_some(),
        "PERF_MTRACE requires PERF_CASE"
    );
    for _ in 0..200 {
        black_box(f());
    }
    let mut samples = Vec::with_capacity(n);
    let begin = Instant::now();
    for _ in 0..n {
        let start = Instant::now();
        black_box(f());
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let elapsed = begin.elapsed().as_secs_f64();
    samples.sort_unstable();
    CALLS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if native_trace {
        // SAFETY: this standalone benchmark runs one thread. The profiling
        // driver sets MALLOC_TRACE before process start; no environment or
        // allocator-hook mutation occurs concurrently.
        unsafe { mtrace() };
    }
    TRACK.store(true, Ordering::Relaxed);
    for _ in 0..100 {
        black_box(f());
    }
    TRACK.store(false, Ordering::Relaxed);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if native_trace {
        // SAFETY: paired with mtrace above, after all 100 measured calls end.
        unsafe { muntrace() };
    }
    println!(
        "{}",
        serde_json::json!({
            "case": name, "iterations": n, "concurrency": 1,
            "p50_ns": samples[n / 2], "p95_ns": samples[n * 95 / 100], "p99_ns": samples[n * 99 / 100],
            "throughput_per_sec": n as f64 / elapsed,
            "allocations_per_op": CALLS.load(Ordering::Relaxed) as f64 / 100.0,
            "allocated_bytes_per_op": BYTES.load(Ordering::Relaxed) as f64 / 100.0,
        })
    );
}

fn cbor(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).unwrap();
    out
}

fn main() {
    let n = if cfg!(debug_assertions) || std::env::args().any(|arg| arg == "--test") {
        10
    } else {
        std::env::var("PERF_ITERATIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000)
    }
    .max(10);
    let wa = Webauthn::new("example.com", "Benchmark", "https://example.com").strict_base64(true);
    let es = EsSigningKey::from_slice(&[7; 32]).unwrap();
    let ed = EdSigningKey::from_bytes(&[7; 32]);
    for algorithm in ["es256", "ed25519"] {
        let cose = if algorithm == "es256" {
            let point = es.verifying_key().to_sec1_point(false);
            cbor(Value::Map(vec![
                (1.into(), 2.into()),
                (3.into(), (-7).into()),
                ((-1).into(), 1.into()),
                ((-2).into(), Value::Bytes(point.x().unwrap().to_vec())),
                ((-3).into(), Value::Bytes(point.y().unwrap().to_vec())),
            ]))
        } else {
            cbor(Value::Map(vec![
                (1.into(), 1.into()),
                (3.into(), (-8).into()),
                ((-1).into(), 6.into()),
                (
                    (-2).into(),
                    Value::Bytes(ed.verifying_key().to_bytes().to_vec()),
                ),
            ]))
        };
        let id = [42; 32];
        let (_, mut register_state) = wa.start_registration(b"benchmark-user", "user", "User", &[]);
        register_state.challenge = Challenge(vec![13; 32]);
        let cdj = serde_json::to_vec(&serde_json::json!({"type":"webauthn.create", "challenge": register_state.challenge.to_b64url(), "origin":"https://example.com", "crossOrigin":false})).unwrap();
        let mut ad = Sha256::digest(b"example.com").to_vec();
        ad.push(0x45);
        ad.extend([0; 4]);
        ad.extend([0; 16]);
        ad.extend(32u16.to_be_bytes());
        ad.extend(id);
        ad.extend(cose);
        let attestation = cbor(Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(ad)),
        ]));
        let register = RegistrationResponse {
            id: B64.encode(id),
            transports: vec!["internal".into()],
            attestation_object: B64.encode(attestation),
            client_data_json: B64.encode(cdj),
        };
        let credential = wa.finish_registration(&register_state, &register).unwrap();
        let (_, mut state) = wa.start_authentication_with_creds_for_user(
            b"benchmark-user",
            std::slice::from_ref(&credential),
        );
        state.challenge = Challenge(vec![19; 32]);
        let cdj = serde_json::to_vec(&serde_json::json!({"type":"webauthn.get", "challenge":state.challenge.to_b64url(), "origin":"https://example.com", "crossOrigin":false})).unwrap();
        let mut ad = Sha256::digest(b"example.com").to_vec();
        ad.push(5);
        ad.extend(1u32.to_be_bytes());
        let mut message = ad.clone();
        message.extend(Sha256::digest(&cdj));
        let signature = if algorithm == "es256" {
            let s: EsSignature = es.sign(&message);
            s.to_der().as_bytes().to_vec()
        } else {
            ed.sign(&message).to_bytes().to_vec()
        };
        let assertion = AuthenticationResponse {
            id: B64.encode(id),
            authenticator_data: B64.encode(ad),
            signature: B64.encode(signature),
            client_data_json: B64.encode(cdj),
            user_handle: Some(B64.encode(b"benchmark-user")),
        };
        measure(&format!("{algorithm}.registration_begin"), n, || {
            wa.start_registration(b"benchmark-user", "user", "User", &[])
        });
        measure(&format!("{algorithm}.registration_finish"), n, || {
            wa.finish_registration(&register_state, &register).unwrap()
        });
        measure(&format!("{algorithm}.authentication_begin"), n, || {
            wa.start_authentication_with_creds_for_user(
                b"benchmark-user",
                std::slice::from_ref(&credential),
            )
        });
        measure(&format!("{algorithm}.authentication_finish"), n, || {
            wa.finish_authentication(&state, &assertion, &credential)
                .unwrap()
        });
    }
    // Crypto controls exclude parsing; production conclusions use finish above.
    let message = [23; 69];
    let es_sig: EsSignature = es.sign(&message);
    measure("primitive.es256.rustcrypto", n, || {
        es.verifying_key().verify(&message, &es_sig).unwrap()
    });
    let ed_sig = ed.sign(&message);
    let ed_vk = ed.verifying_key();
    measure("primitive.ed25519_strict.rustcrypto", n, || {
        ed_vk.verify_strict(&message, &ed_sig).unwrap()
    });
}
