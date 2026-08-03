//! Measures every scheme in the workspace the same way, so the numbers in
//! the root README can be reproduced with `cargo run --release -p compare`.
//!
//! Keygen timing includes deriving the public key, since that is the real
//! cost of producing a usable key pair — for XMSS and leanSig most of the
//! work lives there rather than in generating the secret.

use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"benchmark message for post quantum signatures";

fn avg(total: Duration, n: u32) -> Duration {
    total / n
}

fn print_row(name: &str, keygen: Duration, sign: Duration, verify: Duration, sig_size: usize, pk_size: usize) {
    println!(
        "{:<12} {:>12?} {:>12?} {:>12?} {:>10} B {:>9} B",
        name, keygen, sign, verify, sig_size, pk_size
    );
}

fn bench_lamport(iterations: u32) {
    let (mut keygen_total, mut sign_total, mut verify_total) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let (mut sig_size, mut pk_size) = (0, 0);

    for _ in 0..iterations {
        let start = Instant::now();
        let sk = lamport::PrivateKey::generate();
        let pk = sk.public_key();
        keygen_total += start.elapsed();

        let start = Instant::now();
        let signature = sk.sign(MESSAGE);
        sign_total += start.elapsed();

        let start = Instant::now();
        assert!(lamport::verify(&pk, MESSAGE, &signature));
        verify_total += start.elapsed();

        sig_size = signature.size_bytes();
        pk_size = pk.size_bytes();
    }

    print_row(
        "Lamport",
        avg(keygen_total, iterations),
        avg(sign_total, iterations),
        avg(verify_total, iterations),
        sig_size,
        pk_size,
    );
}

fn bench_wots(iterations: u32) {
    let (mut keygen_total, mut sign_total, mut verify_total) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let (mut sig_size, mut pk_size) = (0, 0);

    for _ in 0..iterations {
        let start = Instant::now();
        let sk = wots::PrivateKey::generate();
        let pk = sk.public_key();
        keygen_total += start.elapsed();

        let start = Instant::now();
        let signature = sk.sign(MESSAGE);
        sign_total += start.elapsed();

        let start = Instant::now();
        assert!(wots::verify(&pk, MESSAGE, &signature));
        verify_total += start.elapsed();

        sig_size = signature.size_bytes();
        pk_size = pk.size_bytes();
    }

    print_row(
        "WOTS",
        avg(keygen_total, iterations),
        avg(sign_total, iterations),
        avg(verify_total, iterations),
        sig_size,
        pk_size,
    );
}

fn bench_xmss(height: u32, iterations: u32) {
    let start = Instant::now();
    let mut sk = xmss::PrivateKey::generate(height);
    let pk = sk.public_key();
    let keygen = start.elapsed();

    let iterations = iterations.min(sk.remaining_signatures() as u32);
    let (mut sign_total, mut verify_total) = (Duration::ZERO, Duration::ZERO);
    let mut sig_size = 0;

    for i in 0..iterations {
        let message = format!("benchmark message for post quantum signatures #{i}");

        let start = Instant::now();
        let signature = sk.sign(message.as_bytes()).unwrap();
        sign_total += start.elapsed();

        let start = Instant::now();
        assert!(xmss::verify(&pk, message.as_bytes(), &signature));
        verify_total += start.elapsed();

        sig_size = signature.size_bytes();
    }

    print_row(
        &format!("XMSS h={height}"),
        keygen,
        avg(sign_total, iterations),
        avg(verify_total, iterations),
        sig_size,
        pk.size_bytes(),
    );
}

fn bench_leansig(iterations: u32) {
    let (mut keygen_total, mut sign_total, mut verify_total) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let (mut sig_size, mut pk_size, mut tries_total) = (0, 0, 0u64);

    for i in 0..iterations {
        let start = Instant::now();
        let sk = leansig::PrivateKey::generate();
        let pk = sk.public_key();
        keygen_total += start.elapsed();

        // Vary the message so the target-sum search cost is representative.
        let message = format!("benchmark message for post quantum signatures #{i}");

        let start = Instant::now();
        let (signature, tries) = sk.sign_counting(message.as_bytes()).expect("target sum found");
        sign_total += start.elapsed();
        tries_total += tries;

        let start = Instant::now();
        assert!(leansig::verify(&pk, message.as_bytes(), &signature));
        verify_total += start.elapsed();

        sig_size = signature.size_bytes();
        pk_size = pk.size_bytes();
    }

    print_row(
        "leanSig",
        avg(keygen_total, iterations),
        avg(sign_total, iterations),
        avg(verify_total, iterations),
        sig_size,
        pk_size,
    );
    println!(
        "{:<12} target-sum search averaged {} tries per signature",
        "", tries_total / iterations as u64
    );
}

fn bench_loquat(iterations: u32) {
    // Setup derives the 32768 public indices; it is shared by all users,
    // so it sits outside the per-key timings.
    let params = loquat::params::Params::loquat_128();

    let (mut keygen_total, mut sign_total, mut verify_total) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let (mut sig_size, mut pk_size) = (0, 0);

    for i in 0..iterations {
        let start = Instant::now();
        let (secret, public) = loquat::keys::generate(&params);
        keygen_total += start.elapsed();

        let message = format!("benchmark message for post quantum signatures #{i}");

        let start = Instant::now();
        let signature = loquat::sig::sign(&params, &secret, message.as_bytes());
        sign_total += start.elapsed();

        let start = Instant::now();
        assert!(loquat::sig::verify(&params, &public, message.as_bytes(), &signature));
        verify_total += start.elapsed();

        sig_size = signature.size_bytes(&params);
        pk_size = public.size_bytes();
    }

    print_row(
        "Loquat-128",
        avg(keygen_total, iterations),
        avg(sign_total, iterations),
        avg(verify_total, iterations),
        sig_size,
        pk_size,
    );
}

fn main() {
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12} {:>11}",
        "scheme", "keygen", "sign", "verify", "sig size", "pk size"
    );
    println!("(averaged over several runs; keygen includes deriving the public key)\n");

    bench_lamport(50);
    bench_wots(50);
    bench_xmss(4, 16);
    bench_xmss(10, 50);
    bench_leansig(50);
    bench_loquat(10);

    println!(
        "\nNotes:\n\
         - Lamport/WOTS/XMSS hash with SHA-256; leanSig hashes with Poseidon2.\n\
           Poseidon2 is slower here (SHA-256 has dedicated CPU instructions) but is\n\
           roughly 490x cheaper inside a circuit. See circuits/README.md.\n\
         - Every hash-based scheme above is limited in how many messages one key\n\
           may sign (1 for Lamport/WOTS/leanSig, 2^h for XMSS). Loquat is not:\n\
           one key signs unlimited messages, which is what the large signature buys."
    );
}
