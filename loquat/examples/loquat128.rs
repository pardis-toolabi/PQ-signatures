//! Runs the real Loquat-128 parameter set and reports size and timing, so
//! the numbers can be held up against the paper's Table 3 (57 KB, and a
//! SageMath prototype at ~5 s to sign / ~0.21 s to verify).

use std::time::Instant;

fn main() {
    let start = Instant::now();
    let params = loquat::params::Params::loquat_128();
    println!("setup (deriving {} public indices): {:?}", params.l, start.elapsed());

    let start = Instant::now();
    let (secret, public) = loquat::keys::generate(&params);
    println!("keygen: {:?}", start.elapsed());
    println!("public key: {} bytes", public.size_bytes());

    let message = b"loquat at the paper's 128-bit parameter set";

    let start = Instant::now();
    let signature = loquat::sig::sign(&params, &secret, &public, message);
    let sign_time = start.elapsed();

    let start = Instant::now();
    let accepted = loquat::sig::verify(&params, &public, message, &signature);
    let verify_time = start.elapsed();

    println!("sign:   {sign_time:?}");
    println!("verify: {verify_time:?}");
    println!("signature: {} bytes ({:.1} KB)", signature.size_bytes(&params), signature.size_bytes(&params) as f64 / 1024.0);
    println!("accepted: {accepted}");
    assert!(accepted, "honest signature must verify");

    let tampered = loquat::sig::verify(&params, &public, b"a different message", &signature);
    println!("tampered message accepted: {tampered}");
    assert!(!tampered, "tampered message must be rejected");
}
