//! Measures how many randomness values the signer tries before the message
//! digits hit the target sum. This is the cost the target-sum trick pays in
//! exchange for cheaper verification.

fn main() {
    let runs = 20u32;
    let mut total_tries = 0u64;
    let start = std::time::Instant::now();

    for i in 0..runs {
        let sk = leansig::PrivateKey::generate();
        let message = format!("benchmark message {i}");
        let (_signature, tries) = sk.sign_counting(message.as_bytes()).unwrap();
        total_tries += tries;
    }

    let elapsed = start.elapsed();
    println!("average tries to hit target sum: {}", total_tries / runs as u64);
    println!("average sign time: {:?}", elapsed / runs);
    println!("verifier chain steps: {}", leansig::DIGITS as u32 * (leansig::W - 1) - leansig::TARGET_SUM);
}
