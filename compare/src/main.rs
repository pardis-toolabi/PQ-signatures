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
        keygen_total += start.elapsed();
        let pk = sk.public_key();

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
        keygen_total += start.elapsed();
        let pk = sk.public_key();

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
    let keygen = start.elapsed();
    let pk = sk.public_key();

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

fn main() {
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12} {:>11}",
        "scheme", "keygen", "sign", "verify", "sig size", "pk size"
    );
    println!("(keygen and sign/verify are averaged over several runs to smooth out noise)\n");

    bench_lamport(50);
    bench_wots(50);
    bench_xmss(4, 16);
    bench_xmss(10, 50);
}
