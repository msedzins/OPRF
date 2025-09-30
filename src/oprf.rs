use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

// Convert password to curve point
fn hash_to_point(pw: &[u8]) -> RistrettoPoint {
    let h = Sha512::digest(pw);
    let hash_array: [u8; 64] = h.into();
    RistrettoPoint::from_uniform_bytes(&hash_array)
}

// Client side: blind input
pub fn client_blind(pw: &[u8]) -> (RistrettoPoint, Scalar) {
    let x = hash_to_point(pw);
    let r = Scalar::random(&mut rand::thread_rng());
    let x_blind = x * r;
    (x_blind, r)
}

// Server side: evaluate with secret key k
pub fn server_eval(x_blind: &RistrettoPoint, k: &Scalar) -> RistrettoPoint {
    x_blind * k
}

// Client side: unblind
pub fn client_unblind(y_blind: &RistrettoPoint, r: &Scalar) -> RistrettoPoint {
    let r_inv = r.invert();
    y_blind * r_inv
}

// For demonstration: calculate 'y' directly, assuming we know everything - pw and secret key
pub fn direct_calculation(pw: &[u8], k: &Scalar) -> RistrettoPoint {
    let x = hash_to_point(pw);
    x*k
}
