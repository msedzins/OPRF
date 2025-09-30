use rand::rngs::ThreadRng;
use sha2::{Digest, Sha256};

use fhe::{
    bfv::{BfvParameters, Encoding, Plaintext, PublicKey, SecretKey, Ciphertext}
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use std::sync::Arc;

// Simple deterministic "h  ash-to-vector" for demonstration.
pub fn hash_to_vec(input: &str, len: usize) -> Vec<i64> {
    const Q: i64 = 97;
    let mut out = Vec::with_capacity(len);
    let h = Sha256::digest(input.as_bytes());
    for i in 0..len {
        // take two bytes per coordinate to get small integer, mod Q
        let b0 = h[(2 * i) % h.len()] as i64;
        let b1 = h[(2 * i + 1) % h.len()] as i64;
        let v = (b0 * 31 + b1) % Q; //"31" for mixing (Different byte pairs are more likely to produce unique values)
        out.push(v);
    }
    out
}

// Client side: blind input (encrypt)
pub fn client_blind(
    pw: &str,
    len: usize,
    params: &Arc<BfvParameters>,
    pk: &PublicKey,
    rng: &mut ThreadRng,
) -> Vec<Ciphertext> {
    let v = hash_to_vec(pw, len);

    let encrypted = v.iter().map(|i| {
    let pt_a = Plaintext::try_encode(&[*i], Encoding::poly(), params).unwrap();    
    pk.try_encrypt(&pt_a, rng).unwrap()
    }).collect::<Vec<Ciphertext>>();

    encrypted
}

// Client side: unblind (decrypt)
pub fn client_unblind(
    encrypted_data: &Ciphertext,
    sk: &SecretKey
) -> Vec::<i64> {
    let res = sk.try_decrypt(&encrypted_data).unwrap();

    Vec::<i64>::try_decode(&res, Encoding::poly()).unwrap()
}

// Server side: evaluate with secret key k
// homomorphic inner product with a server-side secret vector K.
pub fn server_eval(
    encrypted_data: &Vec<Ciphertext>,
    secret_k: &Vec<i64>,
    params: &Arc<BfvParameters>
) -> Ciphertext {

    let mut acc = Ciphertext::zero(params);
    for (ct, w) in encrypted_data.iter().zip(secret_k.iter()) {
        let pt_w = Plaintext::try_encode(&[*w], Encoding::poly(), params).unwrap();
        acc += &(ct * &pt_w);
    }

    acc
}
