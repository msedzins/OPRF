use curve25519_dalek::scalar::Scalar;
use fhe::bfv::{BfvParameters, PublicKey, SecretKey};

mod oprf;
mod oprfs_lattice;

fn main() {
    
    //Standard OPRF using ECC
    oprfs_ec();

    //Experiment with OPRF and lattices.
    opfrs_lattice();
}

fn oprfs_ec() {
    
    //Password known only by the client
    let pw = b"supersecret";
    // Server's secret OPRF key known only by the server
    let k = Scalar::random(&mut rand::thread_rng());

    // Client blinds pw
    // Convert password to point on the curve and then blinds it by multiplying by random scalar
    let (x_blind, r) = oprf::client_blind(pw);

    // Server evaluates OPRF using secret key and blinded pw
    let y_blind = oprf::server_eval(&x_blind, &k);

    // Client unblinds
    // y represents secret value known only to the client (it can be expanded to high-entropy key)
    // This value can't be calculated by client directly because they don't know server secret key.
    let y = oprf::client_unblind(&y_blind, &r);

    // For demonstration: calculate 'y' directly, assuming we know everything - pw and secret key
    let direct = oprf::direct_calculation(pw, &k);

    //values must be equal
    assert_eq!(direct.compress(), y.compress())
}

fn opfrs_lattice() {
    
    /*Part 1 - parameters for preparing lattice vectors */
    const Q: i64 = 97; // small modulus for toy arithmetic (NOT secure)
    let dim = 4; // small example lattice dimension
    // Server chooses secret OPRF key K (vector), should be generated randomly
    let server_k = vec![5i64, 12, 3, 7]; // secret, mod Q

    /*Part 2 - parameters for homomorphic encryption used in blinding */
    let mut rng = rand::thread_rng();
    let params = BfvParameters::default_parameters_128(16)
        .into_iter()
        .nth(2)
        .ok_or("Could not generate parameters")
        .unwrap();

    // Generate keys by client
    let sk = SecretKey::random(&params, &mut rng); // known only by client
    let pk = PublicKey::new(&sk, &mut rng); //known by client, shared with server

    //Password known only by the client
    let pw = "supersecret";

    // Client blinds pw (encrypts vector in our case)
    let ct_x = oprfs_lattice::client_blind(pw, dim, &params, &pk, &mut rng);

    // Server: homomorphically evaluate PRF = <K, x> (inner product of two vectors)
    let ct_y = oprfs_lattice::server_eval(&ct_x, &server_k, &params);

    // Client: Unblind calculation (decrypt in our case)
    let y = oprfs_lattice::client_unblind(&ct_y, &sk);
    let oprf_output = y[0] % Q; // result is modulo 40961 based on params configuration, so we need to take it modulo Q

    // For demonstration: show the raw inner product computed directly (non-oblivious)
    // This is for checking correctness: <K, x> mod Q
    let x_plain = oprfs_lattice::hash_to_vec(pw, dim);
    let mut acc: i64 = 0;
    for (a, k) in x_plain.iter().zip(server_k.iter()) {
        acc += *a * *k;
    }

    //values must be equal
    assert_eq!((acc % Q),oprf_output);
}