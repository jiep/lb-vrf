use lb_vrf::lbvrf::LBVRF;
use lb_vrf::lbvrf::Proof;
use lb_vrf::param::Param;
use lb_vrf::VRF;

use lb_vrf::poly32::Poly32;
use lb_vrf::serde::Serdes;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;

pub fn get_random_key32() -> Vec<u8> {
    let mut x = vec![0; 32];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

pub fn get_random_key88() -> Vec<u8> {
    let mut x = vec![0; 88];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let z: Vec<u8> = x.iter().zip(y).map(|(a, b)| a ^ b).collect();
    z
}

fn main() {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];

    rng.fill_bytes(&mut seed);

    let param: Param = <LBVRF as VRF>::paramgen(seed).unwrap();

    println!("Round 2 ----------------------------------------------------");

    rng.fill_bytes(&mut seed);
    let (pk, sk) = <LBVRF as VRF>::keygen(seed, param).unwrap();

    let ns = get_random_key88();
    println!("ns: {:?}", ns);
    let r = get_random_key32();

    let proof = <LBVRF as VRF>::prove(r.clone(), param, pk, sk, seed).unwrap();

    // println!("y: v={:?}", proof.v);
    let mut y: Vec<u8> = Vec::new();
    proof.v.serialize(&mut y).unwrap();

    println!("y: {:?}", y);
    // println!("pi: (z={:?}, c={:?}); ", proof.z, proof.c);

    let c = xor(&y, &ns);
    println!("c: {:?}", c);

    println!("Round 3 ----------------------------------------------------");

    // Eval
    let mut proof_client = <LBVRF as VRF>::prove(r.clone(), param, pk, sk, seed).unwrap();
    let mut y_client: Vec<u8> = Vec::new();
    proof_client.v.serialize(&mut y_client).unwrap();
    let ns_client = xor(&y_client, &c);

    println!("ns_client: {:?}", ns_client);
    println!("ns:        {:?}", ns);
    assert_eq!(ns_client, ns);

    // Verify
    let y_j = xor(&ns, &c);
    assert_eq!(y_j, y_client);

    let v: Poly32 = Poly32::deserialize(&mut y_j[..].as_ref()).unwrap();

    proof_client.v = v; 

    assert_eq!(v, proof_client.v);

    let created_proof: Proof = Proof { v, z: proof_client.z, c: proof_client.c };

    assert_eq!(created_proof, proof_client);


    let res = <LBVRF as VRF>::verify(r, param, pk, proof).unwrap();
    assert!(res.is_some());
    let mut y_client: Vec<u8> = Vec::new();
    res.unwrap().serialize(&mut y_client).unwrap();    

}
