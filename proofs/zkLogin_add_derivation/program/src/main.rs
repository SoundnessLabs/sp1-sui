// It enables to reveal iss in the zkLogin address and prove the consistency.

#![no_main]
sp1_zkvm::entrypoint!(main);
use fastcrypto::{hash::Blake2b256, bn254::zk_login::poseidon_zk_login};
use zklogin_lib::{get_zk_login_address, gen_address_seed, gen_address_seed_with_salt_hash, PublicValuesStruct}



pub fn main() {
    // read the inputs,
    let iss = sp1_zkvm::io::read::<&str>(); // issuer identity
    let salt = sp1_zkvm::io::read::<&str>(); // salt
    let name = sp1_zkvm::io::read::<&str>(); // i.e. sub 
    let value = sp1_zkvm::io::read::<&str>(); // i.e. the sub value
    let aud = sp1_zkvm::io::read::<&str>(); // i.e. the client ID
    
    // Compute the address_seed = poseidon_zk_login(name, value, aud, poseidon_zk_login(salt).
    let address_seed = gen_address_seed(
        salt,
        name,
        value,
        aud,
    );
    // Compute the zkLogin_address = Blake2b256(len(iss) || iss || address_seed)
    let zkLogin_address = get_zk_login_address(
        address_seed,
        iss
    )

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { iss, salt, name, value, aud, address_seed, zkLogin_address });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
