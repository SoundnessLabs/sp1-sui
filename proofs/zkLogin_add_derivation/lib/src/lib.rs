use alloy_sol_types::sol;
use fastcrypto::{hash::Blake2b256, bn254::zk_login::poseidon_zk_login};


sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        str iss;
        str salt;
        str name;
        str value;
        str aud;
        str address_seed;
        str zkLogin_address;
    }
}

/// Calculate the Sui address based on address seed and address params.
/// taken from https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto-zkp/src/bn254/utils.rs#L26-L65
pub fn get_zk_login_address(
    address_seed: &Bn254FrElement,
    iss: &str,
) -> Result<[u8; 32], FastCryptoError> {
    let mut hasher = Blake2b256::default();
    hasher.update([ZK_LOGIN_AUTHENTICATOR_FLAG]);
    let bytes = iss.as_bytes();
    hasher.update([bytes.len() as u8]);
    hasher.update(bytes);
    hasher.update(address_seed.padded());
    Ok(hasher.finalize().digest)
}

/// Calculate the Sui address based on address seed and address params.
pub fn gen_address_seed(
    salt: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> Result<String, FastCryptoError> {
    let salt_hash = poseidon_zk_login(&[(&Bn254FrElement::from_str(salt)?).into()])?;
    gen_address_seed_with_salt_hash(&salt_hash.to_string(), name, value, aud)
}

pub(crate) fn gen_address_seed_with_salt_hash(
    salt_hash: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> Result<String, FastCryptoError> {
    Ok(poseidon_zk_login(&[
        hash_ascii_str_to_field(name, MAX_KEY_CLAIM_NAME_LENGTH)?,
        hash_ascii_str_to_field(value, MAX_KEY_CLAIM_VALUE_LENGTH)?,
        hash_ascii_str_to_field(aud, MAX_AUD_VALUE_LENGTH)?,
        (&Bn254FrElement::from_str(salt_hash)?).into(),
    ])?
    .to_string())
}


