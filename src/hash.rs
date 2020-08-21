use digest::Digest;
use hmac::{Hmac, Mac, NewMac};
use ripemd160::Ripemd160;
use sha2::{Sha256, Sha512};

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec()
}

pub fn hmac_sha512(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha512>::new_varkey(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
