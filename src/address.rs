use crate::base58check::Base58CheckString;
use crate::hash;

use secp256k1::PublicKey;

pub const PREFIX_P2PKH: &[u8] = &[0x00];
pub const PREFIX_P2SH: &[u8] = &[0x05];

pub fn p2pkh(pubkey: &PublicKey) -> Base58CheckString {
    let pubkey_hash = hash::hash160(&pubkey.serialize());

    Base58CheckString::from_bytes(
        &PREFIX_P2PKH
            .iter()
            .chain(pubkey_hash.iter())
            .copied()
            .collect::<Vec<u8>>(),
    )
}

pub fn p2sh_p2wpkh(pubkey: &PublicKey) -> Base58CheckString {
    let pubkey_hash = hash::hash160(&pubkey.serialize());

    let mut script_sig = Vec::from([0x00, 0x14]);
    script_sig.extend(&pubkey_hash);

    let mut script_hash = Vec::from(PREFIX_P2SH);
    script_hash.extend(&hash::hash160(&script_sig));

    Base58CheckString::from_bytes(&script_hash)
}
