use crate::base58check;
use crate::hash;

use secp256k1::PublicKey;

pub const PREFIX_P2PKH: &[u8] = &[0x00];
pub const PREFIX_P2SH: &[u8] = &[0x05];

pub fn p2pkh(pubkey: &PublicKey) -> String {
    let pubkey_hash = hash::hash160(&pubkey.serialize());

    base58check::encode(
        &PREFIX_P2PKH
            .iter()
            .chain(pubkey_hash.iter())
            .copied()
            .collect::<Vec<u8>>(),
    )
}

pub fn p2sh_p2wpkh(pubkey: &PublicKey) -> String {
    let pubkey_hash = hash::hash160(&pubkey.serialize());

    let mut script_sig = Vec::from([0x00, 0x14]);
    script_sig.extend(&pubkey_hash);

    let mut script_hash = Vec::from(PREFIX_P2SH);
    script_hash.extend(&hash::hash160(&script_sig));

    base58check::encode(&script_hash)
}
