use crypto::{address, base58check::Base58CheckString, bip32::ExtendedPublicKey};
use std::convert::TryFrom;

fn main() {
    println!("\nAddresses derived from master public key:");

    let master_xpub = "xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1";
    let master_xpub = Base58CheckString::try_from(master_xpub.to_string()).unwrap();
    let master_xpub = ExtendedPublicKey::from_base58check(&master_xpub).unwrap();

    let xpub = master_xpub.derive_public(0.into()).unwrap();

    for i in 0..20 {
        let xpub = xpub.derive_public(i.into()).unwrap();
        let address = address::p2sh_p2wpkh(&xpub.public_key);
        println!("{}\t{}", i, address);
    }
}
