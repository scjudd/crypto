use crypto::{address, bip32::ExtendedPublicKey};

fn main() {
    println!("\nAddresses derived from master public key:");

    let master_xpub = ExtendedPublicKey::from_base58check("xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1").unwrap();
    let xpub = master_xpub.derive_public(0.into()).unwrap();

    for i in 0..20 {
        let xpub = xpub.derive_public(i.into()).unwrap();
        let address = address::p2sh_p2wpkh(&xpub.public_key);
        println!("{}\t{}", i, address);
    }
}
