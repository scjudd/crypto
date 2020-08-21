use crate::{base58check, hash};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Fingerprint([u8; 4]);
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ChainCode([u8; 32]);

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ChildNumber {
    Normal(u32),
    Hardened(u32),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExtendedPrivateKey {
    pub depth: u8,
    pub parent_fingerprint: Fingerprint,
    pub child_number: ChildNumber,
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExtendedPublicKey {
    pub depth: u8,
    pub parent_fingerprint: Fingerprint,
    pub child_number: ChildNumber,
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Base58Check(base58check::Error),
    Secp256k1(secp256k1::Error),
    ImpossibleDerivation,
}

impl From<base58check::Error> for Error {
    fn from(err: base58check::Error) -> Error {
        Error::Base58Check(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::Secp256k1(err)
    }
}

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 4]> for Fingerprint {
    fn from(bytes: [u8; 4]) -> Fingerprint {
        Fingerprint(bytes)
    }
}

impl ChainCode {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ChainCode {
    fn from(bytes: [u8; 32]) -> ChainCode {
        ChainCode(bytes)
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> ChildNumber {
        if number >> 31 == 1 {
            ChildNumber::Hardened(number ^ (1 << 31))
        } else {
            ChildNumber::Normal(number)
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(number: ChildNumber) -> u32 {
        match number {
            ChildNumber::Hardened(index) => index | (1 << 31),
            ChildNumber::Normal(index) => index,
        }
    }
}

impl ExtendedPrivateKey {
    pub fn from_base58check(v: &str) -> Result<ExtendedPrivateKey, Error> {
        let data = base58check::decode(v)?;

        if data.len() != 78 {
            return Err(base58check::Error::InvalidLength(data.len()).into());
        }

        if data[0..4] != [0x04, 0x88, 0xad, 0xe4] {
            return Err(base58check::Error::InvalidVersion(data[0..4].to_vec()).into());
        }

        let private_key = SecretKey::from_slice(&data[46..])?;

        Ok(ExtendedPrivateKey {
            depth: data[4],
            parent_fingerprint: copy_from_slice!([0u8; 4], &data[5..9]).into(),
            child_number: u32::from_be_bytes(copy_from_slice!([0u8; 4], &data[9..13])).into(),
            chain_code: copy_from_slice!([0u8; 32], &data[13..45]).into(),
            private_key,
        })
    }

    pub fn to_base58check(&self) -> String {
        let mut data = [0u8; 78];
        data[..4].copy_from_slice(&[0x04, 0x88, 0xad, 0xe4]);
        data[4] = self.depth;
        data[5..9].copy_from_slice(&self.parent_fingerprint.as_bytes());
        data[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        data[13..45].copy_from_slice(&self.chain_code.as_bytes());
        data[46..].copy_from_slice(&self.private_key[..]);
        base58check::encode(&data)
    }

    pub fn derive_private(&self, child_number: ChildNumber) -> Result<ExtendedPrivateKey, Error> {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &self.private_key);

        let mut hmac_data = [0u8; 37];

        match child_number {
            ChildNumber::Hardened(index) => {
                hmac_data[1..33].copy_from_slice(&self.private_key[..]);
                hmac_data[33..].copy_from_slice(&(index | (1 << 31)).to_be_bytes());
            }
            ChildNumber::Normal(index) => {
                hmac_data[..33].copy_from_slice(&public_key.serialize());
                hmac_data[33..].copy_from_slice(&index.to_be_bytes());
            }
        }

        let hmac_result = hash::hmac_sha512(&hmac_data, self.chain_code.as_bytes());
        let chain_code = copy_from_slice!([0u8; 32], &hmac_result[32..]).into();

        let mut private_key = self.private_key;
        private_key.add_assign(&hmac_result[..32])?;

        let depth = self.depth + 1;

        let parent_fingerprint =
            copy_from_slice!([0u8; 4], &hash::hash160(&public_key.serialize())[..4]).into();

        Ok(ExtendedPrivateKey {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key,
        })
    }
}

impl ExtendedPublicKey {
    pub fn from_base58check(v: &str) -> Result<ExtendedPublicKey, Error> {
        let data = base58check::decode(v)?;

        if data.len() != 78 {
            return Err(base58check::Error::InvalidLength(data.len()).into());
        }

        if data[0..4] != [0x04, 0x88, 0xb2, 0x1e] {
            return Err(base58check::Error::InvalidVersion(data[0..4].to_vec()).into());
        }

        let public_key = PublicKey::from_slice(&data[45..])?;

        Ok(ExtendedPublicKey {
            depth: data[4],
            parent_fingerprint: copy_from_slice!([0u8; 4], &data[5..9]).into(),
            child_number: u32::from_be_bytes(copy_from_slice!([0u8; 4], &data[9..13])).into(),
            chain_code: copy_from_slice!([0u8; 32], &data[13..45]).into(),
            public_key,
        })
    }

    pub fn to_base58check(&self) -> String {
        let mut data = [0u8; 78];
        data[..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        data[4] = self.depth;
        data[5..9].copy_from_slice(&self.parent_fingerprint.as_bytes());
        data[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        data[13..45].copy_from_slice(&self.chain_code.as_bytes());
        data[45..].copy_from_slice(&self.public_key.serialize());
        base58check::encode(&data)
    }

    pub fn from_private(xprv: &ExtendedPrivateKey) -> ExtendedPublicKey {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &xprv.private_key);

        ExtendedPublicKey {
            depth: xprv.depth,
            parent_fingerprint: xprv.parent_fingerprint,
            child_number: xprv.child_number,
            chain_code: xprv.chain_code,
            public_key,
        }
    }

    pub fn derive_public(&self, child_number: ChildNumber) -> Result<ExtendedPublicKey, Error> {
        let mut hmac_data = [0u8; 37];

        match child_number {
            ChildNumber::Normal(index) => {
                hmac_data[..33].copy_from_slice(&self.public_key.serialize());
                hmac_data[33..].copy_from_slice(&index.to_be_bytes());
            }
            ChildNumber::Hardened(_) => {
                return Err(Error::ImpossibleDerivation);
            }
        }

        let hmac_result = hash::hmac_sha512(&hmac_data, self.chain_code.as_bytes());
        let chain_code = copy_from_slice!([0u8; 32], &hmac_result[32..]).into();

        let secp = Secp256k1::new();
        let mut public_key = self.public_key;
        public_key.add_exp_assign(&secp, &hmac_result[..32])?;

        let depth = self.depth + 1;

        let parent_fingerprint =
            copy_from_slice!([0u8; 4], &hash::hash160(&self.public_key.serialize())[..4]).into();

        Ok(ExtendedPublicKey {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extendedprivatekey_from_base58check() {
        let expected = ExtendedPrivateKey {
            depth: 3,
            parent_fingerprint: Fingerprint([0x77, 0x92, 0x0d, 0x54]),
            child_number: ChildNumber::Normal(2),
            private_key: SecretKey::from_slice(&[
                0xc4, 0xf1, 0x36, 0x5e, 0xe3, 0xe6, 0x8f, 0xa4, 0x85, 0x40, 0x2c, 0x45, 0x05, 0xa3,
                0xca, 0x99, 0xff, 0xed, 0xb1, 0xdb, 0xd9, 0x6d, 0xff, 0xb2, 0x32, 0xe8, 0xe4, 0xa8,
                0x2d, 0xe9, 0x8e, 0xd0,
            ])
            .unwrap(),
            chain_code: ChainCode([
                0x43, 0x14, 0xc1, 0x00, 0xac, 0xaa, 0x75, 0xd8, 0x3f, 0xf2, 0xf7, 0xa9, 0xfa, 0xba,
                0xe2, 0x5b, 0x94, 0xff, 0xa6, 0xff, 0x52, 0x47, 0x35, 0x69, 0x81, 0x9f, 0x3e, 0x5b,
                0xa4, 0x72, 0xae, 0x6c,
            ]),
        };

        let b58 = "xprv9yYPeJbXz5c4y4UzEaAvWDdWExv2sFsXoU4EN9ERnnKasDbooSNM5kdsoCPh5UMvAvTqqh1oykDxqGsRouyn2xKW2eyEW7R2ie7K7jF9P85";
        let actual = ExtendedPrivateKey::from_base58check(b58).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_extendedprivatekey_to_base58check() {
        let xprv = ExtendedPrivateKey {
            depth: 3,
            parent_fingerprint: Fingerprint([0x77, 0x92, 0x0d, 0x54]),
            child_number: ChildNumber::Normal(2),
            private_key: SecretKey::from_slice(&[
                0xc4, 0xf1, 0x36, 0x5e, 0xe3, 0xe6, 0x8f, 0xa4, 0x85, 0x40, 0x2c, 0x45, 0x05, 0xa3,
                0xca, 0x99, 0xff, 0xed, 0xb1, 0xdb, 0xd9, 0x6d, 0xff, 0xb2, 0x32, 0xe8, 0xe4, 0xa8,
                0x2d, 0xe9, 0x8e, 0xd0,
            ])
            .unwrap(),
            chain_code: ChainCode([
                0x43, 0x14, 0xc1, 0x00, 0xac, 0xaa, 0x75, 0xd8, 0x3f, 0xf2, 0xf7, 0xa9, 0xfa, 0xba,
                0xe2, 0x5b, 0x94, 0xff, 0xa6, 0xff, 0x52, 0x47, 0x35, 0x69, 0x81, 0x9f, 0x3e, 0x5b,
                0xa4, 0x72, 0xae, 0x6c,
            ]),
        };

        assert_eq!(xprv.to_base58check(), "xprv9yYPeJbXz5c4y4UzEaAvWDdWExv2sFsXoU4EN9ERnnKasDbooSNM5kdsoCPh5UMvAvTqqh1oykDxqGsRouyn2xKW2eyEW7R2ie7K7jF9P85");
    }

    #[test]
    fn test_derive_normal_private_from_extendedprivatekey() {
        let parent = ExtendedPrivateKey::from_base58check("xprv9yYPeJbXz5c4y4UzEaAvWDdWExv2sFsXoU4EN9ERnnKasDbooSNM5kdsoCPh5UMvAvTqqh1oykDxqGsRouyn2xKW2eyEW7R2ie7K7jF9P85").unwrap();
        let expected = ExtendedPrivateKey::from_base58check("xprvA2G3jyjAMnHQ563QWh2aq473PXFSGnxP4o5jVwXZXAhDYLgTAAttCvdEUPcmoAeDbTJnucjTnNnxUKfuPuyVpZiFArh2shdKHCcr1bYPfu8").unwrap();
        let actual = parent.derive_private(0.into()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_derive_hardened_private_from_extendedprivatekey() {
        let parent = ExtendedPrivateKey::from_base58check("xprv9yYPeJbXz5c4y4UzEaAvWDdWExv2sFsXoU4EN9ERnnKasDbooSNM5kdsoCPh5UMvAvTqqh1oykDxqGsRouyn2xKW2eyEW7R2ie7K7jF9P85").unwrap();
        let expected = ExtendedPrivateKey::from_base58check("xprvA2G3jyjJhSpNGLhKaUbg47ZHTpYxUmxtRwPktwV1Zb8J6MPFftxCw7JJVom3BGEor6byZrBewKMg5SF5zVXz1YPQUxs7qrHTCxZJVEKchBU").unwrap();
        let actual = parent.derive_private(ChildNumber::Hardened(0)).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_extendedpublickey_from_base58check() {
        let expected = ExtendedPublicKey {
            depth: 4,
            parent_fingerprint: Fingerprint([0xe9, 0x63, 0x32, 0x5c]),
            child_number: ChildNumber::Normal(5),
            public_key: PublicKey::from_slice(&[
                0x03, 0x15, 0xcf, 0x14, 0x2c, 0x10, 0xb4, 0x54, 0x37, 0x55, 0x67, 0x30, 0x97, 0x85,
                0x8e, 0x68, 0x75, 0x17, 0x86, 0x64, 0x27, 0x72, 0x10, 0xa5, 0x4d, 0xab, 0xc6, 0xd3,
                0x9d, 0xd8, 0x9b, 0xf7, 0x00,
            ])
            .unwrap(),
            chain_code: ChainCode([
                0x17, 0xb4, 0x85, 0xce, 0x71, 0x38, 0x05, 0x93, 0x85, 0x12, 0x05, 0x72, 0x2e, 0xdf,
                0x94, 0x3a, 0x3e, 0xa0, 0x03, 0x27, 0x7c, 0x6d, 0x8c, 0x13, 0x48, 0x29, 0x24, 0xf8,
                0x6d, 0xcf, 0x46, 0x68,
            ]),
        };

        let actual = ExtendedPublicKey::from_base58check("xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1").unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_extendedpublickey_to_base58check() {
        let xpub = ExtendedPublicKey {
            depth: 4,
            parent_fingerprint: Fingerprint([0xe9, 0x63, 0x32, 0x5c]),
            child_number: ChildNumber::Normal(5),
            public_key: PublicKey::from_slice(&[
                0x03, 0x15, 0xcf, 0x14, 0x2c, 0x10, 0xb4, 0x54, 0x37, 0x55, 0x67, 0x30, 0x97, 0x85,
                0x8e, 0x68, 0x75, 0x17, 0x86, 0x64, 0x27, 0x72, 0x10, 0xa5, 0x4d, 0xab, 0xc6, 0xd3,
                0x9d, 0xd8, 0x9b, 0xf7, 0x00,
            ])
            .unwrap(),
            chain_code: ChainCode([
                0x17, 0xb4, 0x85, 0xce, 0x71, 0x38, 0x05, 0x93, 0x85, 0x12, 0x05, 0x72, 0x2e, 0xdf,
                0x94, 0x3a, 0x3e, 0xa0, 0x03, 0x27, 0x7c, 0x6d, 0x8c, 0x13, 0x48, 0x29, 0x24, 0xf8,
                0x6d, 0xcf, 0x46, 0x68,
            ]),
        };

        assert_eq!(xpub.to_base58check(), "xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1");
    }

    #[test]
    fn test_extendedpublickey_from_private() {
        let xprv = ExtendedPrivateKey::from_base58check("xprv9yYPeJbXz5c4y4UzEaAvWDdWExv2sFsXoU4EN9ERnnKasDbooSNM5kdsoCPh5UMvAvTqqh1oykDxqGsRouyn2xKW2eyEW7R2ie7K7jF9P85").unwrap();
        let expected = ExtendedPublicKey::from_base58check("xpub6CXk3p8RpTANBYZTLbhvsMaEnzkXGibPAgyqAXe3M7rZk1vxLygbdYxMeVebhU36U9JX1Y1NU1SpvUDeSDFyYFq1CjFxwtgVw5H3HiVDmZQ").unwrap();
        let actual = ExtendedPublicKey::from_private(&xprv);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_derive_normal_public_from_extendedpublickey() {
        let parent = ExtendedPublicKey::from_base58check("xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1").unwrap();
        let expected = ExtendedPublicKey::from_base58check("xpub6G4dSrq5yjRz52Jr1rbSMEMQbUEoM3bcoLmGexYiLGRZp5NeNDMCBZPPVM4qagFfQjX9u6vUUnh2mBjFhR46LrkyvCUQPC7Jr958xygV72R").unwrap();
        let actual = parent.derive_public(0.into()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_derive_hardened_public_from_extendedpublickey_fails() {
        let parent = ExtendedPublicKey::from_base58check("xpub6FFQ9VG4C9qhWBgoa6nURfEkYAbkE6pyScvERKKniwfxGqFabPGUo7uaiHfBb2vpKqdiFkKW1Wab9T2EJahdWXmHXXLV6F53xtaae4uaqR1").unwrap();
        let expected = Err(Error::ImpossibleDerivation);
        let actual = parent.derive_public(ChildNumber::Hardened(0));
        assert_eq!(expected, actual);
    }
}
