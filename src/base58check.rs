use crate::hash;
use std::convert::TryInto;

/// Base58 index to Base58 character conversion table.
///
/// Given a byte in the range `0..58`, this table enables constant-time conversion to a Base58
/// character.
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 character to Base58 index conversion table.
///
/// This enables constant-time conversion of a `u8` containing a character from the Base58 alphabet
/// to the corresponding index within the alphabet. An index of `0xff` indicates that the value is
/// not a valid Base58 character.
const INDEXES: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff, 0x11, 0x12, 0x13, 0x14, 0x15, 0xff,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0xff, 0x2c, 0x2d, 0x2e,
    0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Error represents all of the possible errors that can arise during Base58Check decoding.
#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidCharacter { character: char, position: usize },
    InvalidLength(usize),
    InvalidVersion(Vec<u8>),
    InvalidChecksum { expected: [u8; 4], actual: [u8; 4] },
}

/// Encodes a byte slice into a Base58Check string.
pub fn encode(v: &[u8]) -> String {
    let checksum = &hash::double_sha256(v)[..4];
    let (head, tail) = v.split_at(v.iter().position(|c| *c != 0).unwrap_or(0));
    let tail = to_base58(&[tail, checksum]);

    head.iter()
        .chain(tail.iter())
        .map(|index| ALPHABET[*index as usize] as char)
        .collect()
}

/// Decodes a Base58Check-encoded string.
pub fn decode(v: &str) -> Result<Vec<u8>, Error> {
    let indexes = v
        .bytes()
        .enumerate()
        .map(|(position, character)| match INDEXES[character as usize] {
            0xff => Err(Error::InvalidCharacter {
                character: character as char,
                position,
            }),
            idx => Ok(idx as u8),
        })
        .collect::<Result<Vec<u8>, Error>>()?;

    let (head, tail) = indexes.split_at(indexes.iter().position(|c| *c != 0).unwrap_or(0));
    let tail = to_base256(&[tail]);

    let mut data = head
        .iter()
        .copied()
        .chain(tail.iter().copied())
        .collect::<Vec<u8>>();

    if data.len() < 4 {
        return Err(Error::InvalidLength(data.len()));
    }

    let expected_checksum = &data.drain(data.len() - 4..).collect::<Vec<u8>>()[..];
    let actual_checksum = &hash::double_sha256(&data)[..4];

    if expected_checksum == actual_checksum {
        Ok(data)
    } else {
        Err(Error::InvalidChecksum {
            expected: expected_checksum.try_into().unwrap(),
            actual: actual_checksum.try_into().unwrap(),
        })
    }
}

/// Convert a series of base-256 integer slices into a base-58 integer vector.
fn to_base58(parts: &[&[u8]]) -> Vec<u8> {
    let combined_len: usize = parts.iter().map(|p| p.len()).sum();
    // log 256 ÷ log 58 ≈ 138 ÷ 100
    let mut buf = vec![0; combined_len * 138 / 100 + 1];
    let mut end = 0;

    for part in parts.iter() {
        for word in part.iter() {
            let mut carry = *word as u32;
            let mut cursor = 0;

            while carry != 0 || cursor < end {
                carry += 256 * buf[cursor] as u32;
                buf[cursor] = (carry % 58) as u8;
                carry /= 58;
                cursor += 1;
            }

            end = cursor;
        }
    }

    buf.truncate(end);
    buf.iter().rev().copied().collect()
}

/// Convert a series of base-58 integer slices into a base-256 integer vector.
fn to_base256(parts: &[&[u8]]) -> Vec<u8> {
    let combined_len: usize = parts.iter().map(|p| p.len()).sum();
    // log 58 ÷ log 256 ≈ 733 ÷ 1000
    let mut buf = vec![0u8; combined_len * 733 / 1000 + 1];
    let mut end = 0;

    for part in parts.iter() {
        for word in part.iter() {
            let mut carry = *word as u32;
            let mut cursor = 0;

            while carry != 0 || cursor < end {
                carry += 58 * buf[cursor] as u32;
                buf[cursor] = (carry % 256) as u8;
                carry /= 256;
                cursor += 1;
            }

            end = cursor;
        }
    }

    buf.truncate(end);
    buf.iter().rev().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b"abc"), "4h3c6RH52R");
        assert_eq!(encode(b"\0hello\0"), "16sBRWytR3DeJdK");
    }

    #[test]
    fn test_decode_ok() {
        assert_eq!(decode("4h3c6RH52R").unwrap(), b"abc");
        assert_eq!(decode("16sBRWytR3DeJdK").unwrap(), b"\0hello\0");
    }

    #[test]
    fn test_decode_err() {
        assert_eq!(decode(""), Err(Error::InvalidLength(0)));
        assert_eq!(
            decode("123I"),
            Err(Error::InvalidCharacter {
                position: 3,
                character: 'I'
            })
        );
        assert_eq!(
            decode("16sBRWytR3DeJdL"),
            Err(Error::InvalidChecksum {
                expected: [168, 184, 94, 231],
                actual: [168, 184, 94, 230]
            })
        );
    }
}
