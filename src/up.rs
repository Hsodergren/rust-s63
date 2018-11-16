//! Package for handling user permits, both creating and decrypting


use crypto::symmetriccipher::BlockDecryptor;
use crypto::blowfish::Blowfish;
use byteorder::{ReadBytesExt,BigEndian};
use hex;
use crc;


const PERMIT_LENGTH : u8 = 16 + 8 + 4;
const KEY_LENGTH : u8 = 5;

#[derive(Debug)]
pub enum PermitErr {
    // the length of the hwid
    NonHex,
    // the length of the hwid
    WrongUpLength(usize),
    // the length of the key
    WrongKeyLength(usize),
    HashMisMatch,
    HexErr(hex::FromHexError),
}

impl From<hex::FromHexError> for PermitErr {
    fn from(h: hex::FromHexError) -> PermitErr {
        PermitErr::HexErr(h)
    }
}

#[derive(Debug, PartialEq)]
pub struct UserPermit {
    pub hwid: String,
    pub id: String,
}

impl UserPermit {
    pub fn new(hwid: String, id: String) -> UserPermit {
        UserPermit { hwid, id }
    }

    pub fn decrypt(up: String, key: &str) -> Result<UserPermit,PermitErr> {
        if !up.chars().chain(key.chars()).all(is_hex) {
            return Err(PermitErr::NonHex);
        }
        check_key(key)?;
        let (enc_hwid, _, id) = check_up_string(&up)?;
        let crypto = Blowfish::new(key.as_bytes());
        let enc = &mut [0u8; 8];
        crypto.decrypt_block(hex::decode(enc_hwid)?.as_slice(), enc);

        Ok(UserPermit {
            hwid : hex::encode_upper(&enc[0..5]),
            id : String::from(id),
        })
    }

    pub fn encrypt(&self, key: &str) -> Result<String,PermitErr> {
        Ok(String::from(key))
    }
}

// returns true if c is a valid hexadecimal character else false
fn is_hex(c : char) -> bool {
    if  (c >= '0' && c <= '9') || 
        (c >= 'a' && c <= 'f') || 
        (c >= 'A' && c <= 'F') {
        true
    } else {
        false
    }
}

// sanity checks the key
fn check_key(key: &str) -> Result<(), PermitErr> {
    let kl = key.len();
    if kl != KEY_LENGTH as usize {
        return Err(PermitErr::WrongKeyLength(kl));
    }
    Ok(())
}

// sanity checks the encrypted userpermit
// returns the different parts of the encrypted
fn check_up_string(up: &String) -> Result<(&str,&str,&str), PermitErr> {
    let ul = up.len();
    if ul != PERMIT_LENGTH as usize {
        return Err(PermitErr::WrongUpLength(ul));
    } 
    let (enc_hwid, chksum, id) = (&up[..16], &up[16..24], &up[24..]);

    let chksum_u32 = hex::decode(chksum)?.as_slice().read_u32::<BigEndian>().unwrap();

    if crc::crc32::checksum_ieee(enc_hwid.as_bytes()) != chksum_u32 {
        return Err(PermitErr::HashMisMatch);
    }
    Ok((enc_hwid, chksum, id))
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn is_hex_test() {
        assert_eq!("0123456789AaBbCcDdEeFf".chars().all(is_hex), true);
        assert_eq!("0123456789AaBbCcDdEeFfGg".chars().all(is_hex), false);
    }

    #[test]
    fn encrypt_decrypt_test() -> Result<(),PermitErr> {
        let key1 = "12345";
        let up1 = UserPermit {
            hwid: String::from("12345"),
            id: String::from("1111"),
        };
        let key2 = "abcde";
        let up2 = UserPermit {
            hwid: String::from("12ab5"),
            id: String::from("1254"),
        };
        assert_eq!(up1, UserPermit::decrypt(up1.encrypt(key1)?, key1)?);

        assert_eq!(up2, UserPermit::decrypt(up2.encrypt(key2)?, key2)?);
        Ok(())
    }
}
