//! Package for handling user permits, both creating and decrypting


use crypto::symmetriccipher::BlockDecryptor;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::blowfish::Blowfish;
use byteorder::{ReadBytesExt,BigEndian,WriteBytesExt};
use hex;
use crc;


const PERMIT_LENGTH : usize = 16 + 8 + 4;
const KEY_LENGTH : usize = 5;
const HWID_LENGTH : usize = 5;
const ID_LENGTH : usize = 4;

#[derive(Debug)]
pub enum PermitErr {
    // the length of the hwid
    NonHex,
    // the length of the hwid
    WrongLength(usize, usize),
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
    hwid: String,
    id: String,
}

impl UserPermit {
    pub fn new(hwid: &str, id: &str) -> Result<UserPermit,PermitErr> {
        validator(hwid, HWID_LENGTH)?;
        validator(id, ID_LENGTH)?;
        Ok(UserPermit {
            hwid: String::from(hwid),
            id: String::from(id) 
        })
    }

    pub fn decrypt(up: &str, key: &str) -> Result<UserPermit,PermitErr> {
        if !up.chars().chain(key.chars()).all(is_hex) {
            return Err(PermitErr::NonHex);
        }
        validator(key, KEY_LENGTH)?;
        let (enc_hwid, _, id) = check_up_string(&up)?;
        let crypto = Blowfish::new(key.as_bytes());
        let enc = &mut [0u8; 8];
        crypto.decrypt_block(hex::decode(enc_hwid)?.as_ref(), enc);

        Ok(UserPermit {
            hwid : String::from_utf8(enc[0..5].into()).unwrap(),
            id : String::from(id),
        })
    }

    pub fn encrypt(&self, key: &str) -> Result<String,PermitErr> {
        validator(key, KEY_LENGTH)?;
        let c = Blowfish::new(key.as_bytes());
        let enc = &mut [0u8; 8];
        let mut data : Vec<u8> = Vec::with_capacity(8);
        data.extend(self.hwid.as_bytes().iter().chain([3u8; 3].into_iter()));
        c.encrypt_block(data.as_slice(), enc);
        let enc_hwid = hex::encode_upper(enc);
        let mut w = Vec::with_capacity(4);
        w.write_u32::<BigEndian>(crc::crc32::checksum_ieee(enc_hwid.as_bytes())).unwrap();
        let chksum = hex::encode_upper(w.as_slice());
        Ok(enc_hwid + &chksum + &self.id)
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

// checks length of string and that all characters are valid hex
fn validator(a: &str, l: usize) -> Result<(), PermitErr> {
    if a.len() != l {
        return Err(PermitErr::WrongLength(a.len(), l));
    }
    if !a.chars().all(is_hex) {
        return Err(PermitErr::NonHex);
    }
    Ok(())
}

// sanity checks the encrypted userpermit
// returns the different parts of the encrypted
fn check_up_string(up: &str) -> Result<(&str,&str,&str), PermitErr> {
    validator(up, PERMIT_LENGTH)?;
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

    // a user permit that gets encrypted and then decrypted should get back same result
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
        assert_eq!(up1, UserPermit::decrypt(up1.encrypt(key1)?.as_str(), key1)?);

        assert_eq!(up2, UserPermit::decrypt(up2.encrypt(key2)?.as_str(), key2)?);
        Ok(())
    }

    #[test]
    fn decrypt() -> Result<(), PermitErr> {
        let key = "10121";
        let up = "66B5CBFDF7E4139D5B6086C23130";
        let expected = UserPermit {
            hwid: String::from("12345"),
            id: String::from("3130"),
        };
        assert_eq!(expected, UserPermit::decrypt(up, key)?);
        Ok(())
    }

    #[test]
    fn encrypt() -> Result<(), PermitErr> {
        let key = "10121";
        let up = UserPermit {
            hwid: String::from("12345"),
            id: String::from("3130"),
        };
        let expected = "66B5CBFDF7E4139D5B6086C23130";
        assert_eq!(expected, up.encrypt(key)?);
        Ok(())
    }
}
