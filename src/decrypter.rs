use crypto::blowfish::Blowfish;
use crypto::symmetriccipher::BlockDecryptor;
use permit;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use zip::read::{ZipArchive, ZipFile};

pub struct S63Decrypter<P: permit::GetPermit> {
    pub hwid: String,
    pub permit: P,
}

pub enum E {
    Io(io::Error),
    NoPermit(String),
    NonEightRead,
    ZipErr(zip::result::ZipError),
}

impl From<io::Error> for E {
    fn from(e: io::Error) -> E {
        E::Io(e)
    }
}

impl From<zip::result::ZipError> for E {
    fn from(e: zip::result::ZipError) -> E {
        E::ZipErr(e)
    }
}

impl<P: permit::GetPermit> S63Decrypter<P> {
    pub fn new(hwid: String, permit: P) -> S63Decrypter<P> {
        S63Decrypter { hwid, permit }
    }

    pub fn decrypt<R: Read + Seek, W: Write>(&self, cell: &str, rdr: R) -> Result<(), E> {
        let mut rdr = BufReader::new(rdr);
        let permit = match self.permit.get_permit(cell) {
            Some(val) => val,
            None => return Err(E::NoPermit(String::from(cell))),
        };
        let mut zipfile = Vec::new();
        decrypt_into(&permit.cell_permit.key1, &mut rdr, &mut zipfile)?;
        Ok(())
    }
}

fn decrypt_into<R: Read, W: Write>(key: &[u8], rdr: &mut R, wtr: &mut W) -> Result<(), E> {
    let crypto = Blowfish::new(&key);
    let mut enc = [0u8; 8];
    let mut dec = [0u8; 8];
    loop {
        match rdr.read(&mut enc)? {
            8 => {
                crypto.decrypt_block(&mut enc, &mut dec);
                wtr.write(&dec)?;
            }
            0 => break,
            _ => return Err(E::NonEightRead),
        };
    }
    Ok(())
}
