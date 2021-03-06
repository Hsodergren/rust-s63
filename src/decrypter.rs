use crate::permit;
use crypto::blowfish::Blowfish;
use crypto::symmetriccipher::BlockDecryptor;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, Cursor};
use zip::read::ZipArchive;

pub struct S63Decrypter<P: permit::GetPermit> {
    pub permit: P,
}

#[derive(Debug)]
pub enum E {
    DecryptionFailed,
    PermitIsNone,
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

impl S63Decrypter<permit::EmptyPermit> {
    pub fn new() -> S63Decrypter<permit::EmptyPermit> {
        S63Decrypter {
            permit: permit::EmptyPermit(),
        }
    }
}

impl Default for S63Decrypter<permit::EmptyPermit> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: permit::GetPermit> S63Decrypter<P> {
    pub fn new_with_permit(permit: P) -> S63Decrypter<P> {
        S63Decrypter { permit }
    }

    pub fn with_cell<R: Read + Seek, W: Write>(
        &self,
        cell: &str,
        rdr: R,
        mut wtr: W,
    ) -> Result<(), E> {
        let mut rdr = BufReader::new(rdr);
        let permit = match self.permit.get_permit(cell) {
            Some(val) => val,
            None => return Err(E::NoPermit(String::from(cell))),
        };
        for (i, key) in permit.cell_permit.keys().enumerate() {
            if i != 0 {
                rdr.seek(std::io::SeekFrom::Start(0))?;
            }
            match self.with_key(key, &mut rdr, &mut wtr) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }

        Err(E::DecryptionFailed)
    }

    pub fn with_key<R: Read, W: Write>(&self, key: &[u8], mut rdr: R, mut wtr: W) -> Result<(), E> {
        let mut zipfile = Vec::new();
        decrypt_into(key, &mut rdr, &mut zipfile)?;
        let mut archive = match ZipArchive::new(Cursor::new(zipfile)) {
            Ok(archive) => archive,
            Err(_) => return Err(E::DecryptionFailed),
        };
        let mut zf = archive.by_index(0)?;
        std::io::copy(&mut zf, &mut wtr)?;
        Ok(())
    }

    pub fn with_key_bytes<D: AsRef<[u8]>>(&self, key: &[u8], data: D) -> Result<Vec<u8>, E> {
        let mut res = Vec::new();
        let mut rdr = Cursor::new(data);
        self.with_key(key, &mut rdr, &mut res)?;
        Ok(res)
    }

    pub fn with_cell_bytes<D: AsRef<[u8]>>(&self, cell: &str, data: D) -> Result<Vec<u8>, E> {
        let mut res = Vec::new();
        let mut rdr = Cursor::new(data);
        self.with_cell(cell, &mut rdr, &mut res)?;
        Ok(res)
    }

    pub fn can_decrypt<D: AsRef<[u8]>>(&self, key: &[u8], data: D) -> bool {
        self.with_key_bytes(key, data).is_ok()
    }
}

fn decrypt_into<R: Read, W: Write>(key: &[u8], rdr: &mut R, wtr: &mut W) -> Result<(), E> {
    let crypto = Blowfish::new(&key);
    let mut enc = [0u8; 8];
    let mut dec = [0u8; 8];
    let mut first = true;
    loop {
        let b = rdr.read(&mut enc)?;
        if b == 0 {
            break;
        }

        if !first {
            first = false
        } else {
            wtr.write_all(&dec)?;
        }
        crypto.decrypt_block(&enc, &mut dec);
    }
    wtr.write_all(depad(&dec))?;

    Ok(())
}

fn depad(data: &[u8]) -> &[u8] {
    assert!(data.len() == 8);
    if data[7] > 8 {
        data
    } else {
        let last = data[7];
        for i in 0..last {
            if data[(7 - i) as usize] != last {
                return data;
            }
        }
        &data[..(8 - last) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_depad() {
        let mut data = depad(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7, 8]);

        data = depad(&[1, 2, 3, 4, 5, 6, 7, 1]);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);

        data = depad(&[1, 2, 3, 4, 5, 6, 2, 2]);
        assert_eq!(data, [1, 2, 3, 4, 5, 6]);

        data = depad(&[1, 2, 3, 4, 5, 6, 2, 2]);
        assert_eq!(data, [1, 2, 3, 4, 5, 6]);

        data = depad(&[1, 7, 7, 7, 7, 7, 7, 7]);
        assert_eq!(data, [1]);

        data = depad(&[8, 8, 8, 8, 8, 8, 8, 8]);
        assert_eq!(data, []);
    }
}
