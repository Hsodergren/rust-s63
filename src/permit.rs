use byteorder::{BigEndian, ByteOrder};
use chrono::prelude::*;
use chrono::ParseError;
use crc::crc32;
use crypto::blowfish::Blowfish;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::num::ParseIntError;
use std::str::FromStr;

const PERMIT_RECORD_LENGTH: usize = 8 + 8 + 16 + 16 + 16;

pub trait GetPermit {
    fn get_permit(&self, cell: &str) -> Option<&PermitRecord>;
}

pub struct EmptyPermit();

impl GetPermit for EmptyPermit {
    fn get_permit(&self, _cell: &str) -> Option<&PermitRecord> {
        None
    }
}

impl<S: ::std::hash::BuildHasher> GetPermit for HashMap<String, PermitRecord, S> {
    fn get_permit(&self, cell: &str) -> Option<&PermitRecord> {
        self.get(cell)
    }
}

/// convinience method to get a GetPermit from a reader
pub fn permit_from_rdr<R: Read>(rdr: R, key: &str) -> Result<impl GetPermit, E> {
    let mut res = HashMap::new();
    let (_, f) = PermitFile::new(rdr)?;
    for permit in f.permits(key) {
        let p = permit?;
        res.insert(p.cell_permit.cell.clone(), p);
    }
    Ok(res)
}

/// convinience method to get a GetPermit from a file
pub fn permit_from_file<R: AsRef<std::path::Path>>(
    path: R,
    key: &str,
) -> Result<impl GetPermit, E> {
    Ok(permit_from_rdr(std::fs::File::open(path)?, key)?)
}

#[derive(Debug, PartialEq)]
pub struct CellPermit {
    pub cell: String,
    pub date: NaiveDate,
    pub key1: [u8; 5],
    pub key2: [u8; 5],
}

impl CellPermit {
    pub(crate) fn keys(&self) -> Keys {
        Keys {
            k1: &self.key1,
            k2: &self.key2,
            i: 0,
        }
    }
}

pub(crate) struct Keys<'a> {
    k1: &'a [u8; 5],
    k2: &'a [u8; 5],
    i: u8,
}

impl<'a> Iterator for Keys<'a> {
    type Item = &'a [u8; 5];

    fn next(&mut self) -> Option<&'a [u8; 5]> {
        self.i += 1;
        if self.i == 1 {
            Some(self.k1)
        } else if self.i == 2 {
            if self.k1 == self.k2 {
                None
            } else {
                Some(self.k2)
            }
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SericeLevelIndicator {
    SubscriptionPermit,
    SinglePurchasePermit,
}

impl FromStr for SericeLevelIndicator {
    type Err = E;
    fn from_str(s: &str) -> Result<SericeLevelIndicator, Self::Err> {
        match s {
            "0" => Ok(SericeLevelIndicator::SubscriptionPermit),
            "1" => Ok(SericeLevelIndicator::SinglePurchasePermit),
            _ => Err(E::InvalidSli),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct PermitRecord {
    pub cell_permit: CellPermit,
    pub sli: SericeLevelIndicator,
    pub edition: Option<u8>,
    pub data_server_id: String,
    pub comment: String,
}

#[derive(Debug)]
pub enum E {
    InvalidDate(ParseError),
    ParseError(usize, String),
    IoErr(io::Error),
    ParseIntErr(ParseIntError),
    CellPermitTooShort,
    InvalidSli,
    InvalidChksum,
    FromHex(hex::FromHexError),
}

impl From<ParseError> for E {
    fn from(e: ParseError) -> E {
        E::InvalidDate(e)
    }
}

impl From<ParseIntError> for E {
    fn from(e: ParseIntError) -> E {
        E::ParseIntErr(e)
    }
}

impl From<io::Error> for E {
    fn from(e: io::Error) -> E {
        E::IoErr(e)
    }
}

impl From<hex::FromHexError> for E {
    fn from(e: hex::FromHexError) -> E {
        E::FromHex(e)
    }
}

pub struct MetaData {
    pub date: NaiveDateTime,
    pub version: u8,
}

pub struct PermitFile<R: Read> {
    file: BufReader<R>,
}

pub struct Permits<'a, R: Read>(BufReader<R>, &'a str);

impl<'a, R: Read> Iterator for Permits<'a, R> {
    type Item = Result<PermitRecord, E>;

    fn next(&mut self) -> Option<Result<PermitRecord, E>> {
        let mut s = String::new();
        let res = match self.0.read_line(&mut s) {
            Ok(r) => match r {
                0 => None,
                _ => Some(parse_permit(&s, self.1)),
            },
            Err(e) => Some(Err(e.into())),
        };

        if s.starts_with(":ENC") || s.starts_with(":ECS") {
            self.next()
        } else {
            res
        }
    }
}

// parses one ECS row in the PERMIT.TXT file
fn parse_permit(s: &str, key: &str) -> Result<PermitRecord, E> {
    let mut ss = s.split(',');
    let cell_permit = parse_cell_permit(ss.next().ok_or(E::CellPermitTooShort)?, key)?;
    let sli = ss.next().ok_or(E::CellPermitTooShort)?.parse()?;
    let edition = match ss.next().ok_or(E::CellPermitTooShort)? {
        "" => None,
        a => Some(a.parse()?),
    };
    let data_server_id = String::from(ss.next().ok_or(E::CellPermitTooShort)?);
    let comment = String::from(ss.next().ok_or(E::CellPermitTooShort)?.trim());

    Ok(PermitRecord {
        cell_permit,
        sli,
        edition,
        data_server_id,
        comment,
    })
}

fn parse_cell_permit(s: &str, key: &str) -> Result<CellPermit, E> {
    if s.len() != PERMIT_RECORD_LENGTH {
        return Err(E::ParseError(1, String::from("")));
    }
    permit_chksum(s, key)?;
    let cell = String::from(&s[0..8]);
    let date = NaiveDate::parse_from_str(&s[8..16], "%Y%m%d")?;
    let key1 = decrypt_key(&s[16..32], key)?;
    let key2 = decrypt_key(&s[32..48], key)?;
    Ok(CellPermit {
        cell,
        date,
        key1,
        key2,
    })
}

fn permit_chksum(s: &str, key: &str) -> Result<(), E> {
    let (rest, chksum) = (&s[0..48], &s[48..]);
    let chksum = hex::decode(&chksum)?;
    let crc32_arr = crc32(rest.as_bytes());
    let mut enc = [0u8; 8];
    let crypto = Blowfish::new(hwid6(key).as_bytes());
    crypto.encrypt_block(
        crc32_arr
            .into_iter()
            .chain([4u8; 4].into_iter())
            .cloned()
            .collect::<Vec<u8>>()
            .as_slice(),
        &mut enc,
    );

    if chksum == enc {
        Ok(())
    } else {
        Err(E::InvalidChksum)
    }
}

fn crc32(data: &[u8]) -> [u8; 4] {
    let crc32 = crc32::checksum_ieee(data);
    let mut crc32_arr = [0u8; 4];
    BigEndian::write_u32(&mut crc32_arr, crc32);
    crc32_arr
}

fn hwid6(hwid: &str) -> String {
    hwid.chars().chain(hwid[0..1].chars()).collect()
}

fn decrypt_key(s: &str, hwid: &str) -> Result<[u8; 5], E> {
    let crypto = Blowfish::new(hwid6(hwid).as_bytes());
    let mut dec = [0u8; 8];
    crypto.decrypt_block(hex::decode(s)?.as_slice(), &mut dec);
    Ok([dec[0], dec[1], dec[2], dec[3], dec[4]])
}

impl<'a, R: Read> PermitFile<R> {
    pub fn new(rdr: R) -> Result<(MetaData, PermitFile<R>), E> {
        let mut rdr = BufReader::new(rdr);
        let (mut date_str, mut version_str) = (String::new(), String::new());
        rdr.read_line(&mut date_str)?;
        let date = get_date(&date_str)?;
        rdr.read_line(&mut version_str)?;
        let version = get_version(&version_str)?;

        Ok((MetaData { date, version }, PermitFile { file: rdr }))
    }

    pub fn permits(self, key: &'a str) -> Permits<'a, R> {
        Permits(self.file, key)
    }
}

fn get_date(l: &str) -> Result<NaiveDateTime, E> {
    let l = l.trim();
    let l = if l.starts_with(":DATE ") {
        &l[6..]
    } else {
        return Err(E::ParseError(1, l.to_owned()));
    };

    Ok(NaiveDateTime::parse_from_str(l, "%Y%m%d %H:%M")
        .or_else(|_| NaiveDate::parse_from_str(l, "%Y%m%d").map(|x| x.and_hms(0, 0, 0)))?)
}

fn get_version(l: &str) -> Result<u8, E> {
    let l = l.trim();
    let l = if l.starts_with(":VERSION ") {
        &l[9..]
    } else {
        return Err(E::ParseError(2, l.to_owned()));
    };

    Ok(l.parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_date() -> Result<(), E> {
        let tests = vec![
            (
                ":DATE 19990101 20:20",
                NaiveDate::from_ymd(1999, 1, 1).and_hms(20, 20, 0),
            ),
            (
                ":DATE 19990101",
                NaiveDate::from_ymd(1999, 1, 1).and_hms(0, 0, 0),
            ),
            (
                ":DATE 20120422 14:11",
                NaiveDate::from_ymd(2012, 4, 22).and_hms(14, 11, 0),
            ),
        ];
        for (i, a) in tests.iter().enumerate() {
            println!("test {}: {}", i, a.0);
            match get_date(a.0) {
                Ok(val) => assert_eq!(val, a.1),
                Err(e) => {
                    println!("{:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn read_version() -> Result<(), E> {
        let tests = vec![(":VERSION 2", 2), (":VERSION 123", 123)];

        for (i, a) in tests.iter().enumerate() {
            println!("test {}: {}", i, a.0);
            assert_eq!(get_version(a.0)?, a.1);
        }
        Ok(())
    }

    #[test]
    fn parse_permit() -> Result<(), E> {
        let p_str = "GB61021A200711301F3EC4E525FFFCEC1F3EC4E525FFFCEC3E91E355E4E82D30,0,,GB,";
        let p = super::parse_permit(p_str, &String::from("12345"))?;
        assert_eq!(p.cell_permit.cell, "GB61021A");
        assert_eq!(p.cell_permit.date, NaiveDate::from_ymd(2007, 11, 30));
        Ok(())
    }

    #[test]
    fn decrypt_key() -> Result<(), E> {
        let hwid = "12348";
        let expected_key = "C1CB518E9C";
        let encrypted_key = "BEB9BFE3C7C6CE68";
        let decrypted_key = hex::encode_upper(super::decrypt_key(encrypted_key, hwid)?);
        assert_eq!(decrypted_key, expected_key);
        Ok(())
    }

    #[test]
    fn keys_iter() {
        let p = CellPermit {
            cell: String::from("abc"),
            date: NaiveDate::from_ymd(2012, 4, 22),
            key1: [0, 0, 0, 0, 0],
            key2: [0, 0, 0, 0, 0],
        };
        let mut iter = p.keys();
        assert_eq!(iter.next(), Some(&[0, 0, 0, 0, 0]));
        assert_eq!(iter.next(), None);

        let p = CellPermit {
            cell: String::from("abc"),
            date: NaiveDate::from_ymd(2012, 4, 22),
            key1: [0, 0, 0, 0, 0],
            key2: [0, 0, 0, 0, 1],
        };
        let mut iter = p.keys();
        assert_eq!(iter.next(), Some(&[0, 0, 0, 0, 0]));
        assert_eq!(iter.next(), Some(&[0, 0, 0, 0, 1]));
        assert_eq!(iter.next(), None);
    }
}
