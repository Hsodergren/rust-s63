use chrono::prelude::*;
use chrono::ParseError;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::num::ParseIntError;

const PERMIT_RECORD_LENGTH: usize = 8 + 8 + 16 + 16 + 16;

#[derive(Debug, PartialEq)]
pub struct CellPermit {
    pub cell: String,
    pub date: NaiveDate,
    pub key1: String,
    pub key2: String,
}

#[derive(Debug, PartialEq)]
pub enum SericeLevelIndicator {
    SubscriptionPermit,
    SinglePurchasePermit,
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

pub struct MetaData {
    pub date: NaiveDateTime,
    pub version: u8,
}

pub struct PermitFile<R: Read> {
    file: BufReader<R>,
}

pub struct Permits<R: Read>(BufReader<R>);

impl<R: Read> Iterator for Permits<R> {
    type Item = Result<PermitRecord, E>;

    fn next(&mut self) -> Option<Result<PermitRecord, E>> {
        let mut s = String::new();
        let res = match self.0.read_line(&mut s) {
            Ok(r) => match r {
                0 => None,
                _ => Some(parse_permit(&s[..s.len() - 1])),
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
fn parse_permit(s: &str) -> Result<PermitRecord, E> {
    let ss: Vec<&str> = s.split(",").into_iter().collect();
    if ss.len() != 5 {
        return Err(E::CellPermitTooShort);
    }
    let cell_permit = parse_cell_permit(ss[0])?;
    let sli = match ss[1] {
        "0" => SericeLevelIndicator::SubscriptionPermit,
        "1" => SericeLevelIndicator::SinglePurchasePermit,
        _ => return Err(E::InvalidSli),
    };
    let edition = match ss[2] {
        "" => None,
        a => Some(a.parse()?),
    };
    let data_server_id = String::from(ss[3]);
    let comment = String::from(ss[4]);

    Ok(PermitRecord {
        cell_permit,
        sli,
        edition,
        data_server_id,
        comment,
    })
}

// TODO decrypt keys and check chksum
fn parse_cell_permit(s: &str) -> Result<CellPermit, E> {
    if s.len() != PERMIT_RECORD_LENGTH {
        return Err(E::ParseError(1, String::from("")));
    }
    let cell = String::from(&s[0..8]);
    let date = NaiveDate::parse_from_str(&s[8..16], "%Y%m%d")?;
    let key1 = String::from(&s[16..32]);
    let key2 = String::from(&s[32..48]);
    let _chksum = String::from(&s[48..PERMIT_RECORD_LENGTH]);
    Ok(CellPermit {
        cell,
        date,
        key1,
        key2,
    })
}

impl<R: Read> PermitFile<R> {
    pub fn new(rdr: R) -> Result<(MetaData, PermitFile<R>), E> {
        let mut rdr = BufReader::new(rdr);
        let (mut date_str, mut version_str) = (String::new(), String::new());
        rdr.read_line(&mut date_str)?;
        let date = get_date(&date_str[..date_str.len() - 1])?;
        rdr.read_line(&mut version_str)?;
        let version = get_version(&version_str[..version_str.len() - 1])?;

        Ok((MetaData { date, version }, PermitFile { file: rdr }))
    }

    pub fn permits(self) -> Permits<R> {
        Permits(self.file)
    }
}

fn get_date(l: &str) -> Result<NaiveDateTime, E> {
    let l = if l.starts_with(":DATE ") {
        &l[6..]
    } else {
        return Err(E::ParseError(1, l.to_owned()));
    };

    Ok(NaiveDateTime::parse_from_str(l, "%Y%m%d %H:%M")
        .or(NaiveDate::parse_from_str(l, "%Y%m%d").map(|x| x.and_hms(0, 0, 0)))?)
}

fn get_version(l: &str) -> Result<u8, E> {
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
        let p = super::parse_permit(p_str)?;
        assert_eq!(p.cell_permit.cell, "GB61021A");
        assert_eq!(p.cell_permit.date, NaiveDate::from_ymd(2007, 11, 30));
        Ok(())
    }
}
