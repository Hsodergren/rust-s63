use std::io::BufReader;
use std::io::prelude::*;
use chrono::prelude::*;
use std::io;

pub struct Permit {
    pub cell: String,
    pub date: String,
    pub key: String,
}

pub enum E {
    InvalidDate(chrono::ParseError),
    ParseError(usize, String),
    IoErr(io::Error),
    ParseIntErr(std::num::ParseIntError)

}


impl From<chrono::ParseError> for E {
    fn from(e: chrono::ParseError) -> E {
        E::InvalidDate(e)
    }
}

impl From<std::num::ParseIntError> for E {
    fn from(e: std::num::ParseIntError) -> E {
        E::ParseIntErr(e)
    }
}

impl From<io::Error> for E {
    fn from(e: io::Error) -> E {
        E::IoErr(e)
    }
}

pub struct MetaData {
    pub date: DateTime<FixedOffset>,
    pub version: u8,
}

pub struct PermitFile<R: Read> {
    file: BufReader<R>,
}

pub struct Permits<R: Read>(BufReader<R>);

impl<R: Read> Iterator for Permits<R> {
    type Item = Permit;

    fn next(&mut self) -> Option<Permit>{
        None
    }
}

impl<R: Read> PermitFile<R> {
    pub fn new(rdr: R) -> Result<(MetaData, PermitFile<R>), E> {
        let mut rdr = BufReader::new(rdr);
        let (mut date_str, mut version_str) = (String::new(), String::new());
        rdr.read_line(&mut date_str)?;
        let date = get_date(&date_str)?;
        rdr.read_line(&mut version_str)?;
        let version = get_version(&version_str)?;

        Ok((MetaData{ date, version}, PermitFile{ file: rdr }))
    }

    pub fn permits(self) -> Permits<R> {
        Permits(self.file)
    }
}

fn get_date(l: &str) -> Result<DateTime<FixedOffset>, E> {
    let l = if l.starts_with(":DATE ") { 
        &l[6..] 
    } else { 
        return Err(E::ParseError(1, l.to_owned())) 
    };

    Ok(DateTime::parse_from_str(l, "%Y%m%d %H:%M").
        or(DateTime::parse_from_str(l, "%Y%m%d"))?)
}
fn get_version(l: &str) -> Result<u8, E> {
    let l = if l.starts_with(":VERSION ") { 
        &l[9..] 
    } else { 
        return Err(E::ParseError(2, l.to_owned())) 
    };

    Ok(l.parse()?)
}