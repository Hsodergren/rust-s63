use std::io::BufReader;
use std::io::prelude::*;
use chrono::prelude::*;
use chrono::ParseError;
use std::num::ParseIntError;
use std::io;

pub struct Permit {
    pub cell: String,
    pub date: String,
    pub key: String,
}

#[derive(Debug)]
pub enum E {
    InvalidDate(ParseError),
    ParseError(usize, String),
    IoErr(io::Error),
    ParseIntErr(ParseIntError)

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

fn get_date(l: &str) -> Result<NaiveDateTime, E> {
    let l = if l.starts_with(":DATE ") { 
        &l[6..] 
    } else { 
        return Err(E::ParseError(1, l.to_owned())) 
    };
    println!("'{}'", l);

    Ok(NaiveDateTime::parse_from_str(l, "%Y%m%d %H:%M").
       or(NaiveDate::parse_from_str(l, "%Y%m%d").
          map(|x| x.and_hms(0,0,0)))?
       )
}

fn get_version(l: &str) -> Result<u8, E> {
    let l = if l.starts_with(":VERSION ") { 
        &l[9..] 
    } else { 
        return Err(E::ParseError(2, l.to_owned())) 
    };

    Ok(l.parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    #[test]
    fn read_date() -> Result<(), E> {
        let a = vec![
            (":DATE 19990101 20:20",NaiveDate::from_ymd(1999,1,1).and_hms(20,20,0)),
            (":DATE 19990101", NaiveDate::from_ymd(1999,1,1).and_hms(0,0,0))
        ];
        for (i, a) in a.iter().enumerate() {
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
    fn read_permit() {
    }
}
