use chrono::ParseError;
use failure::Fail;
use std::io;
use std::num::ParseIntError;
#[derive(Debug, Fail)]
pub enum E {
    #[fail(display = "ParseError: {}", _0)]
    InvalidDate(#[cause] ParseError),
    #[fail(display = "Invalid DATE field: {}", _0)]
    ParseCellPermit(CPReason),
    #[fail(display = "Invalid DATE field: {}", _0)]
    ParseDateError(String),
    #[fail(display = "Invalid VERSION field: {}", _0)]
    ParseVersionError(String),
    #[fail(display = "IO Error: {}", _0)]
    IoErr(#[cause] io::Error),
    #[fail(display = "ParseIntError: {}", _0)]
    ParseIntErr(#[cause] ParseIntError),
    #[fail(display = "Too short Cell Permit")]
    CellPermitTooShort,
    #[fail(display = "Invalid Serice Level Indicator")]
    InvalidSli,
    #[fail(display = "Invalid Checksum")]
    InvalidChksum,
    #[fail(display = "HexError: {}", _0)]
    FromHex(hex::FromHexError),
}

#[derive(Debug, Fail)]
pub enum CPReason {
    #[fail(display = "Invalid Date format {}", _0)]
    Date(#[cause] ParseError),
    #[fail(display = "Invalid length {}, expects length 64", _0)]
    Length(usize),
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
