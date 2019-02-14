extern crate chrono;
extern crate rust_s63;

use chrono::prelude::*;
use rust_s63::permit;

#[test]
fn read_permit_file() -> Result<(), failure::Error> {
    let s = r":DATE 20071023 10:20
:VERSION 2
:ENC
GB10000120071231517C1E9A4BCF3826517C1E9A4BCF38263A5A80B723886A31,0,1,GB,hej
GB10000220071231BBA63203A5992420BBA63203A5992420ED56CD0F5F7390FC,1,0,GB,
GB1000042007123164B51D24FB77ADB364B51D24FB77ADB3EEA2291965966391,0,,GB,
:ECS";
    let (md, pf) = permit::PermitFile::new(std::io::Cursor::new(s))?;
    assert_eq!(
        md.date,
        NaiveDate::from_ymd(2007, 10, 23).and_hms(10, 20, 0)
    );
    let cps: Vec<_> = pf.permits("12345").map(|x| x.unwrap()).collect();
    assert_eq!(cps.len(), 3);
    let cps0cp = permit::CellPermit {
        cell: String::from("GB100001"),
        date: chrono::NaiveDate::from_ymd(2007, 12, 31),
        key1: [54, 62, 171, 50, 198],
        key2: [54, 62, 171, 50, 198],
    };
    let cps1cp = permit::CellPermit {
        cell: String::from("GB100002"),
        date: chrono::NaiveDate::from_ymd(2007, 12, 31),
        key1: [73, 74, 128, 79, 106],
        key2: [73, 74, 128, 79, 106],
    };
    let cps2cp = permit::CellPermit {
        cell: String::from("GB100004"),
        date: chrono::NaiveDate::from_ymd(2007, 12, 31),
        key1: [89, 44, 236, 217, 52],
        key2: [89, 44, 236, 217, 52],
    };
    assert_eq!(
        cps[0],
        permit::PermitRecord {
            cell_permit: cps0cp,
            sli: permit::SericeLevelIndicator::SubscriptionPermit,
            edition: Some(1),
            data_server_id: String::from("GB"),
            comment: String::from("hej"),
        }
    );
    assert_eq!(
        cps[1],
        permit::PermitRecord {
            cell_permit: cps1cp,
            sli: permit::SericeLevelIndicator::SinglePurchasePermit,
            edition: Some(0),
            data_server_id: String::from("GB"),
            comment: String::from(""),
        }
    );
    assert_eq!(
        cps[2],
        permit::PermitRecord {
            cell_permit: cps2cp,
            sli: permit::SericeLevelIndicator::SubscriptionPermit,
            edition: None,
            data_server_id: String::from("GB"),
            comment: String::from(""),
        }
    );

    Ok(())
}
