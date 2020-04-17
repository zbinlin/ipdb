extern crate ipdb;

use ipdb::{Ipdb, Language, Fields};
use std::fs::File;

fn create_reader() -> File {
    File::open("./tests/fixtures/test.ipdb").unwrap()
}

#[test]
fn test_new() {
    let mut file = create_reader();
    Ipdb::new(&mut file);
}

#[test]
fn test_find() {
    let mut file = create_reader();
    let db = Ipdb::new(&mut file);
    assert!(db.find("127.0.0.1", Language::CN).is_none());
    let result = db.find("114.114.114.114", Language::CN);
    assert!(result.is_some());
    assert_eq!(result.unwrap().get(&Fields::region_name).unwrap(), "114DNS.COM");
}

#[test]
fn test_reverse() {
    let mut file = create_reader();
    let db = Ipdb::new(&mut file);
    let result = db.reverse(Language::CN);
    for ((start, end), info) in &result {
        eprintln!("{},{},{},{},{}",
            start, end,
            info.get(&Fields::country_name).unwrap(),
            info.get(&Fields::region_name).unwrap(),
            info.get(&Fields::city_name).unwrap(),
        );
    }
    assert_ne!(result.len(), 0);
}
