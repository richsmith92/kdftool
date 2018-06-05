
extern crate crypto;
extern crate regex;
#[macro_use]
extern crate clap;

use crypto::scrypt;
use std::io;
use std::io::Read;
use regex::Regex;
use clap::{Arg, App};

fn main() {
    let matches = App::new("scryptseed")
        .arg(Arg::with_name("salt").long("salt").takes_value(true).default_value("")
            .help("Set salt"))
        .arg(Arg::with_name("logN").long("logn").takes_value(true).default_value("19")
            .help("log₂N (CPU/memory cost) param for scrypt"))
        .arg(Arg::with_name("r").short("r").takes_value(true).default_value("8")
            .help("r (blocksize) param for scrypt"))
        .arg(Arg::with_name("p").short("p").takes_value(true).default_value("1")
            .help("p (parallelization) param for scrypt"))
        .arg(Arg::with_name("len").long("len").takes_value(true).default_value("16")
            .help("Derived key length in bytes"))
        .get_matches();
    let log_n = value_t!(matches, "logN", u8).unwrap_or_else(|e| e.exit());
    let r = value_t!(matches, "r", u32).unwrap_or_else(|e| e.exit());
    let p = value_t!(matches, "p", u32).unwrap_or_else(|e| e.exit());
    let dk_len = value_t!(matches, "len", usize).unwrap_or_else(|e| e.exit());
    let salt = matches.value_of("salt").unwrap();

    let scrypt_params = scrypt::ScryptParams::new(log_n, r, p);
    let mut out = vec![0; dk_len];
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("Failed to read passphrase");
    let re = Regex::new(r"\s+").unwrap();
    let input1 = re.replace_all(&input, " ");
    let processed = input1.trim();
    println!("|{}|", processed);

    scrypt::scrypt(processed.as_bytes(), salt.as_bytes(), &scrypt_params, &mut out);

    // let s = &"asteaset"[..];
    for c in out.iter() {
        print!("{:x}", c);
    }
    println!("");
}
