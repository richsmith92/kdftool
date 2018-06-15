extern crate base64;
extern crate crypto;
extern crate regex;
#[macro_use]
extern crate clap;
extern crate bip39;

use crypto::scrypt;
// use crypto::scrypt::ScryptParams;
use std::io;
// use std::io::Read;
use regex::Regex;
use clap::{Arg, App, ArgMatches};
use bip39::{Mnemonic, MnemonicType, Language};

fn arg_matches<'a>() -> ArgMatches<'a> {
    App::new("scryptseed")
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
        .get_matches()
}

struct Params {
    log_n : u8,
    r : u32,
    p : u32,
    dk_len : usize,
    salt : String,
}

impl Params {
    fn from_matches(matches : ArgMatches) -> Params {
        let log_n = value_t!(matches, "logN", u8).unwrap_or_else(|e| e.exit());
        let r = value_t!(matches, "r", u32).unwrap_or_else(|e| e.exit());
        let p = value_t!(matches, "p", u32).unwrap_or_else(|e| e.exit());
        let dk_len = value_t!(matches, "len", usize).unwrap_or_else(|e| e.exit());
        let salt = matches.value_of("salt").unwrap().to_string();
        Params { log_n : log_n, r : r, p : p, dk_len: dk_len, salt: salt }
    }
}

fn derive_key(params : Params, pass : &str) -> Vec<u8> {
    let mut dk = vec![0; params.dk_len];
    let scrypt_params = scrypt::ScryptParams::new(params.log_n, params.r, params.p);
    scrypt::scrypt(pass.as_bytes(), params.salt.as_bytes(), &scrypt_params, &mut dk);
    dk
}

fn process_passphrase(input : &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    let processed = re.replace_all(input, " ").trim().to_owned();
    processed
}

fn print_hex(bytes: &[u8]) {
    print!("Derived key: ");
    for b in bytes.iter() {
        print!("{:x}", b);
    }
    println!("");
}

fn main() {
    let params = Params::from_matches(arg_matches());
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read passphrase");
    let processed = process_passphrase(&input);
    println!("Normalized phrase: \"{}\"", processed);
    let dk = derive_key(params, &processed);
    print_hex(&dk);
    let mnemonic_type = MnemonicType::for_key_size(dk.len() * 8).unwrap();
    let mnemonic = Mnemonic::from_entropy(&dk, mnemonic_type, Language::English, "").unwrap();
    // println!("{:?}", &dk);
    println!("BIP39: {}", mnemonic.get_string());
    println!("base64: {}", base64::encode(&dk));
}
