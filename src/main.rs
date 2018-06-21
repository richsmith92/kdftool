extern crate base64;
extern crate crypto;
extern crate regex;
#[macro_use]
extern crate clap;
extern crate bip39;
extern crate secp256k1;
extern crate bitcoin;

use bitcoin::util::base58;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;

use secp256k1::{SecretKey, PublicKey};
use crypto::scrypt;
use crypto::pbkdf2;
use crypto::hmac;
use crypto::sha2;

// use crypto::scrypt::ScryptParams;
use std::io;
// use std::io::Read;
use regex::Regex;
use clap::{Arg, App, ArgMatches, SubCommand};
use bip39::{Mnemonic, MnemonicType, Language};

fn arg_matches<'a>() -> ArgMatches<'a> {
    App::new("kdftool")
        .arg(Arg::with_name("salt").long("salt").takes_value(true).default_value("")
            .help("Set salt"))
        .subcommand(SubCommand::with_name("warp")
        )
        .subcommand(SubCommand::with_name("scrypt")
            .arg(Arg::with_name("logN").long("logn").takes_value(true).default_value("19")
                .help("log₂N (CPU/memory cost) param for scrypt"))
            .arg(Arg::with_name("r").short("r").takes_value(true).default_value("8")
                .help("r (blocksize) param for scrypt"))
            .arg(Arg::with_name("p").short("p").takes_value(true).default_value("1")
                .help("p (parallelization) param for scrypt"))
            .arg(Arg::with_name("len").long("len").takes_value(true).default_value("16")
                .help("Derived key length in bytes"))
        )
        .get_matches()
}

fn subcommand_dispatch(app_m: ArgMatches) {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read passphrase");
    let pass = process_passphrase(&input);
    let salt = app_m.value_of("salt").unwrap().to_string();
    println!("Salt: \"{}\"", &salt);
    println!("Normalized password: \"{}\"", pass);

    match app_m.subcommand() {
        ("warp", Some(_sub_m)) => run_warp(&pass, &salt),
        ("scrypt", Some(sub_m)) => run_scrypt(sub_m, &pass, &salt),
        _ => println!("Please choose subcommand"),
    }
}

fn main() {
    subcommand_dispatch(arg_matches());
}

fn warp(pass: &str, salt: &str) -> Vec<u8> {
    let mut s1 = vec![0; 32];
    let scrypt_params = scrypt::ScryptParams::new(18, 8, 1);
    fn add_byte(s: &str, byte: u8) -> Vec<u8> {
        let mut bytes = s.as_bytes().to_owned();
        bytes.push(byte);
        bytes
    }
    scrypt::scrypt(&add_byte(pass, 0x01), &add_byte(salt, 0x01), &scrypt_params, &mut s1);
    let mut s2 = vec![0; 32];
    let mut mac = hmac::Hmac::new(sha2::Sha256::new(), &add_byte(pass, 0x02));
    let _2 : u32 = 2;
    pbkdf2::pbkdf2(&mut mac, &add_byte(salt, 0x02), _2.pow(16), &mut s2);
    // let mut dk2 = vec![0; 32];
    for i in 0..32 {
        s1[i] ^= s2[i]
    }
    s1
}

fn run_warp(pass: &str, salt: &str) {
    let secp256k1 = secp256k1::Secp256k1::new();
    let prv_key = warp(pass, salt);
    let pub_key = PublicKey::from_secret_key(&secp256k1,
        &SecretKey::from_slice(&secp256k1, &prv_key).unwrap()).unwrap();
    // print_hex("Warp:   ", &prv_key);
    let mut wif : Vec<u8> = vec![0x80];
    wif.extend(&prv_key);
    // let mut addr = vec![0x00];
    // addr.extend(&pub_key[..]);
    println!("Warp WIF:       {}", &base58::check_encode_slice(&wif));
    println!("Warp address:   {}", Address::p2upkh(&pub_key, Network::Bitcoin).to_string());
}

struct Params {
    log_n : u8,
    r : u32,
    p : u32,
    dk_len : usize,
}

impl Params {
    fn from_matches(matches : &ArgMatches) -> Params {
        let log_n = value_t!(matches, "logN", u8).unwrap_or_else(|e| e.exit());
        let r = value_t!(matches, "r", u32).unwrap_or_else(|e| e.exit());
        let p = value_t!(matches, "p", u32).unwrap_or_else(|e| e.exit());
        let dk_len = value_t!(matches, "len", usize).unwrap_or_else(|e| e.exit());
        Params { log_n : log_n, r : r, p : p, dk_len: dk_len }
    }
}

fn derive_key(params : Params, pass : &str, salt: &str) -> Vec<u8> {
    let mut dk = vec![0; params.dk_len];
    let scrypt_params = scrypt::ScryptParams::new(params.log_n, params.r, params.p);
    scrypt::scrypt(pass.as_bytes(), salt.as_bytes(), &scrypt_params, &mut dk);
    dk
}

fn run_scrypt(sub_m: &ArgMatches, pass: &str, salt: &str) {
    let params = Params::from_matches(sub_m);
    let dk = derive_key(params, pass, salt);
    print_hex("Scrypt: ", &dk);
    let mnemonic_type = MnemonicType::for_key_size(dk.len() * 8).unwrap();
    let mnemonic = Mnemonic::from_entropy(&dk, mnemonic_type, Language::English, "").unwrap();
    // println!("{:?}", &dk);
    println!("BIP39: {}", mnemonic.get_string());
    println!("base64: {}", base64::encode(&dk));
}

// Utils

fn process_passphrase(input : &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    let pass = re.replace_all(input, " ").trim().to_owned();
    pass
}

fn print_hex(prefix: &str, bytes: &[u8]) {
    print!("{}", prefix);
    for b in bytes.iter() {
        print!("{:x}", b);
    }
    println!("");
}
