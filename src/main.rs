extern crate crypto;

use crypto::scrypt;

fn main() {
    let scrypt_params = scrypt::ScryptParams::new(19, 8, 1);
    let orig_pass = b"";
    let salt = b"";
    let mut out = [0; 16];
    scrypt::scrypt(orig_pass, salt, &scrypt_params, &mut out);
    // let s = &"asteaset"[..];
    for c in out.iter() {
        print!("{:x}", c);
    }
    println!("");
}
