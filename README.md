Build and run:

```
$ cargo run --release -- --salt=salt@example.com scrypt
My passphrase to be scrypted<Enter>
Salt: "salt@example.com"
Normalized passphrase: "My passphrase to be scrypted"
Scrypt: d85c221e9669d01844bd1e709fc0d0
BIP39: success three marble coast other absorb bachelor kick train agent usual path
base64: 2FwiHpZp0AGES9HnAJ/A0A==
```

Usage:
```
Read passphrase (first line from stdin), normalize it (drop extra whitespace) and pass it to KDF

USAGE:
    kdftool [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --salt <salt>    Set salt [default: ]

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    scrypt    Scrypt KDF result in hex, base64, and used as entropy for BIP39 seed
    warp      WarpWallet (https://keybase.io/warp/) Bitcoin private key and address
```