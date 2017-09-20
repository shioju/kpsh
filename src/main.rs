extern crate kpdb;
extern crate rpassword;
extern crate clipboard;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate termios;
extern crate qptrie;

use kpdb::{CompositeKey, Database, EntryUuid, Entry};
use kpdb::StringValue::{Plain, Protected};
use std::fs::File;
use std::io::{self, Read, Write};
use std::char;
use std::collections::hash_map::Values;
use clipboard::{ClipboardContext, ClipboardProvider};
use docopt::Docopt;
use termios::{Termios, TCSANOW, ECHO, ICANON, tcsetattr};
use qptrie::Trie;


const USAGE: &'static str = "
Rust Keypass CLI

Usage:
  kp <kdbx-file-path>
  kp (-h | --help)
  kp --version

Options:
  -h --help     Show this screen.
  --version     Show version.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_kdbx_file_path: String,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.deserialize())
                            .unwrap_or_else(|e| e.exit());
    println!("{:?}", args);

    let mut file = File::open(args.arg_kdbx_file_path).unwrap();

    let pass = rpassword::prompt_password_stdout("Master Password: ").unwrap();
    let key = CompositeKey::from_password(pass);
    let db = Database::open(&mut file, &key).unwrap();

    let t = into_trie(db.entries.values());

    loop {
        let account_name = get_account_name(&t);
        if let Some(password) = t.get(&account_name) {
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents(password.to_owned()).unwrap();
            println!("Password for {} copied onto clipboard\n", account_name);
        } else {
            println!("Password for {} not found\n", account_name);
        }
    }
}

fn into_trie(values: Values<EntryUuid,Entry>) -> Trie<String, String> {
    let mut t = Trie::new();
    let title_string_key = kpdb::StringKey::Title;
    let password_string_key = kpdb::StringKey::Password;

    for val in values {
        if let Plain(ref title) = val.strings[&title_string_key] {
            if let Protected(ref password) = val.strings[&password_string_key] {
                let password = std::str::from_utf8(password.unsecure()).unwrap();
                t.insert(title.to_string(), password.to_string());
            }
        }
    }
    t
}

fn get_account_name(t: &Trie<String, String>) -> String {
    let stdin = 0; // couldn't get std::os::unix::io::FromRawFd to work
                   // on /dev/stdin or /dev/tty
    let termios = Termios::from_fd(stdin).unwrap();
    let mut new_termios = termios.clone();  // make a mutable copy of termios
                                            // that we will modify
    new_termios.c_lflag &= !(ICANON | ECHO); // no echo and canonical mode
    tcsetattr(stdin, TCSANOW, &mut new_termios).unwrap();
    let stdout = io::stdout();
    let mut reader = io::stdin();
    let mut buffer = [0;1];  // read exactly one byte
    let mut account = String::new();
    println!("Get password for which account?");
    loop {
        stdout.lock().flush().unwrap();
        reader.read_exact(&mut buffer).unwrap();
        match char::from_u32(buffer[0] as u32) {
            Some('\n') => {
              println!();
              return account;
            },
            Some('\u{7f}') => { account.pop(); },
            Some('\t') => { show_matching_accounts(&t, &account) },
            Some(c) => { account.push(c); },
            None => (),
        }
        print!("{} \r{}", '\u{8}', account);
    }
    // tcsetattr(stdin, TCSANOW, & termios).unwrap();  // reset the stdin to
                                                    // original termios data
}

fn show_matching_accounts(t: &Trie<String, String>, prefix: &str) {
    println!();
    for (k, _) in t.prefix_iter(&prefix.to_string()).include_prefix() {
        print!("{}\t", k);
    }
    println!();
}
