extern crate kpdb;
extern crate rpassword;
extern crate clipboard;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate termios;
extern crate qptrie;
extern crate ansi_term;

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
use ansi_term::Colour::{Red, Green};

const USAGE: &'static str = "
Rust Keypass CLI

Usage:
  kpsh <kdbx-file-path>
  kpsh (-h | --help)
  kpsh --version

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
            println!("{}",
                     Green
                         .bold()
                         .paint(format!("Password for {} copied onto clipboard\n",
                                        account_name)));
        } else {
            println!("{}",
                     Red.bold()
                         .paint(format!("Password for {} not found\n", account_name)));
        }
    }
}

fn into_trie(values: Values<EntryUuid, Entry>) -> Trie<String, String> {
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
    let mut new_termios = termios.clone(); // make a mutable copy of termios
    // that we will modify
    new_termios.c_lflag &= !(ICANON | ECHO); // no echo and canonical mode
    tcsetattr(stdin, TCSANOW, &mut new_termios).unwrap();
    let stdout = io::stdout();
    let mut reader = io::stdin();
    let mut buffer = [0; 1]; // read exactly one byte
    let mut account = String::new();
    println!("Get password for which account?");
    loop {
        stdout.lock().flush().unwrap();
        reader.read_exact(&mut buffer).unwrap();
        match char::from_u32(buffer[0] as u32) {
            Some('\n') => {
                println!();
                return account;
            }
            Some('\u{7f}') => {
                account.pop();
            }
            Some('\t') => account = typeahead(&t, &account),
            Some(c) => {
                account.push(c);
            }
            None => (),
        }
        print!("{} \r{}", '\u{8}', account);
    }
    // tcsetattr(stdin, TCSANOW, & termios).unwrap();  // reset the stdin to
    // original termios data
}

fn typeahead(t: &Trie<String, String>, prefix: &str) -> String {
    let m = matching_accounts(t, prefix);
    let lcp = longest_common_prefix(&m);
    if lcp == prefix {
        show_vector(&m);
    }
    lcp
}

fn longest_common_prefix(v: &Vec<String>) -> String {
    v.iter()
        .fold(v[0].to_owned(), |acc, s| lcp_util(acc, s.to_owned()))
}

fn lcp_util(s1: String, s2: String) -> String {
    let mut c1 = s1.chars();
    let mut c2 = s2.chars();
    let mut i = 0;
    while let (Some(a), Some(b)) = (c1.next(), c2.next()) {
        if a == b {
            i += 1;
        } else {
            break;
        }
    }
    (&s1)[..i].to_string()
}


fn matching_accounts(t: &Trie<String, String>, prefix: &str) -> Vec<String> {
    t.prefix_iter(&prefix.to_string())
        .include_prefix()
        .map(|(k, _)| k.to_owned())
        .collect()
}

fn show_vector(v: &Vec<String>) {
    println!("\n{}",
             v.iter().fold(String::new(), |acc, s| acc + s + "\t"));
}

#[cfg(test)]
mod tests {
    use super::{longest_common_prefix, lcp_util};

    #[test]
    fn lcp_util_returns_the_longest_common_prefix_of_two_strings() {
        let s1 = "foobar".to_string();
        let s2 = "fooqux".to_string();

        assert_eq!("foo", lcp_util(s1, s2));
    }

    #[test]
    fn longest_common_prefix_returns_the_longest_common_prefix_of_a_vector_of_strings() {
        let v = vec!["foo1".to_string(), "foo2".to_string(), "foo3".to_string()];

        assert_eq!("foo", longest_common_prefix(&v));
    }
}
