//! Differential-test helper (test tool only). Reads one hex datagram per line on stdin and prints
//! one line each: `pass ID:LEN,...` or `drop WHY`. Used by tests/interop/mavguard_diff.py, which
//! compares the answers with pymavlink's.
//!
//! `--wide` widens the guard to every message and command the CRC table knows, FTP, RTK and fence and rally, so
//! the comparison covers all of them. Parameter writes stay off.
//!
//! Usage: cargo run --example mavguard_check [-- --wide]

use oasa_sec::mavguard::{Guard, frames};
use std::io::BufRead;

fn main() {
    let mut g = Guard::new();
    if std::env::args().any(|a| a == "--wide") {
        g = g.allow_ftp().allow_rtk().allow_fence_rally();
        for id in 0..=u32::from(u16::MAX) {
            if let Ok(w) = g.clone().allow_msg(id) {
                g = w;
            }
            if let Ok(w) = g.clone().allow_command(id) {
                g = w;
            }
        }
    }
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let hex = line.trim();
        let d: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect();
        match g.check(&d) {
            Ok(()) => {
                let f = frames(&d).expect("a passed datagram has frames");
                let f: Vec<String> = f.iter().map(|(i, n)| format!("{i}:{n}")).collect();
                println!("pass {}", f.join(","));
            }
            Err(b) => println!("drop {}", b.why.as_str()),
        }
    }
}
