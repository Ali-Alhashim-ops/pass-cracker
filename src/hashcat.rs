use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub fn check_hashcat() -> bool {
    let output = std::process::Command::new("hashcat")
        .arg("--version")
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

// ──────────────────────────────────────────────────────────────
//  Attack dispatcher: shows the menu, then runs the chosen attack
// ──────────────────────────────────────────────────────────────

pub fn run_attack(hash: &str, mode: &str) {
    loop {
        println!("\n=== Choose an attack ===");
        println!("  1- Start the attack with brute-force only numbers");
        println!("  2- Start the attack with a password list (txt file)");
        println!("  3- Start the attack with a custom character set");
        println!("  4- All possible combinations (full brute-force)");
        println!("  q- Back to main menu");

        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return;
        }

        match input.trim() {
            "1" => brute_force_numbers(hash, mode),
            "2" => dictionary_attack(hash, mode),
            "3" => charset_attack(hash, mode),
            "4" => all_combinations_attack(hash, mode),
            "q" | "Q" | "b" => return,
            "" => continue,
            _ => println!("Unknown option. Please enter 1, 2, 3, 4 or q."),
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Attack implementations
// ──────────────────────────────────────────────────────────────

fn brute_force_numbers(hash: &str, mode: &str) {
    println!("\n[+] Starting attack: brute-force with NUMBERS only");
    let max_len = ask_max_length(8);
    let mask = repeat_placeholder('d', max_len);
    let args = vec![
        "-a", "3", "--increment", "--increment-min", "1",
        mask.as_str(),
    ];
    run_hashcat(hash, mode, &args);
}

fn dictionary_attack(hash: &str, mode: &str) {
    println!("\n[+] Starting attack: password list (dictionary)");
    print!("  Enter path to the wordlist txt file: ");
    io::stdout().flush().unwrap();

    let mut path = String::new();
    if io::stdin().read_line(&mut path).is_err() {
        return;
    }
    let path = path.trim().to_string();

    if path.is_empty() || !Path::new(&path).exists() {
        println!("  [x] Error: wordlist file not found: {}", path);
        return;
    }

    let args = vec!["-a", "0", path.as_str()];
    run_hashcat(hash, mode, &args);
}

fn charset_attack(hash: &str, mode: &str) {
    println!("\n[+] Starting attack: custom character set (brute-force)");
    print!("  Enter the characters to use (e.g. abcXYZ0123?@#): ");
    io::stdout().flush().unwrap();

    let mut charset = String::new();
    if io::stdin().read_line(&mut charset).is_err() {
        return;
    }
    let charset = charset.trim().to_string();

    if charset.is_empty() {
        println!("  [x] Error: empty character set.");
        return;
    }

    let max_len = ask_max_length(8);
    let mask = repeat_placeholder('1', max_len);
    let args = vec![
        "-a", "3", "--increment", "--increment-min", "1",
        "-1", charset.as_str(),
        mask.as_str(),
    ];
    run_hashcat(hash, mode, &args);
}

fn all_combinations_attack(hash: &str, mode: &str) {
    println!("\n[+] Starting attack: ALL possible combinations (full brute-force)");
    let max_len = ask_max_length(8);
    let mask = repeat_placeholder('a', max_len);
    let args = vec![
        "-a", "3", "--increment", "--increment-min", "1",
        mask.as_str(),
    ];
    run_hashcat(hash, mode, &args);
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

fn ask_max_length(default: usize) -> usize {
    print!("  Password max length (default {}): ", default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return default;
    }
    input.trim().parse::<usize>().unwrap_or(default).clamp(1, 32)
}

/// Build a hashcat mask made of the same placeholder repeated `len` times,
/// e.g. ('d', 4) -> "?d?d?d?d", ('a', 4) -> "?a?a?a?a", ('1', 4) -> "?1?1?1?1".
fn repeat_placeholder(placeholder: char, len: usize) -> String {
    std::iter::repeat(format!("?{}", placeholder))
        .take(len)
        .collect()
}

/// Run hashcat with the given extra arguments. The hash is written to a
/// temporary hash file that hashcat reads. Returns true if the password was
/// cracked.
fn run_hashcat(hash: &str, mode: &str, args: &[&str]) -> bool {
    let outfile = format!("/tmp/pass-cracker-result-{}.txt", std::process::id());
    let hashfile = format!("/tmp/pass-cracker-hash-{}.txt", std::process::id());
    let _ = std::fs::remove_file(&outfile);
    let _ = std::fs::remove_file(&hashfile);

    if let Err(e) = std::fs::write(&hashfile, format!("{}\n", hash)) {
        println!("[x] Failed to write hash file: {}", e);
        return false;
    }

    println!("[+] Running hashcat... (live progress shown below, this may take a while)");
    let start = std::time::Instant::now();

    let mut cmd = Command::new("hashcat");
    cmd.arg("-m")
        .arg(mode)
        .arg(&hashfile)
        .args(args)
        .arg("--potfile-disable")
        .arg("--status")
        .arg("--status-timer")
        .arg("2")
        .arg("--outfile")
        .arg(&outfile)
        .arg("--outfile-format")
        .arg("2") // plain text only
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            println!("[x] Failed to start hashcat: {}", e);
            return false;
        }
    };

    let status = child.wait();

    let found = match std::fs::read_to_string(&outfile) {
        Ok(content) => {
            let content = content.trim();
            if !content.is_empty() {
                println!("\n✅ PASSWORD FOUND: {}  (time: {})", content, fmt_elapsed(start));
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };

    if !found {
        let code = status.map(|s| s.code()).unwrap_or(None);
        match code {
            Some(c) => println!(
                "\n[x] Attack finished — password not found (hashcat exit: {}, time: {}).",
                c,
                fmt_elapsed(start)
            ),
            None => println!(
                "\n[x] Attack interrupted — password not found (time: {}).",
                fmt_elapsed(start)
            ),
        }
    }

    let _ = std::fs::remove_file(&outfile);
    let _ = std::fs::remove_file(&hashfile);
    found
}

fn fmt_elapsed(start: std::time::Instant) -> String {
    let secs = start.elapsed().as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}
