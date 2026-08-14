mod banner;
mod help;
mod hashcat;
use std::io::{self, Write};

fn main() {
     banner::print_banner();


     loop 
     {

        if ! hashcat::check_hashcat() {
            println!("Error: Hashcat is not installed or not found in PATH.");
            break;
        }

        print!("pass-cracker> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() { continue; }

        let args: Vec<&str> = trimmed.split_whitespace().collect();

        match args[0] {
            "-h" => help::print_help(),
            "-q" => break,
            "-f" => {
                    // Handle the -f option here
                    // expecting a file path after -f like -f /path/to/file.xlsx 
                    }
            _ => println!("Unknown command. Use -h for help."),
        } //end of match


     } //end of loop    

}
