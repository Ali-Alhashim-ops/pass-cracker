mod banner;
mod help;
mod hashcat;
mod file_type;
mod encryption_extractor;
mod pdf;
mod zip;
mod rar;
use std::io::{self, Write};

/*
test 
-f /home/ali/Downloads/libere.xlsx
-f /home/ali/Downloads/office2013.xlsx
-f /home/ali/Downloads/sample.pdf.zip
-f /tmp/opencode/samples/pdf_aes256.pdf
-f /tmp/opencode/samples/pdf_rc4_40.pdf
-f /tmp/opencode/samples/pdf_rc4_128.pdf
-f /tmp/opencode/samples/pdf_aes128.pdf
 */

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
        if input.is_empty() {
            break; // EOF
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
                        // ok file path is provided we need to File Identification & Parsing
                        // Identification we will pass the file to fn that only identify the file type and return the file type as a string
                        if args.len() < 2 {
                            println!("Error: No file path provided. Usage: -f <file_path>");
                            continue;   
                        }

                        // ok file path is arg[1] we will pass it to the file_type module to identify the file type
                        let file_type = file_type::file_type(args[1]);

                        match file_type {
                            Some(ft) => {
                                println!("File Type: {}", ft);

                                let result = match ft.as_str() {
                                    "Excel 2007 to 2016+" =>
                                        encryption_extractor::excel_2007_to_2016(args[1]),
                                    "Word 2007 to 2016+" =>
                                        encryption_extractor::excel_2007_to_2016(args[1]),
                                    "Excel 2003 and older" =>
                                        encryption_extractor::excel_legacy_9700(args[1], "Excel 2003 and older"),
                                    "Word 2003 and older" =>
                                        encryption_extractor::excel_legacy_9700(args[1], "Word 2003 and older"),
                                    "PDF" =>
                                        pdf::pdf_encryption(args[1]),
                                    "ZIP" =>
                                        zip::zip_encryption(args[1]),
                                    "RAR" =>
                                        rar::rar_encryption(args[1]),
                                    other => {
                                        println!("Error: Unsupported file type '{}'.", other);
                                        None
                                    }
                                };

                                if let Some((hash, hashcat_mode)) = result {
                                    hashcat::run_attack(&hash, &hashcat_mode);
                                }
                            },
                            None => println!("Error: Could not determine the file type."),
                        }
                    }
            _ => println!("Unknown command. Use -h for help."),
        } //end of match


     } //end of loop    

}
