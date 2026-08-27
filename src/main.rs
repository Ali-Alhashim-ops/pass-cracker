mod banner;
mod help;
mod hashcat;
mod file_type;
mod encryption_extractor;
use std::io::{self, Write};

/*
test 
/home/ali/Downloads/libere.xlsx
/home/ali/Downloads/office2013.xlsx
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
                                // Here you can call the parsing function based on the file type
                                // For example, if ft is "Excel File", you can call a function to parse Excel files
                                // parse_excel(args[1]);
                                if ft == "Excel 2007 to 2016+" {
                                    // call the function to extract encryption information for Excel 2007 to 2016+ files
                                    encryption_extractor::excel_2007_to_2016(args[1]);
                                }
                            },
                            None => println!("Error: Could not determine the file type."),
                        }
                    }
            _ => println!("Unknown command. Use -h for help."),
        } //end of match


     } //end of loop    

}
