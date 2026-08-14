
pub fn check_hashcat() -> bool {
    let output = std::process::Command::new("hashcat")
        .arg("--version")
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}