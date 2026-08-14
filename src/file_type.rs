pub fn file_type(file_path: &str) -> Option<String> {
    let path = std::path::Path::new(file_path);
    if !path.exists() {
        print!("Error: File does not exist: {}", file_path);
        return None;
    }

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("xls")  => Some("Excel 2003 and older".to_string()),
        Some("xlsx") => Some("Excel 2007 to 2016+".to_string()),
        _ => None,
    }
}