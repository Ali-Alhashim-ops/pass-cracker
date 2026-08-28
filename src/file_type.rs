use std::fs;
use std::path::Path;

/// Identifies the file type by magic bytes first, falling back to the
/// file extension. Returns a stable label string used by main.rs.
pub fn file_type(file_path: &str) -> Option<String> {
    let path = Path::new(file_path);
    if !path.exists() {
        println!("Error: File does not exist: {}", file_path);
        return None;
    }

    let data = fs::read(file_path).ok().unwrap_or_default();
    let ext = path.extension().and_then(|e| e.to_str());

    // ── magic-byte detection ──
    if data.starts_with(b"%PDF-") {
        return Some("PDF".to_string());
    }

    if data.starts_with(b"Rar!\x1a\x07\x01\x00") || data.starts_with(b"Rar!\x1a\x07\x00") {
        return Some("RAR".to_string());
    }

    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return Some(classify_zip(&data, ext));
    }

    // OLE2 / CFB compound file (xls, doc, ppt, or an encrypted OOXML container)
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return match ext {
            // Encrypted OOXML packages (.xlsx/.docx/.pptx with a password) are
            // stored as CFB containers holding EncryptionInfo + EncryptedPackage.
            Some("xlsx") => Some("Excel 2007 to 2016+".to_string()),
            Some("docx") => Some("Word 2007 to 2016+".to_string()),
            Some("pptx") => Some("PowerPoint 2007 to 2016+".to_string()),
            Some("xls") => Some("Excel 2003 and older".to_string()),
            Some("doc") => Some("Word 2003 and older".to_string()),
            Some("ppt") => Some("PowerPoint 2003 and older".to_string()),
            _ => Some("OLE (encrypted container)".to_string()),
        };
    }

    if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("7z".to_string());
    }

    // ── extension fallback ──
    match ext {
        Some("xlsx") => Some("Excel 2007 to 2016+".to_string()),
        Some("docx") => Some("Word 2007 to 2016+".to_string()),
        Some("xls") => Some("Excel 2003 and older".to_string()),
        Some("doc") => Some("Word 2003 and older".to_string()),
        Some("pdf") => Some("PDF".to_string()),
        Some("zip") => Some("ZIP".to_string()),
        Some("rar") => Some("RAR".to_string()),
        _ => None,
    }
}

/// A PK-style zip: is it an OOXML document or a plain ZIP archive?
fn classify_zip(data: &[u8], ext: Option<&str>) -> String {
    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);

    // OOXML packages must contain [Content_Types].xml at the package root.
    if ext == Some("docx") || (contains(b"[Content_Types].xml") && contains(b"word/")) {
        return "Word 2007 to 2016+".to_string();
    }
    if ext == Some("xlsx") || (contains(b"[Content_Types].xml") && contains(b"xl/")) {
        return "Excel 2007 to 2016+".to_string();
    }
    if ext == Some("pptx") || (contains(b"[Content_Types].xml") && contains(b"ppt/")) {
        return "PowerPoint 2007 to 2016+".to_string();
    }

    "ZIP".to_string()
}