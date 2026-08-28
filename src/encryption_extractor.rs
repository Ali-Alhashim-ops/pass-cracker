use std::path::Path;
use std::io::Read;

/// Returns the hashcat hash and its hashcat mode, or None on failure.
pub fn excel_2007_to_2016(file_path: &str) -> Option<(String, String)> {
    println!("File Type: Excel 2007 to 2016+ (Encrypted OLE Container)");

    let path = Path::new(file_path);
    if !path.exists() {
        println!("Error: File does not exist: {}", file_path);
        return None;
    }

    match cfb::open(path) {
        Ok(mut comp) => {
            if comp.exists("/EncryptionInfo") {
                match comp.open_stream("/EncryptionInfo") {
                    Ok(mut stream) => {
                        let mut encryption_info_data = Vec::new();
                        match stream.read_to_end(&mut encryption_info_data) {
                            Ok(size) => {
                                println!(
                                    "Success: Found 'EncryptionInfo' stream! Read {} bytes.",
                                    size
                                );
                                parse_encryption_info(&encryption_info_data)
                            }
                            Err(e) => {
                                println!("Error reading EncryptionInfo stream: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error opening EncryptionInfo stream: {}", e);
                        None
                    }
                }
            } else {
                println!("Status: The OLE container does not contain an 'EncryptionInfo' stream.");
                None
            }
        }
        Err(e) => {
            println!("Error: Failed to open file as an OLE/CFB container: {}", e);
            None
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Top-level dispatcher
// ──────────────────────────────────────────────────────────────

/// Legacy binary (pre-2007) Office files — .doc / .xls.
/// Uses RC4 (1.1) or RC4 CryptoAPI (v2/v3/v4) and maps to hashcat mode 9700.
///
/// The RC4 CryptoAPI parameters are *not* stored in an "EncryptionInfo"
/// stream for these formats. Instead:
///   - .doc: the FibBase in the "wordDocument" stream says which table
///           stream ("0Table"/"1Table") begins with the encryption block.
///   - .xls: the "Workbook" stream contains a BIFF "FilePass" record whose
///           payload starts with the encryption block.
pub fn excel_legacy_9700(file_path: &str, label: &str) -> Option<(String, String)> {
    println!("File Type: {} (Encrypted OLE Container)", label);

    let path = Path::new(file_path);
    if !path.exists() {
        println!("Error: File does not exist: {}", file_path);
        return None;
    }

    let mut comp = match cfb::open(path) {
        Ok(c) => c,
        Err(e) => {
            println!("Error: Failed to open file as an OLE/CFB container: {}", e);
            return None;
        }
    };

    // 1) Some containers (rare for .doc/.xls) really do use "EncryptionInfo".
    if comp.exists("/EncryptionInfo") {
        match read_stream(&mut comp, "/EncryptionInfo") {
            Some(data) => {
                println!("Found 'EncryptionInfo' stream ({} bytes).", data.len());
                return parse_legacy_encryption_info(&data);
            }
            None => return None,
        }
    }

    // 2) .doc: locate the table stream via the FibBase inside "wordDocument".
    if comp.exists("/wordDocument") {
        let wd = match read_stream(&mut comp, "/wordDocument") {
            Some(d) => d,
            None => return None,
        };
        if wd.len() < 12 {
            println!("Error: wordDocument stream too small to hold a FibBase.");
            return None;
        }
        let flags = u16::from_le_bytes([wd[10], wd[11]]);
        let encrypted = (flags >> 8) & 1;
        let which_tbl = (flags >> 9) & 1;
        if encrypted == 0 {
            println!("Status: The document is not flagged as encrypted (fEncrypted=0).");
            println!("        XOR-obfuscated files store encryption here and cannot be cracked.");
            return None;
        }
        let table = if which_tbl == 1 { "/1Table" } else { "/0Table" };
        if !comp.exists(table) {
            println!("Error: Table stream '{}' not found.", table);
            return None;
        }
        let data = read_stream(&mut comp, table)?;
        println!("Legacy encryption block found in '{}' stream ({} bytes).", table, data.len());
        return parse_legacy_encryption_info(&data);
    }

    // 3) .xls: scan the "Workbook" stream for the FilePass record.
    if comp.exists("/Workbook") {
        let wb = match read_stream(&mut comp, "/Workbook") {
            Some(d) => d,
            None => return None,
        };
        // BIFF records: [type u16][size u16][payload size bytes]. FilePass = 0x002F.
        let mut pos = 0usize;
        let mut payload: Option<Vec<u8>> = None;
        while pos + 4 <= wb.len() {
            let rec_type = u16::from_le_bytes([wb[pos], wb[pos + 1]]);
            let rec_size = u16::from_le_bytes([wb[pos + 2], wb[pos + 3]]) as usize;
            if rec_size > wb.len() - pos - 4 {
                break;
            }
            let body = &wb[pos + 4..pos + 4 + rec_size];
            if rec_type == 0x002F {
                payload = Some(body.to_vec());
                break;
            }
            pos += 4 + rec_size;
        }
        return match payload {
            Some(mut body) => {
                println!("Found FilePass record ({} bytes).", body.len());
                let w_encryption_type = u16::from_le_bytes([body[0], body[1]]);
                body.drain(..2); // remove wEncryptionType, keep version...
                match w_encryption_type {
                    0x0001 => parse_legacy_encryption_info(&body),
                    0x0000 => {
                        println!("Status: XOR obfuscation — hashcat cannot crack this.");
                        None
                    }
                    other => {
                        println!("Error: Unknown encryption type 0x{:04x} in FilePass.", other);
                        None
                    }
                }
            }
            None => {
                println!("Status: No FilePass record found — the workbook is not encrypted.");
                None
            }
        };
    }

    // 4) Fall back to an EncryptionInfo stream if still nothing matched.
    println!("Status: No encryption parameters found in this OLE container.");
    None
}

fn read_stream(comp: &mut cfb::CompoundFile<std::fs::File>, name: &str) -> Option<Vec<u8>> {
    match comp.open_stream(name) {
        Ok(mut stream) => {
            let mut data = Vec::new();
            match stream.read_to_end(&mut data) {
                Ok(_) => Some(data),
                Err(e) => {
                    println!("Error reading stream {}: {}", name, e);
                    None
                }
            }
        }
        Err(e) => {
            println!("Error opening stream {}: {}", name, e);
            None
        }
    }
}

fn parse_legacy_encryption_info(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 4 {
        eprintln!("Error: Encryption data too short ({} bytes).", data.len());
        return None;
    }

    let v_major = u16::from_le_bytes([data[0], data[1]]);
    let v_minor = u16::from_le_bytes([data[2], data[3]]);
    println!("Encryption Version: vMajor={}, vMinor={}", v_major, v_minor);

    match v_major {
        1 => {
            if v_minor == 1 {
                // Plain RC4 (MS-OFFCRYPTO RC4): salt + verifier + verifierHash, no header.
                const RC4_INFO_LEN: usize = 16 + 16 + 16;
                if data.len() < 4 + RC4_INFO_LEN {
                    println!("Error: RC4 encryption block too short ({} bytes).", data.len());
                    return None;
                }
                let salt = &data[4..20];
                let ev = &data[20..36];
                let evh = &data[36..52];
                println!("\n  RC4 (v1.1) params:");
                println!("    salt:                    {}", to_hex(salt));
                println!("    encryptedVerifier:       {}", to_hex(ev));
                println!("    encryptedVerifierHash:    {}", to_hex(evh));

                let hash = format!(
                    "$oldoffice$0*{}*{}*{}",
                    to_hex(salt),
                    to_hex(ev),
                    to_hex(evh)
                );
                println!("\n  hashcat hash:");
                println!("  {}", hash);
                println!("  hashcat mode: 9700");
                return Some((hash, "9700".to_string()));
            }
            println!("Error: Unsupported legacy version v{}.{}.", v_major, v_minor);
            None
        }
        2 | 3 | 4 => {
            if v_minor != 2 {
                println!("Error: Unsupported minor version v{}.{}.", v_major, v_minor);
                return None;
            }
            if v_major == 4 {
                println!("Note: v4 legacy RC4 CryptoAPI — mapping to mode 9700.");
            }
            parse_standard_encryption(&data[4..], v_major, true)
        }
        _ => {
            println!("Error: Unsupported legacy version v{}.", v_major);
            None
        }
    }
}

fn parse_encryption_info(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 4 {
        eprintln!("Error: EncryptionInfo stream too short ({} bytes).", data.len());
        return None;
    }

    // Version header: [vMajor (u16 LE), vMinor (u16 LE)]
    let v_major = u16::from_le_bytes([data[0], data[1]]);
    let v_minor = u16::from_le_bytes([data[2], data[3]]);
    println!("Encryption Version: vMajor={}, vMinor={}", v_major, v_minor);

    match v_major {
        4 => Some(parse_agile_encryption(&data[4..])),
        2 | 3 => parse_standard_encryption(&data[4..], v_major, false),
        _ => {
            println!("Unsupported encryption version: vMajor={}", v_major);
            None
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Agile Encryption (Office 2010 / 2013 / 2016)
//  After the 4-byte version, the rest is XML.
// ──────────────────────────────────────────────────────────────

fn parse_agile_encryption(data: &[u8]) -> (String, String) {
    // Auto-detect XML start (some files have 4 reserved bytes before XML)
    let xml_start = if data.starts_with(b"<?xml") || data.starts_with(b"<encryption") {
        0
    } else if data.len() > 4 && (data[4..].starts_with(b"<?xml") || data[4..].starts_with(b"<encryption"))
    {
        4
    } else {
        0
    };

    // Trim trailing null bytes
    let xml_bytes = &data[xml_start..];
    let xml_end = xml_bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|p| p + 1)
        .unwrap_or(xml_bytes.len());

    let xml_str = match std::str::from_utf8(&xml_bytes[..xml_end]) {
        Ok(s) => s,
        Err(e) => {
            println!("Error: Failed to parse XML from EncryptionInfo stream: {}", e);
            return (String::new(), String::new());
        }
    };

    println!("\n=== Agile Encryption (Office 2010+) ===");

    // The password-specific parameters all live on the <p:encryptedKey>
    // element. saltValue also appears on <keyData>, so restrict the search
    // to the <p:encryptedKey> opening tag (self-closing in practice).
    let enc_key = match xml_str.find("<p:encryptedKey") {
        Some(start) => {
            match xml_str[start..].find('>') {
                Some(end) => &xml_str[start..start + end + 1],
                None => xml_str,
            }
        }
        None => xml_str,
    };

    // Extract attributes from <p:encryptedKey> element
    let spin_count = xml_attr(enc_key, "spinCount");
    let key_bits = xml_attr(enc_key, "keyBits");
    let salt_size = xml_attr(enc_key, "saltSize");
    let block_size = xml_attr(enc_key, "blockSize");
    let hash_size = xml_attr(enc_key, "hashSize");
    let cipher_algorithm = xml_attr(enc_key, "cipherAlgorithm");
    let cipher_chaining = xml_attr(enc_key, "cipherChaining");
    let hash_algorithm = xml_attr(enc_key, "hashAlgorithm");
    let salt_value_b64 = xml_attr(enc_key, "saltValue");
    let evhi_b64 = xml_attr(enc_key, "encryptedVerifierHashInput");
    let evhv_b64 = xml_attr(enc_key, "encryptedVerifierHashValue");
    let ekv_b64 = xml_attr(enc_key, "encryptedKeyValue");

    println!("  spinCount:                   {}", spin_count.as_deref().unwrap_or("N/A"));
    println!("  keyBits:                     {}", key_bits.as_deref().unwrap_or("N/A"));
    println!("  saltSize:                    {}", salt_size.as_deref().unwrap_or("N/A"));
    println!("  blockSize:                   {}", block_size.as_deref().unwrap_or("N/A"));
    println!("  hashSize:                    {}", hash_size.as_deref().unwrap_or("N/A"));
    println!("  cipherAlgorithm:             {}", cipher_algorithm.as_deref().unwrap_or("N/A"));
    println!("  cipherChaining:              {}", cipher_chaining.as_deref().unwrap_or("N/A"));
    println!("  hashAlgorithm:               {}", hash_algorithm.as_deref().unwrap_or("N/A"));
    println!("  saltValue (base64):          {}", salt_value_b64.as_deref().unwrap_or("N/A"));
    println!("  encryptedVerifierHashInput:  {}", evhi_b64.as_deref().unwrap_or("N/A"));
    println!("  encryptedVerifierHashValue:  {}", evhv_b64.as_deref().unwrap_or("N/A"));
    println!("  encryptedKeyValue:           {}", ekv_b64.as_deref().unwrap_or("N/A"));

    // Decode base64 → hex
    let salt_hex = salt_value_b64.as_deref().map(base64_to_hex).unwrap_or_default();
    let evhi_hex = evhi_b64.as_deref().map(base64_to_hex).unwrap_or_default();
    let evhv_hex = evhv_b64.as_deref().map(base64_to_hex).unwrap_or_default();

    println!("\n  salt (hex):                   {}", salt_hex);
    println!("  encryptedVerifierHashInput:   {}", evhi_hex);
    println!("  encryptedVerifierHashValue:   {}", evhv_hex);

    // Determine Office version for hashcat format
    let office_version = match hash_algorithm.as_deref() {
        Some("SHA512") => "2013",
        Some("SHA256") => "2010",
        Some("SHA1") => "2010",
        _ => "2010",
    };

    // Build office2john / hashcat hash string
    // $office$*<ver>*<spinCount>*<keyBits>*<saltSize>*<salt>*<verifier>*<verifierHash>
    let spin = spin_count.as_deref().unwrap_or("100000");
    let kb = key_bits.as_deref().unwrap_or("256");
    let ss = salt_size.as_deref().unwrap_or("16");

    // hashcat modes 9500/9600 expect the encrypted verifier hash to be
    // exactly 32 bytes (64 hex chars). For Office 2013 the value is a 64-byte
    // SHA-512 hash; only the first 32 bytes are compared, so truncate.
    let evhv_hex_trimmed = &evhv_hex[..evhv_hex.len().min(64)];

    let hash = format!(
        "$office$*{}*{}*{}*{}*{}*{}*{}",
        office_version, spin, kb, ss, salt_hex, evhi_hex, evhv_hex_trimmed
    );

    let hashcat_mode = match office_version {
        "2013" => "9600",
        "2010" => "9500",
        _ => "9500",
    };

    println!("\n  office2john / hashcat hash:");
    println!("  {}", hash);
    println!("  hashcat mode: {}", hashcat_mode);

    (hash, hashcat_mode.to_string())
}

// ──────────────────────────────────────────────────────────────
//  Standard / Extensible Encryption (Office 2007 / 2010 compat)
//  After the 4-byte version, two 4-byte fields (header flags +
//  encryption header size) precede the binary header + verifier.
// ──────────────────────────────────────────────────────────────

fn parse_standard_encryption(data: &[u8], version: u16, legacy: bool) -> Option<(String, String)> {
    // EncryptionInfo layout (all u32 LE):
    //   [ 0.. 4] HeaderFlags  (reserved)
    //   [ 4.. 8] EncryptionHeaderSize  (size of EncryptionHeader in bytes)
    //   [ 8..12] Header.Flags
    //   [12..16] Header.SizeExtra
    //   [16..20] Header.AlgID
    //   [20..24] Header.AlgIDHash
    //   [24..28] Header.KeySize       (in bits)
    //   [28..32] Header.ProviderType
    //   [32..36] Header.Reserved1
    //   [36..40] Header.Reserved2
    //   [40..  ] Header.CSPName  (null-terminated UTF-16LE)
    //
    // EncryptionVerifier layout (follows CSPName null terminator):
    //   [ 0.. 4] SaltSize  (= 0x10)
    //   [ 4..20] Salt  (16 bytes)
    //   [20..36] EncryptedVerifier  (16 bytes)
    //   [36..40] VerifierHashSize  (= 0x14 for SHA1)
    //   [40..72] EncryptedVerifierHash  (32 bytes for AES)

    if data.len() < 44 {
        println!(
            "Error: Standard encryption data too short ({} bytes).",
            data.len()
        );
        return None;
    }

    let header_flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let size_extra = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let alg_id = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let alg_id_hash = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let key_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let provider_type = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let reserved1 = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let reserved2 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    // Find end of CSPName (search for double-null in UTF-16LE)
    let mut csp_end = 40;
    while csp_end + 1 < data.len() {
        if data[csp_end] == 0 && data[csp_end + 1] == 0 {
            break;
        }
        csp_end += 2;
    }
    let csp_name: String = String::from_utf16_lossy(
        &data[40..csp_end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<u16>>(),
    );

    println!("\n=== Standard Encryption (Office 2007, v{}) ===", version);
    let _ = legacy;
    println!("  HeaderFlags:    0x{:08X}", header_flags);
    println!("  HeaderSize:     {}", header_size);
    println!("  Flags:         0x{:08X}", flags);
    println!("  SizeExtra:     {}", size_extra);
    println!("  AlgID:         0x{:08X} ({})", alg_id, alg_id_name(alg_id));
    println!(
        "  AlgIDHash:     0x{:08X} ({})",
        alg_id_hash,
        alg_id_hash_name(alg_id_hash)
    );
    println!("  KeySize:       {} bits", key_size);
    println!("  ProviderType:  0x{:08X}", provider_type);
    println!("  Reserved1:     0x{:08X}", reserved1);
    println!("  Reserved2:     0x{:08X}", reserved2);
    println!("  CSPName:       {}", csp_name);

    // ── Parse EncryptionVerifier ──
    let verifier_offset = csp_end + 2; // +2 to skip the null terminator
    if data.len() < verifier_offset + 40 {
        println!(
            "Error: Not enough data for EncryptionVerifier (need {}, have {}).",
            verifier_offset + 40,
            data.len()
        );
        return None;
    }

    let v = &data[verifier_offset..];
    let salt_size_val = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
    let salt = &v[4..20]; // 16 bytes
    let encrypted_verifier = &v[20..36]; // 16 bytes
    let verifier_hash_size = u32::from_le_bytes([v[36], v[37], v[38], v[39]]);
    // Legacy RC4 CryptoAPI verifier hashes are MD5 (16) or SHA1 (20) bytes.
    // OOXML standard encryption stores 32 bytes of verifier hash.
    let vhs = if legacy { verifier_hash_size.min(20) as usize } else { 32 };
    if v.len() < 40 + vhs {
        println!(
            "Error: Not enough data for the verifier hash (need {}, have {}).",
            40 + vhs,
            v.len()
        );
        return None;
    }
    let evh_full = &v[40..40 + vhs];

    let salt_hex = to_hex(salt);
    let ev_hex = to_hex(encrypted_verifier);
    let evh_hex = to_hex(evh_full);

    println!("\n  SaltSize:               {}", salt_size_val);
    println!("  Salt (hex):             {}", salt_hex);
    println!("  EncryptedVerifier:     {}", ev_hex);
    println!("  VerifierHashSize:      {}", verifier_hash_size);
    println!("  EncryptedVerifierHash:  {}", evh_hex);

    if legacy {
        if verifier_hash_size <= 16 {
            // MD5-based verifier -> mode 9700, prefix $0, hash field = 16 bytes.
            let hash = format!(
                "$oldoffice$0*{}*{}*{}",
                salt_hex,
                ev_hex,
                &evh_hex[..evh_hex.len().min(32)]
            );
            println!("\n  hashcat hash:");
            println!("  {}", hash);
            println!("  hashcat mode: 9700");
            Some((hash, "9700".to_string()))
        } else {
            // SHA1-based RC4 CryptoAPI -> mode 9800. Prefix selects the RC4
            // key length: $3 = 40-bit, $4 = 128-bit (hash field = full SHA1).
            let typ = match key_size {
                40 => 3,
                56 => 5,
                _ => 4,
            };
            let hash = format!(
                "$oldoffice${}*{}*{}*{}",
                typ, salt_hex, ev_hex, evh_hex
            );
            println!("\n  hashcat hash:");
            println!("  {}", hash);
            println!("  hashcat mode: 9800");
            Some((hash, "9800".to_string()))
        }
    } else {
        // hashcat mode 9400 expects the encrypted verifier hash to be exactly
        // 20 bytes (40 hex chars). AES files store 32 bytes where the first
        // 20 bytes are the SHA1 and the rest is random padding, so truncate.
        let hash = format!(
            "$office$*2007*20*{}*{}*{}*{}*{}",
            key_size,
            salt_size_val,
            salt_hex,
            ev_hex,
            &evh_hex[..evh_hex.len().min(40)]
        );

        println!("\n  office2john / hashcat hash:");
        println!("  {}", hash);
        println!("  hashcat mode: 9400");

        Some((hash, "9400".to_string()))
    }
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

/// Extract an XML attribute value: `attrName="value"` → `value`
fn xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    let start = xml.find(&pattern)? + pattern.len();
    let end = xml[start..].find('"')?;
    Some(xml[start..start + end].to_string())
}

/// Byte slice → lowercase hex string
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Minimal Base64 decoder → hex string (no external crate needed)
fn base64_to_hex(b64: &str) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let chars: Vec<u8> = b64.trim().bytes().filter(|&b| b != b'=').collect();
    let mut result = Vec::new();

    for chunk in chars.chunks(4) {
        let mut bits: u32 = 0;
        let mut bit_count = 0;
        for &c in chunk {
            if let Some(pos) = CHARSET.iter().position(|&ch| ch == c) {
                bits = (bits << 6) | (pos as u32);
                bit_count += 6;
            }
        }
        while bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
        }
    }

    to_hex(&result)
}

fn alg_id_name(alg_id: u32) -> &'static str {
    match alg_id {
        0x00006601 | 0x0000660E => "AES-128",
        0x00006602 | 0x0000660F => "AES-192",
        0x00006603 | 0x00006610 => "AES-256",
        0x00006801 => "RC4",
        _ => "Unknown",
    }
}

fn alg_id_hash_name(alg_id_hash: u32) -> &'static str {
    match alg_id_hash {
        0x00008004 => "SHA-1",
        0x0000800c => "SHA-256",
        0x0000800d => "SHA-384",
        0x0000800e => "SHA-512",
        0x00008003 => "MD5",
        _ => "Unknown",
    }
}