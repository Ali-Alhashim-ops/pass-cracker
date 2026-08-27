use std::path::Path;
use std::io::Read;

pub fn excel_2007_to_2016(file_path: &str) {
    println!("File Type: Excel 2007 to 2016+ (Encrypted OLE Container)");

    let path = Path::new(file_path);
    if !path.exists() {
        println!("Error: File does not exist: {}", file_path);
        return;
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
                                parse_encryption_info(&encryption_info_data);
                            }
                            Err(e) => println!("Error reading EncryptionInfo stream: {}", e),
                        }
                    }
                    Err(e) => println!("Error opening EncryptionInfo stream: {}", e),
                }
            } else {
                println!("Status: The OLE container does not contain an 'EncryptionInfo' stream.");
            }
        }
        Err(e) => {
            println!("Error: Failed to open file as an OLE/CFB container: {}", e);
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Top-level dispatcher
// ──────────────────────────────────────────────────────────────

fn parse_encryption_info(data: &[u8]) {
    if data.len() < 4 {
        eprintln!("Error: EncryptionInfo stream too short ({} bytes).", data.len());
        return;
    }

    // Version header: [vMajor (u16 LE), vMinor (u16 LE)]
    let v_major = u16::from_le_bytes([data[0], data[1]]);
    let v_minor = u16::from_le_bytes([data[2], data[3]]);
    println!("Encryption Version: vMajor={}, vMinor={}", v_major, v_minor);

    match v_major {
        4 => parse_agile_encryption(&data[4..]),
        2 | 3 => parse_standard_encryption(&data[4..], v_major),
        _ => println!("Unsupported encryption version: vMajor={}", v_major),
    }
}

// ──────────────────────────────────────────────────────────────
//  Agile Encryption (Office 2010 / 2013 / 2016)
//  After the 4-byte version, the rest is XML.
// ──────────────────────────────────────────────────────────────

fn parse_agile_encryption(data: &[u8]) {
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
            return;
        }
    };

    println!("\n=== Agile Encryption (Office 2010+) ===");

    // Extract attributes from <p:encryptedKey> element
    let spin_count = xml_attr(xml_str, "spinCount");
    let key_bits = xml_attr(xml_str, "keyBits");
    let salt_size = xml_attr(xml_str, "saltSize");
    let block_size = xml_attr(xml_str, "blockSize");
    let hash_size = xml_attr(xml_str, "hashSize");
    let cipher_algorithm = xml_attr(xml_str, "cipherAlgorithm");
    let cipher_chaining = xml_attr(xml_str, "cipherChaining");
    let hash_algorithm = xml_attr(xml_str, "hashAlgorithm");
    let salt_value_b64 = xml_attr(xml_str, "saltValue");
    let evhi_b64 = xml_attr(xml_str, "encryptedVerifierHashInput");
    let evhv_b64 = xml_attr(xml_str, "encryptedVerifierHashValue");
    let ekv_b64 = xml_attr(xml_str, "encryptedKeyValue");

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

    let hash = format!(
        "$office$*{}*{}*{}*{}*{}*{}*{}",
        office_version, spin, kb, ss, salt_hex, evhi_hex, evhv_hex
    );

    let hashcat_mode = match office_version {
        "2013" => "9600",
        "2010" => "9500",
        _ => "9500",
    };

    println!("\n  office2john / hashcat hash:");
    println!("  {}", hash);
    println!("  hashcat mode: {}", hashcat_mode);
}

// ──────────────────────────────────────────────────────────────
//  Standard / Extensible Encryption (Office 2007)
//  After the 4-byte version, binary header + verifier follow.
// ──────────────────────────────────────────────────────────────

fn parse_standard_encryption(data: &[u8], version: u16) {
    // EncryptionHeader layout (all u32 LE):
    //   [ 0.. 4] Flags
    //   [ 4.. 8] SizeExtra
    //   [ 8..12] AlgID
    //   [12..16] AlgIDHash
    //   [16..20] KeySize       (in bits)
    //   [20..24] ProviderType
    //   [24..28] Reserved1
    //   [28..32] Reserved2
    //   [32..  ] CSPName  (null-terminated UTF-16LE)
    //
    // EncryptionVerifier layout (follows CSPName):
    //   [ 0.. 4] SaltSize  (= 0x10)
    //   [ 4..20] Salt  (16 bytes)
    //   [20..36] EncryptedVerifier  (16 bytes)
    //   [36..40] VerifierHashSize  (= 0x14 for SHA1)
    //   [40..72] EncryptedVerifierHash  (32 bytes for AES)

    if data.len() < 36 {
        println!(
            "Error: Standard encryption data too short ({} bytes).",
            data.len()
        );
        return;
    }

    let flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let size_extra = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let alg_id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let alg_id_hash = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let key_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let provider_type = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let reserved1 = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let reserved2 = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

    // Find end of CSPName (search for double-null in UTF-16LE)
    let mut csp_end = 32;
    while csp_end + 1 < data.len() {
        if data[csp_end] == 0 && data[csp_end + 1] == 0 {
            break;
        }
        csp_end += 2;
    }
    let csp_name: String = String::from_utf16_lossy(
        &data[32..csp_end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<u16>>(),
    );

    println!("\n=== Standard Encryption (Office 2007, v{}) ===", version);
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
    if data.len() < verifier_offset + 72 {
        println!(
            "Error: Not enough data for EncryptionVerifier (need {}, have {}).",
            verifier_offset + 72,
            data.len()
        );
        return;
    }

    let v = &data[verifier_offset..];
    let salt_size_val = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
    let salt = &v[4..20]; // 16 bytes
    let encrypted_verifier = &v[20..36]; // 16 bytes
    let verifier_hash_size = u32::from_le_bytes([v[36], v[37], v[38], v[39]]);
    let encrypted_verifier_hash = &v[40..72]; // 32 bytes

    let salt_hex = to_hex(salt);
    let ev_hex = to_hex(encrypted_verifier);
    let evh_hex = to_hex(encrypted_verifier_hash);

    println!("\n  SaltSize:               {}", salt_size_val);
    println!("  Salt (hex):             {}", salt_hex);
    println!("  EncryptedVerifier:     {}", ev_hex);
    println!("  VerifierHashSize:      {}", verifier_hash_size);
    println!("  EncryptedVerifierHash:  {}", evh_hex);

    // Build office2john / hashcat hash
    // $office$*2007*20*<keyBits>*<saltSize>*<salt>*<verifier>*<verifierHash>
    // Note: field 2 = 20 (SHA1 hash size, not spin count — standard enc. has no spin count)
    let hash = format!(
        "$office$*2007*20*{}*{}*{}*{}*{}",
        key_size, salt_size_val, salt_hex, ev_hex, evh_hex
    );

    println!("\n  office2john / hashcat hash:");
    println!("  {}", hash);
    println!("  hashcat mode: 9400");
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
        0x00006601 | 0x00006610 => "AES-128",
        0x00006602 | 0x00006611 => "AES-192",
        0x00006603 | 0x00006612 => "AES-256",
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