use std::fs;

/// Extracts a hashcat hash from an encrypted RAR file.
///
/// RAR5 (magic `Rar!\x1a\x07\x01\x00`)        -> mode 13000 ($rar5$)
/// RAR4 with encrypted headers / -hp magic    -> mode 12500 ($RAR3$*0*)
pub fn rar_encryption(file_path: &str) -> Option<(String, String)> {
    println!("File Type: RAR (encrypted)");

    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            println!("Error: Could not read file: {}", e);
            return None;
        }
    };

    if data.len() < 8 {
        println!("Error: File too small to be a RAR archive.");
        return None;
    }

    if data.starts_with(b"Rar!\x1a\x07\x01\x00") {
        println!("  RAR format: RAR5");
        rar5_encryption(&data)
    } else if data.starts_with(b"Rar!\x1a\x07\x00") {
        println!("  RAR format: RAR4 (RAR3-compatible)");
        rar4_encryption(&data)
    } else {
        println!("Error: Not a RAR file (bad magic).");
        None
    }
}

// ──────────────────────────────────────────────────────────────
//  RAR5 -> mode 13000
// ──────────────────────────────────────────────────────────────

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HEAD_MAIN: u8 = 0x01;
const HEAD_FILE: u8 = 0x02;
const HEAD_SERVICE: u8 = 0x03;
const HEAD_CRYPT: u8 = 0x04;
const HEAD_ENDARC: u8 = 0x05;
const FHEXTRA_CRYPT: u64 = 0x01;
const FHFL_UTIME: u64 = 0x02;
const FHFL_CRC32: u64 = 0x04;
const CHFL_CRYPT_PSWCHECK: u64 = 0x01;

struct Rar5Ctx {
    salt: [u8; 16],
    iter: u32,
    encrypted: bool,
    pswcheck: [u8; 8],
}

fn rar5_encryption(data: &[u8]) -> Option<(String, String)> {
    let mut pos = 8usize; // skip the 8-byte RAR5 signature
    let mut ctx = Rar5Ctx {
        salt: [0; 16],
        iter: 0,
        encrypted: false,
        pswcheck: [0; 8],
    };

    while pos + 5 <= data.len() {
        // header: CRC32(4) + block_size(vint) + type(1) ...
        let mut p = pos + 4; // skip CRC
        let (block_size, n) = read_vuint(data, p)?;
        p += n;
        let head_size = block_size as usize + 4 + n;
        if p >= data.len() {
            break;
        }
        let header_type = data[p];
        p += 1;
        let (flags, n) = read_vuint(data, p)?;
        p += n;

        let mut extra_size: u64 = 0;
        let mut data_size: u64 = 0;
        if flags & HFL_EXTRA != 0 {
            let (v, n2) = read_vuint(data, p)?;
            p += n2;
            extra_size = v;
        }
        if flags & HFL_DATA != 0 {
            let (v, n2) = read_vuint(data, p)?;
            p += n2;
            data_size = v;
        }

        match header_type {
            HEAD_MAIN => {
                // vint ArcFlags, maybe volume number — not needed for hash
                let _ = read_vuint(data, p);
            }
            HEAD_CRYPT => {
                // archive-level encryption record (headers encrypted, -hp)
                let (_enc_version, nv) = read_vuint(data, p)?;
                p += nv;
                let (enc_flags, n2) = read_vuint(data, p)?;
                p += n2;
                if p >= data.len() {
                    break;
                }
                let lg2 = data[p] as u32;
                p += 1;
                if p + 16 > data.len() {
                    break;
                }
                ctx.salt.copy_from_slice(&data[p..p + 16]);
                p += 16;
                let use_pswcheck = (enc_flags & CHFL_CRYPT_PSWCHECK) != 0;
                if use_pswcheck {
                    if p + 8 > data.len() {
                        break;
                    }
                    ctx.pswcheck.copy_from_slice(&data[p..p + 8]);
                }
                ctx.iter = lg2;
                ctx.encrypted = true;

                // With -hp the <size> and <type> fields of the record are
                // followed by the rest of the (encrypted) headers as a single
                // stream. The first 16 bytes of that stream are the CBC IV.
                let iv_start = pos + head_size;
                if iv_start + 16 <= data.len() {
                    let iv = &data[iv_start..iv_start + 16];
                    println!("\n  RAR5 (encrypted headers / file names):");
                    println!("    salt:        {}", to_hex(&ctx.salt));
                    println!("    iterations:  {}", ctx.iter);
                    println!("    iv:          {}", to_hex(iv));
                    println!("    pswcheck:    {}", to_hex(&ctx.pswcheck));
                    return Some((
                        build_rar5(&ctx.salt, ctx.iter, iv, &ctx.pswcheck),
                        "13000".to_string(),
                    ));
                }
            }
            HEAD_FILE | HEAD_SERVICE => {
                // If headers are encrypted the block content cannot be parsed;
                // the first 16 bytes of the encrypted block are the IV.
                if ctx.encrypted {
                    if p + 16 > data.len() {
                        return None;
                    }
                    let iv = &data[p..p + 16];
                    println!("\n  RAR5 (encrypted headers / file names):");
                    println!("    salt:        {}", to_hex(&ctx.salt));
                    println!("    iterations:  {}", ctx.iter);
                    println!("    iv:          {}", to_hex(iv));
                    println!("    pswcheck:    {}", to_hex(&ctx.pswcheck));
                    return Some((build_rar5(&ctx.salt, ctx.iter, iv, &ctx.pswcheck), "13000".to_string()));
                }

                // parse file header fields
                let (file_flags, n) = read_vuint(data, p)?;
                p += n;
                let (unp_size, n) = read_vuint(data, p)?;
                p += n;
                let (_file_attr, n) = read_vuint(data, p)?;
                p += n;
                if file_flags & FHFL_UTIME != 0 {
                    p += 4;
                }
                if file_flags & FHFL_CRC32 != 0 {
                    p += 4;
                }
                let (_comp_info, n) = read_vuint(data, p)?;
                p += n;
                let (_host_os, n) = read_vuint(data, p)?;
                p += n;
                let (name_size, n) = read_vuint(data, p)?;
                p += n;
                p += name_size as usize;

                if extra_size > 0 {
                    if let Some(h) = parse_extra_crypt(data, p, extra_size as usize, header_type) {
                        return Some(h);
                    }
                }
                let _ = unp_size;
            }
            HEAD_ENDARC => break,
            _ => {}
        }

        pos += head_size + data_size as usize;
    }

    None
}

/// Parse the "extra area" of a RAR5 file/service header, looking for the
/// encryption record (field type 0x01). Returns (hash, mode) on success.
fn parse_extra_crypt(
    data: &[u8],
    mut p: usize,
    extra_size: usize,
    header_type: u8,
) -> Option<(String, String)> {
    let end = p + extra_size;
    let bytes_left = extra_size;

    while p < end && bytes_left > 0 {
        let (field_size, n) = read_vuint(data, p)?;
        p += n;
        if field_size as usize > bytes_left {
            break;
        }
        let (field_type, n2) = read_vuint(data, p)?;
        p += n2;
        let _ = header_type;

        if field_type == FHEXTRA_CRYPT {
            let (_enc_version, n) = read_vuint(data, p)?;
            p += n;
            let (enc_flags, n) = read_vuint(data, p)?;
            p += n;
            if enc_flags & CHFL_CRYPT_PSWCHECK == 0 {
                println!("Error: RAR5 encryption without a password check is not supported.");
                return None;
            }
            if p >= data.len() {
                return None;
            }
            let lg2 = data[p] as u32;
            p += 1;
            if p + 16 + 16 + 8 > data.len() {
                return None;
            }
            let salt = &data[p..p + 16];
            let iv = &data[p + 16..p + 32];
            let pswcheck = &data[p + 32..p + 40];

            println!("\n  RAR5 encryption record (first encrypted file):");
            println!("    salt:        {}", to_hex(salt));
            println!("    iterations:  {}", lg2);
            println!("    iv:          {}", to_hex(iv));
            println!("    pswcheck:    {}", to_hex(pswcheck));

            let hash = build_rar5(salt, lg2, iv, pswcheck);
            println!("\n  hashcat hash:");
            println!("  {}", hash);
            println!("  hashcat mode: 13000");
            return Some((hash, "13000".to_string()));
        }

        p += field_size as usize;
    }

    None
}

fn build_rar5(salt: &[u8], iter: u32, iv: &[u8], pswcheck: &[u8]) -> String {
    format!(
        "$rar5$16${}${}${}$8${}",
        to_hex(&salt[..16.min(salt.len())]),
        iter,
        to_hex(&iv[..16.min(iv.len())]),
        to_hex(&pswcheck[..8.min(pswcheck.len())]),
    )
}

/// RAR5 variable-length integer: 7 bits per byte, LSB-first order, high bit 0x80 = continuation.
fn read_vuint(data: &[u8], p: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    for i in 0..10 {
        if p + i >= data.len() {
            return None;
        }
        let c = data[p + i];
        val |= (u64::from(c & 0x7f)) << shift;
        if c & 0x80 == 0 {
            return Some((val, i + 1));
        }
        shift += 7;
    }
    None
}

// ──────────────────────────────────────────────────────────────
//  RAR4 / RAR3 -> mode 12500 (only when headers are encrypted, -hp)
// ──────────────────────────────────────────────────────────────

fn rar4_encryption(data: &[u8]) -> Option<(String, String)> {
    // archive header:  CRC(2)  Type(1)=0x73  Flags(2)  HeadSize(2)  Reserved1(4) (+comment)
    // After the 7-byte signature.
    let p = 7usize; // RAR4 signature is 7 bytes
    if p + 7 > data.len() {
        println!("Error: RAR4 archive header missing.");
        return None;
    }

    let hdr_type = data[p + 2];
    if hdr_type != 0x73 {
        println!("Error: Unexpected RAR4 first header (type 0x{:02x}).", hdr_type);
        return None;
    }
    let flags = u16::from_le_bytes([data[p + 3], data[p + 4]]);
    let head_size = u16::from_le_bytes([data[p + 5], data[p + 6]]) as usize;

    println!("  main header flags: 0x{:04x}", flags);

    // -hp: headers encrypted (MHD_ENCVER)
    if flags & 0x0080 != 0 {
        if data.len() < 24 {
            println!("Error: File too small for the RAR3-hp trick.");
            return None;
        }
        let last24 = &data[data.len() - 24..];
        let salt = &last24[0..8];
        let crypted = &last24[8..24];

        println!("  encrypted headers (-hp) detected");
        println!("  salt (from end-of-archive):     {}", to_hex(salt));
        println!("  encrypted check block:          {}", to_hex(crypted));

        let hash = format!("$RAR3$*0*{}*{}", to_hex(salt), to_hex(crypted));
        println!("\n  hashcat hash:");
        println!("  {}", hash);
        println!("  hashcat mode: 12500");
        return Some((hash, "12500".to_string()));
    }

    // no -hp: only file contents are encrypted — hashcat has no usable mode for this
    println!("Status: This RAR4 archive encrypts file *contents only* (no -hp).");
    println!("        hashcat cannot crack this variant directly (needs mode 23700).");
    let _ = head_size;
    None
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}