use std::fs;

/// Extracts a hashcat PKZIP hash (modes 17200 / 17210) from an encrypted
/// ZIP file. Only the FIRST encrypted member is used (hashcat's single-file
/// pkzip2 format requires exactly one "hash tuple").
///
/// The output layout mirrors John the Ripper's zip2john (single-file branch):
///   $pkzip2$<count=1>*<checksum_size>*2*0*<comp_len>*<uncomp_len>*<crc32>*
///   0*<extra_offset>*<comp_type>*<data_len>*<cs_crc>*<cs_time>*<data>$/pkzip2$
///
/// where cs_crc  = (crc32 >> 16) & 0xffff     (or a time-derived value when the
///                  file was written with a data descriptor, bit 0x08 set), and
/// cs_time = (dos_time >> 8) & 0xff two bytes from the local header's mtime.
pub fn zip_encryption(file_path: &str) -> Option<(String, String)> {
    println!("File Type: ZIP (encrypted)");

    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            println!("Error: Could not read file: {}", e);
            return None;
        }
    };

    if !(data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || find_sig(&data, b"PK\x03\x04", 0).is_some())
    {
        println!("Error: Not a ZIP file (bad magic).");
        return None;
    }

    // ── find the first encrypted local file header ──
    let mut search_from = 0usize;
    while let Some(sig) = find_sig(&data, b"PK\x03\x04", search_from) {
let (comp_len, uncomp_len, crc32, name_len, extra_len, dos_time, flags, comp_type) =
                match parse_local_header(&data, sig) {
                    Some(x) => x,
                    None => {
                        search_from = sig + 4;
                        continue;
                    }
                };

        if flags & 0x0001 == 0 {
            // not encrypted, skip past this member to keep scanning
            let member_end = match next_local_header_after(&data, sig, name_len, extra_len, comp_len, flags) {
                Some(e) => e,
                None => data.len(),
            };
            search_from = member_end.min(sig + 4);
            continue;
        }

        if comp_type != 0 && comp_type != 8 {
            println!("Error: First encrypted member uses unsupported compression type {}.", comp_type);
            return None;
        }

        // data starts right after local header + name + extra
        let data_start = sig + 30 + name_len as usize + extra_len as usize;
        let mut actual_comp_len = comp_len as usize;
        let mut actual_uncomp_len = uncomp_len as usize;
        let mut actual_crc = crc32;

        if flags & 0x0008 != 0 {
            // sizes live in the data descriptor which follows the data.
            // If the header still carries real sizes (zip 3.0 does), the
            // descriptor sits right after the data; otherwise scan for the
            // next structure signature and read the descriptor preceding it.
            let found = if comp_len > 0 && data_start + comp_len + 16 <= data.len() {
                parse_data_descriptor(&data, data_start + comp_len as usize)
            } else {
                let next = data[data_start..]
                    .windows(4)
                    .position(|w| w == b"PK\x03\x04" || w == b"PK\x01\x02" || w == b"PK\x05\x06")
                    .map(|p| data_start + p);
                match next {
                    Some(p) if p >= data_start + 16 => parse_data_descriptor(&data, p - 16),
                    _ => None,
                }
            };
            let (crc2, cmp2, unc2, desc_off) = match found {
                Some(x) => x,
                None => {
                    println!("Error: Could not locate the data descriptor for the first member.");
                    return None;
                }
            };
            actual_crc = crc2;
            actual_comp_len = cmp2;
            actual_uncomp_len = unc2;
            println!("  First encrypted member: streaming (data descriptor)");
            println!(
                "  data descriptor: crc={:08x} comp_len={} uncomp_len={} (descriptor ends at offset {})",
                actual_crc, actual_comp_len, actual_uncomp_len, desc_off
            );
        }

        if data_start + actual_comp_len > data.len() {
            println!("Error: Encrypted member data exceeds file size.");
            return None;
        }
        if actual_comp_len == 0 {
            println!("Error: Encrypted member has zero compressed length.");
            return None;
        }

        let encrypted_data = &data[data_start..data_start + actual_comp_len];

        println!("\n  First encrypted member:");
        println!("    offset in file:           {}", sig);
        println!("    flags:                    0x{:04x}", flags);
        println!("    compression type:         {}", comp_type);
        println!("    compressed length:        {}", actual_comp_len);
        println!("    uncompressed length:      {}", actual_uncomp_len);
        println!("    crc32:                    0x{:08x}", actual_crc);

        // checksum strings, matching zip2john exactly:
        //  - normal      : from crc32 top 2 bytes
        //  - descriptor  : from local header mtime
        let cs = if flags & 0x0008 != 0 {
            format!("{:02x}{:02x}", (dos_time >> 8) & 0xff, dos_time & 0xff)
        } else {
            format!("{:02x}{:02x}", (actual_crc >> 24) & 0xff, (actual_crc >> 16) & 0xff)
        };
        // tc (timestamp-derived checksum) is always emitted alongside cs
        let tc = format!("{:02x}{:02x}", (dos_time >> 8) & 0xff, dos_time & 0xff);

        // extra_offset (additional_offset past the PK\x03\x04 signature):
        //   30-byte local header + filename + extra field
        let extra_offset = 30u64 + name_len as u64 + extra_len as u64;

        let hash = format!(
            "$pkzip2$1*1*2*0*{:x}*{:x}*{:08x}*0*{:x}*{}*{:x}*{}*{}*{}*$/pkzip2$",
            actual_comp_len,
            actual_uncomp_len,
            actual_crc,
            extra_offset,
            comp_type,
            actual_comp_len,
            cs,
            tc,
            to_hex(encrypted_data),
        );

        let mode = if comp_type == 8 { "17200" } else { "17210" };

        println!("\n  hashcat hash:");
        println!("  {}", hash);
        println!("  hashcat mode: {}", mode);

        return Some((hash, mode.to_string()));
    }

    println!("Status: No encrypted entry found in this ZIP file.");
    None
}

fn parse_local_header(data: &[u8], sig: usize) -> Option<(usize, usize, u32, usize, usize, u16, u16, u16)> {
    if sig + 30 > data.len() {
        return None;
    }
    let version = u16::from_le_bytes([data[sig + 4], data[sig + 5]]);
    let flags = u16::from_le_bytes([data[sig + 6], data[sig + 7]]);
    let comp_type = u16::from_le_bytes([data[sig + 8], data[sig + 9]]);
    let dos_time = u16::from_le_bytes([data[sig + 10], data[sig + 11]]);
    let crc32 = u32::from_le_bytes([data[sig + 14], data[sig + 15], data[sig + 16], data[sig + 17]]);
    let comp_len = u32::from_le_bytes([data[sig + 18], data[sig + 19], data[sig + 20], data[sig + 21]]) as usize;
    let uncomp_len = u32::from_le_bytes([data[sig + 22], data[sig + 23], data[sig + 24], data[sig + 25]]) as usize;
    let name_len = u16::from_le_bytes([data[sig + 26], data[sig + 27]]) as usize;

    if sig + 30 + name_len > data.len() {
        return None;
    }
    let extra_len = u16::from_le_bytes([data[sig + 28], data[sig + 29]]) as usize;

    let _ = version;
    Some((comp_len, uncomp_len, crc32, name_len, extra_len, dos_time, flags, comp_type))
}

/// Position right after a (non-encrypted) member so we can scan the next one.
fn next_local_header_after(
    data: &[u8],
    sig: usize,
    name_len: usize,
    extra_len: usize,
    comp_len: usize,
    flags: u16,
) -> Option<usize> {
    let mut end = sig + 30 + name_len + extra_len + comp_len;
    if flags & 0x0008 != 0 {
        // descriptor present
        if let Some((_, _, _, d)) = parse_data_descriptor(data, sig + 30 + name_len + extra_len + comp_len) {
            end = d;
        }
    }
    Some(end)
}

fn parse_data_descriptor(data: &[u8], search_from: usize) -> Option<(u32, usize, usize, usize)> {
    // descriptor: optional sig PK\x07\x08 then crc32 u32, comp_len u32, uncomp_len u32
    let i = search_from;
    if i + 16 > data.len() {
        return None;
    }
    let has_sig = data[i..].starts_with(b"PK\x07\x08");
    let off = if has_sig { i + 4 } else { i };
    if off + 12 > data.len() {
        return None;
    }
    let crc = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let comp = u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]) as usize;
    let uncomp = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as usize;
    let desc_end = off + 12;
    Some((crc, comp, uncomp, desc_end))
}

fn find_sig(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() || needle.is_empty() {
        return None;
    }
    data[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}