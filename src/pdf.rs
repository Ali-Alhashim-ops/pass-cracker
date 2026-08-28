use std::fs;

/// Extracts the hashcat hash and mode for a password-protected PDF file.
///
/// Supported revisions (Standard Security Handler):
///   R2  -> mode 10400   (PDF 1.1 - 1.3, RC4-40)
///   R3  -> mode 10500   (PDF 1.4, RC4-128)
///   R4  -> mode 10500   (PDF 1.5 - 1.6, AES-128)
///   R5  -> mode 10600   (PDF 1.7 Level 3, AES-256)
///   R6  -> mode 10700   (PDF 1.7 Level 8, AES-256)
pub fn pdf_encryption(file_path: &str) -> Option<(String, String)> {
    println!("File Type: PDF (encrypted)");

    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            println!("Error: Could not read file: {}", e);
            return None;
        }
    };

    if !data.starts_with(b"%PDF-") {
        println!("Error: Not a PDF file (bad magic).");
        return None;
    }

    // ── 1. locate the /Encrypt indirect reference in the trailer ──
    let Some((enc_obj, enc_gen)) = find_encrypt_ref(&data) else {
        println!("Error: No /Encrypt dictionary found (file is not encrypted).");
        return None;
    };

    // ── 2. read the encryption dictionary object ──
    let Some(raw_dict) = read_pdf_object(&data, enc_obj, enc_gen) else {
        println!("Error: Could not read the /Encrypt object ({}, {}).", enc_obj, enc_gen);
        return None;
    };
    let dict = parse_dict(&raw_dict);

    println!("  Encrypt object: {} {} R", enc_obj, enc_gen);
    println!("  Encrypt dictionary: << {} >>", printable_dict(&dict));

    // ── 3. trailer /ID ──
    let id = find_first_id(&data);

    // ── 4. required values ──
    let v = number_value(&dict, b"V");
    let r = number_value(&dict, b"R");
    let p_i32 = signed_number_value(&dict, b"P");
    let length = number_value(&dict, b"Length");
    let enc_metadata = boolean_value(&dict, b"EncryptMetadata");
    let o = string_value(&dict, b"O");
    let u = string_value(&dict, b"U");
    let oe = string_value(&dict, b"OE");
    let ue = string_value(&dict, b"UE");

    let (v, r) = match (v, r) {
        (Some(v), Some(r)) => (v, r),
        _ => {
            println!("Error: Encrypt dictionary missing /V or /R.");
            return None;
        }
    };
    let enc_metadata_bool = enc_metadata.unwrap_or(true);

    println!("  V={}  R={}  P={}  Length={}", v, r, p_i32, length.unwrap_or(0));
    println!("  EncryptMetadata={}", enc_metadata_bool);
    println!("  O={} bytes, U={} bytes, OE={} bytes, UE={} bytes", o.len(), u.len(), oe.len(), ue.len());
    println!("  ID={} bytes", id.len());

    let bits = match length {
        Some(40) => 40,
        Some(_) | None => match r {
            2 => 40,
            _ => 128,
        },
    };
    let _ = bits;

    // ── 5. build the hash ──
    let mut hash = String::from("$pdf$");

let mode: &'static str = match r {
        2 => {
            // $pdf$1*2*40*<P>*0*<id_len>*<ID>*32*<U>*32*<O
            hash.push_str(&format!("1*2*40*{}*0*", p_i32));
            push_id_and_lengths(&mut hash, &id, &u, &o);
            "10400"
        }
        3 | 4 => {
            // $pdf$<V>*<R>*128*<P>*<enc_md>*<id_len>*<ID>*32*<U>*32*<O
            let enc_md = if r >= 4 { if enc_metadata_bool { 1 } else { 0 } } else { 1 };
            let v_out = if r == 4 { 4 } else { 2 };
            hash.push_str(&format!("{}*{}*128*{}*{}*", v_out, r, p_i32, enc_md));
            if id.is_empty() {
                hash.push_str(&format!("0*"));
            } else {
                hash.push_str(&format!("{}*{}*", id.len(), to_hex(&id)));
            }
            hash.push_str(&format!("32*{}*32*{}", to_hex(&u_32_or_pad(&u)), to_hex(&o_32_or_pad(&o))));
            "10500"
        }
        5 | 6 => {
            // $pdf$5*<R>*256*<P>*<enc_md>*16*<ID>*127*<U+UE pad to 127>*127*<O+OE pad to 127>*32*<UE>*32*<OE>
            let enc_md = if enc_metadata_bool { 1 } else { 0 };
            hash.push_str(&format!("5*{}*256*{}*{}*", r, p_i32, enc_md));
            if id.is_empty() {
                hash.push_str("0*");
            } else {
                hash.push_str(&format!("{}*{}*", id.len(), to_hex(&id)));
            }
            let u_combined = merge_pad(&u, &ue, 127);
            let o_combined = merge_pad(&o, &oe, 127);
            hash.push_str(&format!("127*{}*127*{}*", to_hex(&u_combined), to_hex(&o_combined)));
            hash.push_str(&format!("32*{}*32*{}", to_hex(&pad_32(&ue)), to_hex(&pad_32(&oe))));
            if r == 5 { "10600" } else { "10700" }
        }
        _ => {
            println!("Error: Unsupported PDF encryption revision R={}.", r);
            return None;
        }
    };

    println!("\n  hashcat hash:");
    println!("  {}", hash);
    println!("  hashcat mode: {}", mode);

    Some((hash, mode.to_string()))
}

// ──────────────────────────────────────────────────────────────
//  PDF scanning helpers
// ──────────────────────────────────────────────────────────────

/// Find the `/Encrypt <obj> <gen> R` reference (usually in the trailer).
fn find_encrypt_ref(data: &[u8]) -> Option<(u32, u32)> {
    let mut search_from = 0;
    loop {
        let rel = find_bytes(data, b"/Encrypt", search_from)?;
        let mut p = rel + b"/Encrypt".len();
        while p < data.len() && data[p].is_ascii_whitespace() {
            p += 1;
        }
        let (obj, p2) = parse_signed(&data, p)?;
        if obj < 0 {
            search_from = rel + 1;
            continue;
        }
        let mut p3 = p2;
        while p3 < data.len() && data[p3].is_ascii_whitespace() {
            p3 += 1;
        }
        let (gen_n, p4) = parse_signed(&data, p3)?;
        if gen_n < 0 {
            search_from = rel + 1;
            continue;
        }
        let mut p5 = p4;
        while p5 < data.len() && data[p5].is_ascii_whitespace() {
            p5 += 1;
        }
        // must be followed by an "R" (indirect reference), which is the trailer's
        // reference to the /Encrypt object
        if p5 < data.len() && (data[p5] == b'R' || data[p5] == b'r') {
            return Some((obj as u32, gen_n as u32));
        }
        search_from = rel + 1;
    }
}

/// Locate `<obj> <gen> obj` and return the slice between it and `endobj`.
fn read_pdf_object(data: &[u8], obj: u32, gen_num: u32) -> Option<Vec<u8>> {
    let header = format!("{} {} obj", obj, gen_num).into_bytes();
    let start = find_bytes(data, &header, 0)?;
    let end = find_bytes(data, b"endobj", start)?;
    let mut body = data[start..end].to_vec();
    // drop the "obj" keyword at the front
    let kw = find_bytes(&body, b"obj", 0)? + 3;
    body.drain(..kw);
    Some(body)
}

/// Trailer `/ID [` value `]` — returns the first array element (a string).
fn find_first_id(data: &[u8]) -> Vec<u8> {
    let mut search_from = 0;
    let mut result: Vec<u8> = Vec::new();
    loop {
        let Some(rel) = find_bytes(data, b"/ID", search_from) else {
            return result;
        };
        let mut p = rel + 3;
        while p < data.len() && data[p].is_ascii_whitespace() {
            p += 1;
        }
        // value is an array [ <str> <str> ]
        if p < data.len() && data[p] == b'[' {
            p += 1;
            while p < data.len() && data[p].is_ascii_whitespace() {
                p += 1;
            }
            if p < data.len() && (data[p] == b'<' || data[p] == b'(') {
                let (s, _) = if data[p] == b'<' {
                    parse_hex_string(&data, p, data.len())
                } else {
                    parse_literal_string(&data, p, data.len())
                };
                result = s;
                return result;
            }
        }
        search_from = rel + 1;
    }
}

/// Parse a very small subset of a PDF dictionary into a flat Vec<(key, value)>.
///
/// Only /Name value pairs on the top level of the (possibly nested) dictionary
/// are collected; nested dictionaries simply contribute their own entries too,
/// which is harmless because lookups are by exact name only.
fn parse_dict(data: &[u8]) -> Vec<(Vec<u8>, DictValue)> {
    let mut out = Vec::new();
    // start scanning inside the outermost << ... >> pair
    let (mut i, content) = match find_bytes_between(data, b"<<", b">>") {
        Some((s, e)) => (s, e),
        None => (0, data.len()),
    };
    let content = content;

    while i < content {
        let c = data[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'/' => {
                let mut j = i + 1;
                while j < content
                    && !data[j].is_ascii_whitespace()
                    && data[j] != b'['
                    && data[j] != b']'
                    && data[j] != b'('
                    && data[j] != b')'
                    && data[j] != b'<'
                    && data[j] != b'>'
                {
                    j += 1;
                }
                out.push((data[i + 1..j].to_vec(), DictValue::None));
                i = j;
            }
            b'[' => {
                // skip to matching ']'
                let mut depth = 1usize;
                let mut j = i + 1;
                while j < content && depth > 0 {
                    match data[j] {
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
            }
            b'<' => {
                if i + 1 < content && data[i + 1] == b'<' {
                    // nested dict (e.g. /CF): skip to matching '>>'
                    if let Some((_s, e)) = find_bytes_between(&data[i..], b"<<", b">>") {
                        i += e + 2;
                    } else {
                        i += 2;
                    }
                } else {
                    let (s, j) = parse_hex_string(&data, i, content);
                    assign_last(&mut out, DictValue::Bytes(s));
                    i = j;
                }
            }
            b'>' => {
                i += 1;
            }
            b'(' => {
                let (s, j) = parse_literal_string(&data, i, content);
                assign_last(&mut out, DictValue::Bytes(s));
                i = j;
            }
            b't' if data[i..].starts_with(b"true") => {
                assign_last(&mut out, DictValue::Bool(true));
                i += 4;
            }
            b'f' if data[i..].starts_with(b"false") => {
                assign_last(&mut out, DictValue::Bool(false));
                i += 5;
            }
            _ => {
                if c.is_ascii_digit() || c == b'-' || c == b'+' {
                    let (n, j) = match parse_signed(&data, i) {
                        Some(x) => x,
                        None => {
                            i += 1;
                            continue;
                        }
                    };
                    // possibly "N M R" indirect reference
                    let mut k = j;
                    while k < content && data[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < content && data[k].is_ascii_digit() {
                        if let Some((m, k2)) = parse_signed(&data, k) {
                            let mut l = k2;
                            while l < content && data[l].is_ascii_whitespace() {
                                l += 1;
                            }
                            if l < content && (data[l] == b'R' || data[l] == b'r') {
                                assign_last(&mut out, DictValue::Ref(n as u32, m as u32));
                                i = l + 1;
                            } else {
                                assign_last(&mut out, DictValue::Num(n));
                                i = j;
                            }
                        } else {
                            assign_last(&mut out, DictValue::Num(n));
                            i = j;
                        }
                    } else {
                        assign_last(&mut out, DictValue::Num(n));
                        i = j;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }
    out
}

fn assign_last(out: &mut Vec<(Vec<u8>, DictValue)>, value: DictValue) {
    for i in (0..out.len()).rev() {
        if matches!(out[i].1, DictValue::None) {
            out[i].1 = value;
            return;
        }
    }
    out.push((Vec::new(), value));
}

// We use a marker enum variant ("None") to represent "no value yet" (name seen).
enum DictValue {
    Num(i64),
    Bytes(Vec<u8>),
    Bool(bool),
    Ref(u32, u32),
    None,
}

fn number_value(dict: &[(Vec<u8>, DictValue)], key: &[u8]) -> Option<u32> {
    for (k, v) in dict {
        if k == key {
            if let DictValue::Num(n) = v {
                if *n < 0 {
                    return None;
                }
                return Some(*n as u32);
            }
        }
    }
    None
}

fn signed_number_value(dict: &[(Vec<u8>, DictValue)], key: &[u8]) -> i32 {
    for (k, v) in dict {
        if k == key {
            if let DictValue::Num(n) = v {
                return *n as i32;
            }
        }
    }
    -1i32
}

fn boolean_value(dict: &[(Vec<u8>, DictValue)], key: &[u8]) -> Option<bool> {
    for (k, v) in dict {
        if k == key {
            match v {
                DictValue::Bool(b) => return Some(*b),
                DictValue::Num(n) => return Some(*n != 0),
                _ => return Some(true),
            }
        }
    }
    None
}

fn string_value(dict: &[(Vec<u8>, DictValue)], key: &[u8]) -> Vec<u8> {
    for (k, v) in dict {
        if k == key {
            if let DictValue::Bytes(b) = v {
                return b.clone();
            }
        }
    }
    Vec::new()
}

// ──────────────────────────────────────────────────────────────
//  low-level helpers
// ──────────────────────────────────────────────────────────────

/// A very small and intentionally simple PDF token-aware string parser.
fn parse_hex_string(data: &[u8], start: usize, content: usize) -> (Vec<u8>, usize) {
    let mut i = start + 1;
    let mut hex = Vec::new();
    while i < content && data[i] != b'>' {
        hex.push(data[i]);
        i += 1;
    }
    let end = if i < content { i + 1 } else { i };
    let mut out = Vec::new();
    let mut nib: Option<u8> = None;
    for &c in &hex {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = match (c as char).to_digit(16) {
            Some(d) => d as u8,
            None => continue,
        };
        match nib.take() {
            Some(h) => out.push((h << 4) | v),
            None => nib = Some(v),
        }
    }
    if let Some(h) = nib {
        out.push(h << 4);
    }
    (out, end)
}

fn parse_literal_string(data: &[u8], start: usize, content: usize) -> (Vec<u8>, usize) {
    let mut i = start + 1;
    let mut out = Vec::new();
    let mut depth = 1usize;
    while i < content && depth > 0 {
        match data[i] {
            b'\\' => {
                i += 1;
                if i < content {
                    let c = data[i];
                    match c {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'(' => out.push(b'('),
                        b')' => out.push(b')'),
                        b'\\' => out.push(b'\\'),
                        b'\r' => {
                            // line continuation: swallow optional \n
                            if i + 1 < content && data[i + 1] == b'\n' {
                                i += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut val = 0u32;
                            let mut j = i;
                            for _ in 0..3 {
                                if j < content && (b'0'..=b'7').contains(&data[j]) {
                                    val = val * 8 + (data[j] - b'0') as u32;
                                    j += 1;
                                }
                            }
                            out.push(val as u8);
                            i = j - 1;
                        }
                        _ => out.push(c),
                    }
                    i += 1;
                }
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth > 0 {
                    out.push(b')');
                }
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    (out, i)
}

fn parse_signed(data: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut i = start;
    let mut sign = 1i64;
    if i < data.len() && (data[i] == b'-' || data[i] == b'+') {
        if data[i] == b'-' {
            sign = -1;
        }
        i += 1;
    }
    let mut val = 0i64;
    let mut seen = false;
    while i < data.len() && data[i].is_ascii_digit() {
        val = val * 10 + (data[i] - b'0') as i64;
        seen = true;
        i += 1;
    }
    if !seen {
        return None;
    }
    // stop at "obj" keyword etc. naturally: digits stop at '.'
    if i < data.len() && data[i] == b'.' {
        // skip fraction (real number)
        while i < data.len() && (data[i].is_ascii_digit() || data[i] == b'.') {
            i += 1;
        }
    }
    Some((sign * val, i))
}

fn find_bytes(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= data.len() {
        return None;
    }
    data[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// find first "<<...>>" balanced pair, returning (content_start, content_end)
fn find_bytes_between(data: &[u8], open: &[u8], close: &[u8]) -> Option<(usize, usize)> {
    let s = find_bytes(data, open, 0)? + open.len();
    let mut depth = 1usize;
    let mut i = s;
    while i + close.len() <= data.len() {
        if data[i..].starts_with(open) {
            depth += 1;
            i += open.len();
        } else if data[i..].starts_with(close) {
            depth -= 1;
            if depth == 0 {
                return Some((s, i));
            }
            i += close.len();
        } else {
            i += 1;
        }
    }
    None
}

fn u_32_or_pad(v: &[u8]) -> Vec<u8> {
    if v.len() >= 32 {
        v[..32].to_vec()
    } else {
        let mut out = v.to_vec();
        out.resize(32, 0);
        out
    }
}

fn o_32_or_pad(v: &[u8]) -> Vec<u8> {
    u_32_or_pad(v)
}

fn pad_32(v: &[u8]) -> Vec<u8> {
    if v.len() >= 32 {
        v[..32].to_vec()
    } else {
        let mut out = v.to_vec();
        out.resize(32, 0);
        out
    }
}

fn merge_pad(a: &[u8], b: &[u8], total: usize) -> Vec<u8> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    out.resize(total, 0);
    out
}

fn push_id_and_lengths(hash: &mut String, id: &[u8], u: &[u8], o: &[u8]) {
    if id.is_empty() {
        hash.push_str(&format!("0**"));
    } else {
        hash.push_str(&format!("{}*{}*", id.len(), to_hex(id)));
    }
    hash.push_str(&format!("32*{}*32*{}", to_hex(&u_32_or_pad(u)), to_hex(&u_32_or_pad(o))));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn printable_dict(dict: &[(Vec<u8>, DictValue)]) -> String {
    let mut parts = Vec::new();
    for (k, v) in dict {
        let vs = match v {
            DictValue::Num(n) => n.to_string(),
            DictValue::Bytes(b) => format!("<{}>", to_hex(b)),
            DictValue::Bool(b) => b.to_string(),
            DictValue::Ref(a, g) => format!("{} {} R", a, g),
            DictValue::None => String::from("?"),
        };
        parts.push(format!("/{} {}", String::from_utf8_lossy(k), vs));
    }
    parts.join(" ")
}