
pub fn is_whitespace_byte(b: u8) -> bool {
    return b == b' ' || b == b'\t'
}

/// VCHAR
pub fn is_visible_byte(byte: u8) -> bool {
    byte >= 0x21 && byte <= 0x7e
}

pub fn is_token_byte(byte: u8) -> bool {
    b"!#$%&'*+-.^_`|~".contains(&byte) || byte.is_ascii_digit() || byte.is_ascii_alphabetic()
}

pub fn is_header_value_byte(byte: u8) -> bool {
    is_visible_byte(byte) || byte == b' ' || byte == b'\t'
}

fn is_obs_text_byte(byte: u8) -> bool {
    byte >= 0x80 // and implicitly `byte <= 0xff`
}

pub fn is_status_reason_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b' ' || is_visible_byte(byte) || is_obs_text_byte(byte)
}


