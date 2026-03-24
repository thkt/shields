/// Decode obfuscation while preserving shell structure (quotes stay intact).
/// Applies: N7 (ANSI-C) → N5 (indirection) → N6 (backslash) → N3 (IFS).
pub fn decode(command: &str) -> String {
    let mut cmd = command.to_string();
    if cmd.contains("$'") {
        cmd = n7_decode_ansi_c(&cmd);
    }
    if cmd.contains("${!") {
        cmd = n5_strip_var_indirection(&cmd);
    }
    if cmd.contains('\\') {
        cmd = n6_strip_backslash(&cmd);
    }
    if cmd.contains("IFS") {
        cmd = n3_strip_ifs(&cmd);
    }
    cmd
}

/// Strip shell structure (quotes, braces, command substitution markers).
/// Applies: N1 (quotes) → N4 (braces) → N2 (cmd sub).
pub fn strip(command: &str) -> String {
    let mut cmd = command.to_string();
    if cmd.contains(['\'', '"', '`']) {
        cmd = n1_strip_quotes(&cmd);
    }
    if cmd.contains(['{', '}', ',']) {
        cmd = n4_strip_braces(&cmd);
    }
    if cmd.contains("$(") {
        cmd = n2_strip_command_sub(&cmd);
    }
    cmd
}

fn n1_strip_quotes(cmd: &str) -> String {
    cmd.replace(['\'', '"', '`'], "")
}

fn n2_strip_command_sub(cmd: &str) -> String {
    cmd.replace("$(", "")
}

fn n3_strip_ifs(cmd: &str) -> String {
    cmd.replace("${IFS}", " ").replace("$IFS", " ")
}

fn n4_strip_braces(cmd: &str) -> String {
    cmd.replace(['{', '}'], "").replace(',', " ")
}

fn n5_strip_var_indirection(cmd: &str) -> String {
    cmd.replace("${!", "${")
}

fn n6_strip_backslash(cmd: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && next.is_alphanumeric()
        {
            continue;
        }
        result.push(c);
    }
    result
}

fn n7_decode_ansi_c(cmd: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    let bytes = cmd.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if i + 2 < len && bytes[i] == b'$' && bytes[i + 1] == b'\'' {
            let start = i;
            i += 2; // skip $'
            let mut decoded = String::new();
            let mut valid = false;

            while i < len && bytes[i] != b'\'' {
                if i + 1 < len
                    && bytes[i] == b'\\'
                    && let Some((ch, consumed)) = decode_escape(cmd, bytes, i, len)
                {
                    decoded.push(ch);
                    i += consumed;
                    valid = true;
                    continue;
                }
                decoded.push(bytes[i] as char);
                i += 1;
            }

            if valid && i < len && bytes[i] == b'\'' {
                result.push_str(&decoded);
                i += 1;
            } else {
                result.push_str(&cmd[start..i.min(len)]);
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Decode a single escape sequence starting at `\` (position `i`).
/// Returns (decoded_char, bytes_consumed) or None if unrecognized.
fn decode_escape(cmd: &str, bytes: &[u8], i: usize, len: usize) -> Option<(char, usize)> {
    // \xNN — hex byte
    if i + 3 < len && bytes[i + 1] == b'x' {
        let hex = &cmd[i + 2..i + 4];
        if let Ok(byte) = u8::from_str_radix(hex, 16) {
            return Some((byte as char, 4));
        }
    }
    // \uNNNN — 4-digit Unicode
    if i + 5 < len
        && bytes[i + 1] == b'u'
        && let Ok(cp) = u32::from_str_radix(&cmd[i + 2..i + 6], 16)
        && let Some(ch) = char::from_u32(cp)
    {
        return Some((ch, 6));
    }
    // \UNNNNNNNN — 8-digit Unicode
    if i + 9 < len
        && bytes[i + 1] == b'U'
        && let Ok(cp) = u32::from_str_radix(&cmd[i + 2..i + 10], 16)
        && let Some(ch) = char::from_u32(cp)
    {
        return Some((ch, 10));
    }
    // \NNN — octal (1-3 digits)
    if bytes[i + 1] >= b'0' && bytes[i + 1] <= b'7' {
        let oct_start = i + 1;
        let mut oct_end = oct_start;
        while oct_end < len
            && oct_end < oct_start + 3
            && bytes[oct_end] >= b'0'
            && bytes[oct_end] <= b'7'
        {
            oct_end += 1;
        }
        if let Ok(byte) = u8::from_str_radix(&cmd[oct_start..oct_end], 8) {
            return Some((byte as char, oct_end - i));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode tests ---

    #[test]
    fn decode_preserves_quotes() {
        let input = r#"sudo bash -c "rm -rf /""#;
        assert_eq!(decode(input), input);
    }

    #[test]
    fn decode_ansi_c_hex() {
        assert_eq!(decode("$'\\x72\\x6d' -rf /"), "rm -rf /");
    }

    #[test]
    fn decode_ansi_c_octal() {
        assert_eq!(decode("$'\\162\\155' -rf /"), "rm -rf /");
    }

    #[test]
    fn decode_ansi_c_unicode_u() {
        assert_eq!(decode("$'\\u0072\\u006d' -rf /"), "rm -rf /");
    }

    #[test]
    fn decode_ansi_c_unicode_big_u() {
        assert_eq!(n7_decode_ansi_c("$'\\U00000041'"), "A");
    }

    #[test]
    fn decode_var_indirection() {
        assert_eq!(decode("${!var}"), "${var}");
    }

    #[test]
    fn decode_backslash() {
        assert_eq!(decode(r"r\m -rf"), "rm -rf");
    }

    #[test]
    fn decode_ifs() {
        assert_eq!(decode("rm${IFS}-rf"), "rm -rf");
    }

    #[test]
    fn decode_identity() {
        assert_eq!(decode("cargo test"), "cargo test");
    }

    // --- strip tests ---

    #[test]
    fn strip_quotes() {
        assert_eq!(strip(r#""rm" -rf /"#), "rm -rf /");
    }

    #[test]
    fn strip_braces() {
        assert_eq!(strip("{rm,-rf,/}"), "rm -rf /");
    }

    #[test]
    fn strip_command_sub() {
        assert_eq!(strip("$(rm -rf /)"), "rm -rf /)");
    }

    // --- cross-phase: decode + strip composition ---

    #[test]
    fn cross_phase_indirection_then_braces() {
        // decode: N5 ${!var} → ${var}, strip: N4 ${var} → $var
        assert_eq!(strip(&decode("${!var}")), "$var");
    }

    #[test]
    fn cross_phase_backslash_then_quotes() {
        // decode: N6 strips \m, strip: N1 strips quotes
        assert_eq!(strip(&decode("'r\\m' -rf /")), "rm -rf /");
    }

    #[test]
    fn cross_phase_ifs_then_braces() {
        // decode: N3 IFS→space, strip: N4 braces→spaces
        assert_eq!(strip(&decode("{rm,${IFS}-rf}")), "rm  -rf");
    }

    // --- n7 internals ---

    #[test]
    fn n7_single_hex() {
        assert_eq!(n7_decode_ansi_c("$'\\x41'"), "A");
    }

    #[test]
    fn n7_single_octal() {
        assert_eq!(n7_decode_ansi_c("$'\\101'"), "A");
    }

    #[test]
    fn n7_mixed_hex_octal() {
        assert_eq!(n7_decode_ansi_c("$'\\x72\\155'"), "rm");
    }

    #[test]
    fn n7_mixed_hex_unicode() {
        assert_eq!(n7_decode_ansi_c("$'\\x72\\u006d'"), "rm");
    }

    #[test]
    fn n7_passthrough() {
        assert_eq!(n7_decode_ansi_c("normal command"), "normal command");
    }

    #[test]
    fn n7_unterminated() {
        assert_eq!(n7_decode_ansi_c("$'unterminated"), "$'unterminated");
    }

    #[test]
    fn n7_invalid_hex() {
        assert_eq!(n7_decode_ansi_c("$'\\xZZ'"), "$'\\xZZ'");
    }

    #[test]
    fn n7_empty() {
        assert_eq!(n7_decode_ansi_c("$''"), "$''");
    }

    #[test]
    fn n7_mixed_valid_invalid() {
        let result = n7_decode_ansi_c("$'\\x72\\xZZ'");
        assert!(result.starts_with('r'));
    }

    // --- n6 internals ---

    #[test]
    fn n6_multiple() {
        assert_eq!(n6_strip_backslash(r"g\i\t push"), "git push");
    }

    #[test]
    fn n6_non_alpha_kept() {
        assert_eq!(n6_strip_backslash(r"echo\ hello"), r"echo\ hello");
    }

    #[test]
    fn n6_trailing_kept() {
        assert_eq!(n6_strip_backslash("test\\"), "test\\");
    }

    #[test]
    fn n6_before_digit() {
        assert_eq!(n6_strip_backslash("r\\1m"), "r1m");
    }

    #[test]
    fn n6_before_dollar_kept() {
        assert_eq!(n6_strip_backslash("r\\$m"), "r\\$m");
    }

    #[test]
    fn n6_double_backslash() {
        assert_eq!(n6_strip_backslash("r\\\\m"), "r\\m");
    }

    // --- other internals ---

    #[test]
    fn n3_bare_ifs() {
        assert_eq!(n3_strip_ifs("rm$IFS-rf"), "rm -rf");
    }

    #[test]
    fn n5_preserves_normal_var() {
        assert_eq!(n5_strip_var_indirection("${var}"), "${var}");
    }
}
