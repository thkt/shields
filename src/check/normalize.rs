/// Normalize a command string to defeat common bypass techniques.
/// Order matters: N7 before N1 (needs quotes), N5 before N4 (needs braces).
pub fn normalize(command: &str) -> String {
    let mut cmd = command.to_string();
    // Order matters: N7 needs quotes intact (before N1), N5 needs braces intact (before N4)
    if cmd.contains("$'") {
        cmd = n7_decode_ansi_c(&cmd);
    }
    if cmd.contains("${!") {
        cmd = n5_strip_var_indirection(&cmd);
    }
    if cmd.contains(['\'', '"', '`']) {
        cmd = n1_strip_quotes(&cmd);
    }
    if cmd.contains("$(") {
        cmd = n2_strip_command_sub(&cmd);
    }
    if cmd.contains("IFS") {
        cmd = n3_strip_ifs(&cmd);
    }
    if cmd.contains(['{', '}', ',']) {
        cmd = n4_strip_braces(&cmd);
    }
    if cmd.contains('\\') {
        cmd = n6_strip_backslash(&cmd);
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
        // Match $'...' ANSI-C quoting
        if i + 2 < len && bytes[i] == b'$' && bytes[i + 1] == b'\'' {
            let start = i;
            i += 2; // skip $'
            let mut decoded = String::new();
            let mut valid = false;

            while i < len && bytes[i] != b'\'' {
                if i + 1 < len && bytes[i] == b'\\' {
                    // Hex: \xNN
                    if i + 3 < len && bytes[i + 1] == b'x' {
                        let hex = &cmd[i + 2..i + 4];
                        if let Ok(byte) = u8::from_str_radix(hex, 16) {
                            decoded.push(byte as char);
                            i += 4;
                            valid = true;
                            continue;
                        }
                    }
                    // Octal: \NNN (1-3 octal digits)
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
                            decoded.push(byte as char);
                            i = oct_end;
                            valid = true;
                            continue;
                        }
                    }
                }
                decoded.push(bytes[i] as char);
                i += 1;
            }

            if valid && i < len && bytes[i] == b'\'' {
                result.push_str(&decoded);
                i += 1; // skip closing '
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- N1: Quote removal ---

    // T-004: single quotes
    #[test]
    fn t004_n1_single_quotes_removed() {
        assert_eq!(normalize("'rm' -rf /"), "rm -rf /");
    }

    #[test]
    fn n1_double_quotes_removed() {
        assert_eq!(n1_strip_quotes(r#""rm" -rf /"#), "rm -rf /");
    }

    #[test]
    fn n1_backticks_removed() {
        assert_eq!(n1_strip_quotes("`rm` -rf /"), "rm -rf /");
    }

    #[test]
    fn n1_mixed_quotes() {
        assert_eq!(n1_strip_quotes("'r\"m` -rf"), "rm -rf");
    }

    // --- N2: Command substitution removal ---

    // T-005
    #[test]
    fn t005_n2_command_sub_removed() {
        assert_eq!(normalize("$(rm -rf /)"), "rm -rf /)");
    }

    #[test]
    fn n2_preserves_dollar_without_paren() {
        assert_eq!(n2_strip_command_sub("$VAR"), "$VAR");
    }

    // --- N3: IFS expansion ---

    // T-006
    #[test]
    fn t006_n3_ifs_braces_replaced() {
        assert_eq!(normalize("rm${IFS}-rf"), "rm -rf");
    }

    #[test]
    fn n3_ifs_bare_replaced() {
        assert_eq!(n3_strip_ifs("rm$IFS-rf"), "rm -rf");
    }

    // --- N4: Brace expansion ---

    // T-007
    #[test]
    fn t007_n4_braces_expanded() {
        assert_eq!(normalize("{rm,-rf,/}"), "rm -rf /");
    }

    // --- N5: Variable indirection ---

    // T-008: N5 transform strips `!` from `${!var}`
    #[test]
    fn t008_n5_indirection_stripped() {
        assert_eq!(n5_strip_var_indirection("${!var}"), "${var}");
    }

    #[test]
    fn n5_preserves_normal_var() {
        assert_eq!(n5_strip_var_indirection("${var}"), "${var}");
    }

    #[test]
    fn n5_full_normalize_strips_braces_too() {
        // After N5 → N4, ${!var} → ${var} → $var
        assert_eq!(normalize("${!var}"), "$var");
    }

    // --- N6: Backslash removal (NEW) ---

    // T-009
    #[test]
    fn t009_n6_backslash_before_alpha_removed() {
        assert_eq!(normalize(r"r\m -rf"), "rm -rf");
    }

    #[test]
    fn n6_multiple_backslashes() {
        assert_eq!(n6_strip_backslash(r"g\i\t push"), "git push");
    }

    #[test]
    fn n6_backslash_before_non_alpha_kept() {
        assert_eq!(n6_strip_backslash(r"echo\ hello"), r"echo\ hello");
    }

    #[test]
    fn n6_trailing_backslash_kept() {
        assert_eq!(n6_strip_backslash("test\\"), "test\\");
    }

    // --- N7: ANSI-C escape decode (hex + octal) ---

    // T-010: hex
    #[test]
    fn t010_n7_hex_decoded() {
        assert_eq!(normalize("$'\\x72\\x6d' -rf /"), "rm -rf /");
    }

    #[test]
    fn n7_single_hex_char() {
        assert_eq!(n7_decode_ansi_c("$'\\x41'"), "A");
    }

    #[test]
    fn n7_non_hex_preserved() {
        assert_eq!(n7_decode_ansi_c("normal command"), "normal command");
    }

    #[test]
    fn n7_incomplete_pattern_preserved() {
        assert_eq!(n7_decode_ansi_c("$'unterminated"), "$'unterminated");
    }

    // SEC-06: octal decode
    #[test]
    fn n7_octal_rm_decoded() {
        // \162 = 'r', \155 = 'm'
        assert_eq!(normalize("$'\\162\\155' -rf /"), "rm -rf /");
    }

    #[test]
    fn n7_single_octal_char() {
        // \101 = 'A'
        assert_eq!(n7_decode_ansi_c("$'\\101'"), "A");
    }

    #[test]
    fn n7_mixed_hex_octal() {
        // \x72 = 'r', \155 = 'm'
        assert_eq!(n7_decode_ansi_c("$'\\x72\\155'"), "rm");
    }

    #[test]
    fn n7_octal_git() {
        // \147 = 'g', \151 = 'i', \164 = 't'
        assert_eq!(normalize("$'\\147\\151\\164' push"), "git push");
    }

    // --- Combined transforms ---

    // T-011: both raw and normalized are checked (normalize doesn't destroy valid commands)
    #[test]
    fn t011_identity_for_normal_command() {
        assert_eq!(normalize("cargo test"), "cargo test");
    }

    #[test]
    fn combined_n1_n6() {
        assert_eq!(normalize("'r\\m' -rf /"), "rm -rf /");
    }

    #[test]
    fn combined_n3_n4() {
        assert_eq!(normalize("{rm,${IFS}-rf}"), "rm  -rf");
    }
}
