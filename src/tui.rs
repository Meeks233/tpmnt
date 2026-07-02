//! Tiny, dependency-free interactive helpers: a numbered-checklist multi-select
//! and a yes/no confirm. Deliberately *not* a raw-mode full-screen TUI — that
//! would pull in crossterm/termion and bloat the dependency tree this project
//! keeps lean for distro packaging. Instead we print a numbered list and read a
//! single reply line (`1 3 5`, `2-4`, `all`), which is plenty for "pick which to
//! delete" and stays scriptable/pipe-safe.
//!
//! All prompts render to **stderr** so stdout stays clean for `--json` consumers.

use std::io::{IsTerminal, Write};

use crate::error::{Code, Error, Result};

/// May we prompt? Not `--non-interactive`, and both stdin and stdout are TTYs.
pub fn interactive(non_interactive: bool) -> bool {
    !non_interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// One row in a multi-select list: a primary `label` and a dim `detail`.
pub struct Item {
    pub label: String,
    pub detail: String,
}

impl Item {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Item {
        Item {
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// Present `items` as a numbered checklist and read the user's picks. Returns the
/// chosen indices (0-based), possibly empty (an empty reply = cancel). Call only
/// when [`interactive`] is true.
pub fn multiselect(title: &str, items: &[Item]) -> Result<Vec<usize>> {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{title}");
    for (i, it) in items.iter().enumerate() {
        if it.detail.is_empty() {
            let _ = writeln!(err, "  {:>2}) {}", i + 1, it.label);
        } else {
            let _ = writeln!(err, "  {:>2}) {}   {}", i + 1, it.label, it.detail);
        }
    }
    let _ = write!(
        err,
        "select numbers (e.g. `1 3`, `2-4`, `all`; empty = cancel): "
    );
    let _ = err.flush();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::EInternal, format!("read selection: {e}")))?;
    Ok(parse_selection(&line, items.len()))
}

/// Parse a selection reply into 0-based indices within `0..n`. Accepts
/// space/comma-separated 1-based numbers, inclusive `lo-hi` ranges, and
/// `a`/`all`. Non-numeric or out-of-range tokens are ignored; duplicates
/// collapse; first-seen order is preserved so the caller can echo it back.
pub fn parse_selection(input: &str, n: usize) -> Vec<usize> {
    let t = input.trim();
    if t.eq_ignore_ascii_case("a") || t.eq_ignore_ascii_case("all") {
        return (0..n).collect();
    }
    let mut out: Vec<usize> = Vec::new();
    let push = |k1: usize, out: &mut Vec<usize>| {
        if (1..=n).contains(&k1) {
            let idx = k1 - 1;
            if !out.contains(&idx) {
                out.push(idx);
            }
        }
    };
    for tok in t.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = tok.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<usize>(), hi.trim().parse::<usize>()) {
                // Clamp the upper bound so a huge `hi` (e.g. `1-99999999999`) can't spin
                // the loop for billions of iterations; out-of-range indices were already
                // dropped by `push`, so behavior for valid input is unchanged.
                for k in lo..=hi.min(n) {
                    push(k, &mut out);
                }
                continue;
            }
        }
        if let Ok(k) = tok.parse::<usize>() {
            push(k, &mut out);
        }
    }
    out
}

/// Prompt on stderr and read one line from stdin (trimmed of the trailing
/// newline). Echo is *not* suppressed — matching the project's existing plaintext
/// PIN prompt, since tpmnt takes no terminal/`rpassword` dependency.
pub fn prompt_line(prompt: &str) -> Result<String> {
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::EInternal, format!("read input: {e}")))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// A yes/no confirmation on stderr. Only an explicit `y`/`yes` (any case) is
/// treated as consent; everything else (including empty) is a no.
pub fn confirm(prompt: &str) -> Result<bool> {
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::EInternal, format!("read confirmation: {e}")))?;
    let a = line.trim().to_ascii_lowercase();
    Ok(a == "y" || a == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_numbers_space_and_comma() {
        assert_eq!(parse_selection("1 3 5", 5), vec![0, 2, 4]);
        assert_eq!(parse_selection("1,3 , 5", 5), vec![0, 2, 4]);
        assert_eq!(parse_selection("  2 ", 5), vec![1]);
    }

    #[test]
    fn parse_ranges_and_mixed() {
        assert_eq!(parse_selection("2-4", 5), vec![1, 2, 3]);
        assert_eq!(parse_selection("1 3-4", 5), vec![0, 2, 3]);
        // Reversed range yields nothing (lo>hi), not a panic.
        assert_eq!(parse_selection("4-2", 5), Vec::<usize>::new());
    }

    #[test]
    fn parse_huge_upper_bound_is_clamped_not_a_hang() {
        // A giant `hi` must be clamped to `n`, not iterated billions of times.
        assert_eq!(parse_selection("1-99999999999", 3), vec![0, 1, 2]);
        assert_eq!(parse_selection("2-18446744073709551615", 3), vec![1, 2]);
    }

    #[test]
    fn parse_all_keyword() {
        assert_eq!(parse_selection("all", 3), vec![0, 1, 2]);
        assert_eq!(parse_selection("A", 3), vec![0, 1, 2]);
        assert_eq!(parse_selection("all", 0), Vec::<usize>::new());
    }

    #[test]
    fn parse_ignores_out_of_range_and_garbage_and_dedupes() {
        // 0 and 9 are out of 1..=5; "x" is garbage; 3 repeats.
        assert_eq!(parse_selection("0 3 9 x 3", 5), vec![2]);
        assert_eq!(parse_selection("", 5), Vec::<usize>::new());
        // A range partly out of bounds keeps only the in-bounds part.
        assert_eq!(parse_selection("3-99", 5), vec![2, 3, 4]);
    }
}
