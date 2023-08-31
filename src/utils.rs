use crate::*;
use fancy_regex::Regex;
use itertools::Itertools;
use std::fs::File;

/// Compute expected masked chars and substring ids from the given list of the substrings and their start positions.
///
/// # Arguments
/// * `max_byte_size` - The maximum byte size of the input string.
/// * `substrs` - A list of the substrings and their start positions.
/// # Return values
/// Return a tuple of the expected masked chars and substring ids.
pub fn get_expected_substr_chars_and_ids(max_byte_size: usize, substrs: &[Option<(usize, String)>]) -> (Vec<u8>, Vec<u8>) {
    let mut expected_masked_chars = vec![0u8; max_byte_size];
    let mut expected_substr_ids = vec![0u8; max_byte_size]; // We only support up to 256 substring patterns.
    for (substr_idx, m) in substrs.iter().enumerate() {
        if let Some((start, chars)) = m {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = *char;
                expected_substr_ids[start + idx] = substr_idx as u8 + 1;
            }
        }
    }
    (expected_masked_chars, expected_substr_ids)
}

/// Extract substrings and their start positions from the given header and body strings.
///
/// # Arguments
/// * `header_str` - The header string.
/// * `body_str` - The body string.
/// * `header_substr_regexes` - A list of the substring regexes for the header string.
/// * `body_substr_regexes` - A list of the substring regexes for the body string.
/// # Return values
/// Return a tuple of the extracted substrings and their start positions.
pub fn get_email_substrs(
    header_str: &str,
    body_str: &str,
    header_substr_regexes: Vec<Vec<String>>,
    body_substr_regexes: Vec<Vec<String>>,
) -> (Vec<Option<(usize, String)>>, Vec<Option<(usize, String)>>) {
    let header_substrs = header_substr_regexes
        .iter()
        .map(|raws| {
            let raws = raws.into_iter().map(|raw| format!(r"{}", raw)).collect_vec();
            get_substr(&header_str, raws.as_slice())
        })
        .collect_vec();
    let body_substrs = body_substr_regexes
        .iter()
        .map(|raws| {
            let raws = raws.into_iter().map(|raw| format!(r"{}", raw)).collect_vec();
            get_substr(&body_str, raws.as_slice())
        })
        .collect_vec();
    (header_substrs, body_substrs)
}

/// Extract a substring and its start position from the given input string.
///
/// # Arguments
/// * `input_str` - The input string.
/// * `regexes` - A list of the substring regexes.
/// # Return values
/// Return a tuple of the extracted substring and its start position.
pub fn get_substr(input_str: &str, regexes: &[String]) -> Option<(usize, String)> {
    let regexes = regexes.into_iter().map(|raw| Regex::new(&raw).unwrap()).collect_vec();
    let mut start = 0;
    let mut substr = input_str;
    // println!("first regex {}", regexes[0]);
    for regex in regexes.into_iter() {
        // println!(r"regex {}", regex);
        match regex.find(substr).unwrap() {
            Some(m) => {
                start += m.start();
                substr = m.as_str();
            }
            None => {
                return None;
            }
        };
    }
    // println!("substr {}", substr);
    // println!("start {}", start);
    Some((start, substr.to_string()))
}
