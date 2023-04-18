use fancy_regex::Regex;
use itertools::Itertools;

pub fn get_substr(input_str: &str, regexes: &[String]) -> Option<(usize, String)> {
    let regexes = regexes
        .into_iter()
        .map(|raw| Regex::new(&raw).unwrap())
        .collect_vec();
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
    Some((start, substr.to_string()))
}
