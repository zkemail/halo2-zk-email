use fancy_regex::Regex;
use itertools::Itertools;

pub fn get_substr(input_str: &str, regexes: &[String]) -> (usize, String) {
    let regexes = regexes
        .into_iter()
        .map(|raw| Regex::new(&raw).unwrap())
        .collect_vec();
    let mut start = 0;
    let mut substr = input_str;
    // println!("first regex {}", regexes[0]);
    for regex in regexes.into_iter() {
        // println!(r"regex {}", regex);
        let substr_match = regex.find(substr).unwrap().unwrap();
        start += substr_match.start();
        substr = substr_match.as_str();
    }
    // println!("substr {}", substr);
    (start, substr.to_string())
}
