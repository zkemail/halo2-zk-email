# halo2-zk-email

Email verification circuit in halo2

## Description

Generate regexes by calling the CLI in zk-regex with a specific string, and copying over the halo2_regex_lookup_js.txt file. The first line is total states, second line is accept states.

test_regexes/regex_bh.txt is the body hash regex.

```
cargo build
cargo test
```

To test just DNS get of a domain, run `cargo run --bin parse_email -- --nocapture`.

TODO:

-   Move test dependencies to dev section
