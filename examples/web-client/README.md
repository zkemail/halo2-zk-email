# Web client
This is an example web client for tests and benchmarks of halo2_zk_email.

## Setup
1. Ensure that `zkemail` CLI is already installed.
2. Under the `web-client` directory, run `chmod +x setup.bash` and `./setup.bash`
3. Open http://localhost:3000 on Google Chrome browser.

## Tests
Please set up the local web server as described above and go to http://localhost:3000 first.
To run a test of a valid case, press the "Run test" button after "Run test of valid case".
To run a test of an invalid case in which a public key is modified, press the "Run test" button after "Run test of invalid case (invalid public key)".

## Bench
Please set up the local web server as described above and go to http://localhost:3000 first.
To measure a benchmark, enter the number of bench times in the form immediately after the "Select an email file." button and press "Run bench" below it.
To use your email in the benchmark, upload it by pressing the "Select an email file." button.
Its email header must be less than 1024 bytes, and its email body must be less than 512 bytes and satisfy the regex of "Hello (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+!". 

## Acknowledgment
The web client and rust wasm code refers to [halo2 wasm guide](https://zcash.github.io/halo2/user/wasm-port.html) and [this repository](https://github.com/nalinbhardwaj/zordle/tree/main/test-client).
