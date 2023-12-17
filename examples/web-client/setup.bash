#!/bin/bash
cd `dirname $0`
zkemail gen-params --k 13 --params-path ./public/params.bin
zkemail gen-keys --params-path ./public/params.bin --circuit-config-path ./public/wasm_email_verify.config --email-path ./public/demo_wasm.eml --pk-path ./public/bench.pk --vk-path ./public/bench.vk
yarn build:wasm
yarn build
yarn start