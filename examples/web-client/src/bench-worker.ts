import { expose, proxy } from 'comlink';

type MultiThread = typeof import('halo2-zk-email');

/**
 * The public input of the default email verification circuit.
 */
interface DefaultEmailVerifyPublicInput {
    // A decimal string of a commitment of the signature defined as poseidon(rsaSign).
    sign_commit: string,
    // A decimal string of the poseidon hash of the `n` parameter in the RSA public key. (The e parameter is fixed to 65537.)
    public_key_hash: string,
    // The start position of the substrings in the email header.
    header_starts: number[],
    // The substrings in the email header.
    header_substrs: string[],
    // The start position of the substrings in the email body.
    body_starts: number[],
    // The substrings in the email body.
    body_substrs: string[],
}

/**
 * Fetch the trusted setup parameters for k=13.
 * @returns The trusted setup parameters.
 */
export async function fetchParams() {
    const response = await fetch('http://localhost:3000/params.bin');
    const bytes = await response.arrayBuffer();
    const params = new Uint8Array(bytes);
    return params;
}

/**
 * Fetch the verification key of the default email verification circuit.
 * @returns The verification key.
 */
export async function fetchVk() {
    const response = await fetch('http://localhost:3000/bench.vk');
    const bytes = await response.arrayBuffer();
    const vk = new Uint8Array(bytes);
    return vk;
}

/**
 * Run a valid test of the default email verification circuit.
 * @param emailStr The email string to be verified.
 * @returns The result of the verification.
 */
export async function runValidTest(emailStr: string) {
    const multiThread = await initMultiThread();
    await fetchSaveConfigs(multiThread);
    const params = await fetchParams();
    console.log(params);
    const publicKey = await fetchPublicKey(multiThread, emailStr);
    const pkChunks = await fetchPkChunks();
    console.log(pkChunks);
    if (pkChunks == null) {
        throw new Error("pkChunks is null");
    }
    const vk = await fetchVk();
    const [proof, publicInput] = proveEmail(multiThread, params, pkChunks, emailStr, publicKey);
    console.log(proof);
    console.log(publicInput);
    const isValid = verifyEmailProof(multiThread, params, vk, proof, publicInput);
    console.log(isValid);
    return isValid;
}

/**
 * Run an invalid test of the default email verification circuit.
 * @param emailStr The email string to be verified.
 * @returns The result of the verification.
 */
export async function runInvalidTest(emailStr: string) {
    const multiThread = await initMultiThread();
    await fetchSaveConfigs(multiThread);
    const params = await fetchParams();
    console.log(params);
    let publicKey = await fetchPublicKey(multiThread, emailStr);
    publicKey = '0x' + 'f'.repeat(publicKey.length - 2);
    const pkChunks = await fetchPkChunks();
    console.log(pkChunks);
    if (pkChunks == null) {
        throw new Error("pkChunks is null");
    }
    const vk = await fetchVk();
    const [proof, publicInput] = proveEmail(multiThread, params, pkChunks, emailStr, publicKey);
    console.log(proof);
    console.log(publicInput);
    const isValid = verifyEmailProof(multiThread, params, vk, proof, publicInput);
    console.log(isValid);
    return isValid;
}

/**
 * Run a benchmark of the default email verification circuit.
 * @param emailStr The email string to be verified.
 * @param times The number of times to run the benchmark.
 * @returns The benchmark results as a proxy of comlink.
 */
export async function runBench(emailStr: string, times: number) {
    const multiThread = await initMultiThread();
    await fetchSaveConfigs(multiThread);
    const params = await fetchParams();
    console.log(params);
    const publicKey = await fetchPublicKey(multiThread, emailStr);
    const pkChunks = await fetchPkChunks();
    console.log(pkChunks);
    if (pkChunks == null) {
        throw new Error("pkChunks is null");
    }
    const vk = await fetchVk();
    const indexes = [];
    const benches: number[] = [];
    console.log("init");
    for (let i = 0; i < times; i++) {
        indexes.push(i);
        const start = performance.now();
        const [proof, publicInput] = proveEmail(multiThread, params, pkChunks, emailStr, publicKey);
        console.log(proof);
        console.log(publicInput);
        const sub = performance.now() - start;
        console.log(`index: ${i}, bench: ${sub} ms`);
        benches.push(sub);
        const isValid = verifyEmailProof(multiThread, params, vk, proof, publicInput);
        console.log(isValid);
        if (!isValid) {
            throw new Error("verify failed");
        }
    }
    return proxy({
        indexes: indexes,
        benches: benches
    })
}

/**
 * Prove the email string.
 * @param multiThread The multi-threaded WASM module.
 * @param params The trusted setup parameters.
 * @param pkChunks The chunks of the proving key.
 * @param emailStr The email string to be verified.
 * @param publicKey The RSA public key.
 * @returns The hex string of the proof and the public input.
*/
export function proveEmail(multiThread: MultiThread, params: Uint8Array, pkChunks: Uint8Array[], emailStr: string, publicKey: string): [string, DefaultEmailVerifyPublicInput] {
    const proofOut = multiThread.prove_email(params, pkChunks, emailStr, publicKey);
    return [proofOut[0], proofOut[1]];
}

/**
 * Verify the proof.
 * @param multiThread The multi-threaded WASM module.
 * @param params The trusted setup parameters.
 * @param vk The verification key.
 * @param proof The hex string of the proof.
 * @param publicInput The public input.
 * @returns The result of the verification.
*/
export function verifyEmailProof(multiThread: MultiThread, params: Uint8Array, vk: Uint8Array, proof: string, publicInput: DefaultEmailVerifyPublicInput): boolean {
    const isValid = multiThread.verify_email_proof(params, vk, proof, publicInput);
    return isValid;
}

/**
 * Fetch the RSA public key from the Google DNS server.
 * @param multiThread The multi-threaded WASM module.
 * @param emailStr The email string to be verified.
 * @returns The RSA public key.
*/
export async function fetchPublicKey(multiThread: MultiThread, emailStr: string) {
    console.log(emailStr);
    const url = multiThread.google_dns_url_from_email(emailStr);
    console.log(url);
    const response = await fetch(url);
    const responseText = await response.text();
    console.log(responseText);
    const publicKey = multiThread.fetch_rsa_public_key(responseText);
    return publicKey;
}


/**
 * Fetch the chunks of the proving key.
 * @returns The chunks of the proving key.
*/
export async function fetchPkChunks() {
    const response = await fetch('http://localhost:3000/bench.pk');
    if (response.body == null) {
        return;
    }
    const chunks: Uint8Array[] = [];
    let maxSize = 0;
    const reader = response.body.getReader();

    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        chunks.push(value);
        maxSize += value.byteLength;
    }
    console.log(maxSize);

    return chunks;
}

/**
 * Fetch and save the configurations for the default email verification circuit.
 * You must call this function once for each `multiThread` before calling any other functions in this module.
 * @param multiThread The multi-threaded WASM module.
*/
export async function fetchSaveConfigs(multiThread: MultiThread) {
    const configParams = await fetchConfigParams();
    let configParamsJson = JSON.parse(configParams);
    const bodyHashAllstrDef = await fetchRegexFile(configParamsJson.header_config.bodyhash_allstr_filepath);
    const bodyHashSubstrDef = await fetchRegexFile(configParamsJson.header_config.bodyhash_substr_filepath);
    console.log(bodyHashAllstrDef);
    console.log(bodyHashSubstrDef);
    const headerAllstrDefs = [];
    for (const filePath of configParamsJson.header_config.allstr_filepathes) {
        headerAllstrDefs.push(await fetchRegexFile(filePath));
    }
    console.log(headerAllstrDefs);
    const headerSubstrDefs = [];
    for (const filePathes of configParamsJson.header_config.substr_filepathes) {
        const defs = [];
        for (const filePath of filePathes) {
            defs.push(await fetchRegexFile(filePath));
        }
        headerSubstrDefs.push(JSON.stringify(defs));
    }
    console.log(headerSubstrDefs);
    const bodyAllstrDefs = [];
    for (const filePath of configParamsJson.body_config.allstr_filepathes) {
        bodyAllstrDefs.push(await fetchRegexFile(filePath));
    }
    console.log(bodyAllstrDefs);
    const bodySubstrDefs = [];
    for (const filePathes of configParamsJson.body_config.substr_filepathes) {
        const defs = [];
        for (const filePath of filePathes) {
            defs.push(await fetchRegexFile(filePath));
        }
        bodySubstrDefs.push(JSON.stringify(defs));
    }
    console.log(bodySubstrDefs);
    multiThread.init_configs(configParams, bodyHashAllstrDef, bodyHashSubstrDef, headerAllstrDefs, headerSubstrDefs, bodyAllstrDefs, bodySubstrDefs);
}

async function fetchConfigParams() {
    const config_params = await (await fetch('http://localhost:3000/wasm_email_verify.config')).text();
    // localStorage.setItem("EMAIL_VERIFY_CONFIG", config_params);
    const config_params_json = JSON.parse(config_params);
    console.log(config_params_json);
    return config_params;
}

async function fetchRegexFile(filePath: string) {
    const response = await fetch(`http://localhost:3000/${getFilename(filePath)}`);
    const regexConfig = await response.text();
    return regexConfig;
}

function getFilename(filePath: string) {
    const parts = filePath.split('/');
    return parts.pop();
}

/**
 * Initialize the multi-threaded WASM module.
 * @returns The multi-threaded WASM module.
 */
export async function initMultiThread() {
    const multiThread = await import(
        'halo2-zk-email'
    );
    console.log(multiThread);
    await multiThread.default();
    console.log(`hardware: ${navigator.hardwareConcurrency}`);
    await multiThread.initThreadPool(4);
    return multiThread;
}



const exports = {
    fetchParams,
    fetchVk,
    runValidTest,
    runInvalidTest,
    runBench,
    fetchSaveConfigs,
    fetchPkChunks,
    fetchPublicKey,
    proveEmail,
    verifyEmailProof,
    initMultiThread,
};
expose(exports);
export type BenchWorker = typeof exports;
