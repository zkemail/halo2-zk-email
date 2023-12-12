import { expose, proxy } from 'comlink';

type MultiThread = typeof import('halo2-zk-email');

export async function fetchParams() {
    const response = await fetch('http://localhost:3000/params.bin');
    const bytes = await response.arrayBuffer();
    const params = new Uint8Array(bytes);
    return params;
}



export async function fetchPublicKey(emailStr: string) {
    // const multiThread = await import(
    //     'halo2-zk-email'
    // );
    // console.log(multiThread);
    // await multiThread.default();
    // await multiThread.initThreadPool(4);
    const multiThread = await initMultiThread();
    console.log(emailStr);
    const url = multiThread.google_dns_url_from_email(emailStr);
    console.log(url);
    const response = await fetch(url);
    const responseText = await response.text();
    console.log(responseText);
    const publicKey = multiThread.fetch_rsa_public_key(responseText);
    return publicKey;
}

export async function genProvingKey(params: Uint8Array, emailStr: string, publicKey: string) {
    // const multiThread = await import(
    //     'halo2-zk-email'
    // );
    // console.log(multiThread);
    // await multiThread.default();
    // console.log(`hardware: ${navigator.hardwareConcurrency}`);
    // await multiThread.initThreadPool(4);
    const multiThread = await fetchSaveConfigs();
    console.log(publicKey);
    await multiThread.gen_proving_key(params, emailStr, publicKey);
}

// export async function fetchPk() {
//     const response = await fetch('http://localhost:3000/bench.pk');
//     // console.log(await response.blob());
//     if (response.body == null) {
//         return;
//     }
//     const chunks: Uint8Array[] = [];
//     let maxSize = 0;
//     let idx = 0;
//     const reader = response.body.getReader();

//     while (true) {
//         const { done, value } = await reader.read();
//         if (done) {
//             break;
//         }
//         // console.log(value.toString());
//         // localStorage.setItem(`pk_chunk_${idx}`, value.toString());
//         chunks.push(value);
//         maxSize += value.byteLength;
//     }
//     console.log(maxSize);

//     // reader.read().then(function pump({ done, value }) {
//     //     console.log(done, value);
//     //     if (!done) {
//     //         segments.push(value);
//     //         maxSize += value.byteLength;
//     //         reader.read().then(pump);
//     //     }
//     // });
//     // const whole = new Uint8Array(0);
//     // console.log(whole);
//     // let pos = 0;
//     // for (const chunk of chunks) {
//     //     whole.set(new Uint8Array(chunk), pos);
//     //     pos += chunk.byteLength;
//     // }

//     // return whole;
//     //     // for await (chunk of response.body) {
//     //     //     console.log(chunk);
//     //     // }
//     //     // const blob = await response.blob();
//     //     // const bytes = await blob.arrayBuffer();
//     //     // console.log(bytes);
//     //     // const pk = new Uint8Array(bytes);
//     //     // console.log(pk);
//     //     // return pk;
//     return chunks;
// }

// export async function fetchVk() {
//     const response = await fetch('http://localhost:3000/bench.vk');
//     const bytes = await response.arrayBuffer();
//     const vk = new Uint8Array(bytes);
//     return vk;
// }

async function fetchSaveConfigs() {
    // const multiThread = await import(
    //     'halo2-zk-email'
    // );
    // await multiThread.default();
    // await multiThread.initThreadPool(4);
    const multiThread = await initMultiThread();
    const configParams = await fetchConfigParams();
    let configParamsJson = JSON.parse(configParams);
    // localStorage.setItem(configParamsJson.header_config.bodyhash_allstr_filepath, await fetchRegexFile(configParamsJson.header_config.bodyhash_allstr_filepath));
    // localStorage.setItem(configParamsJson.header_config.bodyhash_substr_filepath, await fetchRegexFile(configParamsJson.header_config.bodyhash_substr_filepath));
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
    return multiThread;
}

async function fetchConfigParams() {
    const config_params = await (await fetch('http://localhost:3000/wasm_email_verify.config')).text();
    // localStorage.setItem("EMAIL_VERIFY_CONFIG", config_params);
    const config_params_json = JSON.parse(config_params);
    console.log(config_params_json);
    return config_params;
}

async function fetchRegexFile(filePath: string) {
    const response = await fetch(`http://localhost:3000/${filePath}`);
    const regexConfig = await response.text();
    return regexConfig;
}

// export async function fetchParams() {
//     /* eslint-disable-next-line no-restricted-globals */
//     console.log(self);
//     console.log(window);
//     /* eslint-disable-next-line no-restricted-globals */
//     window = self;
//     console.log(window);
//     const multiThread = await import(
//         'halo2-zk-email'
//     );
//     console.log(multiThread);
//     await multiThread.default();
//     console.log(`hardware: ${navigator.hardwareConcurrency}`);
//     await multiThread.initThreadPool(4);
//     const params = await multiThread.fetch_proving_key("http://localhost:3000/params.bin");
//     console.log(params);
//     return params;
// }

// export async function fetchPk() {
//     /* eslint-disable-next-line no-restricted-globals */
//     window = self;
//     const multiThread = await import(
//         'halo2-zk-email'
//     );
//     console.log(multiThread);
//     await multiThread.default();
//     console.log(`hardware: ${navigator.hardwareConcurrency}`);
//     await multiThread.initThreadPool(4);
//     const pk = await multiThread.fetch_public_key("http://localhost:3000/bench.pk");
//     console.log(pk);
//     return pk;
// }

// async function bench(multiThread: typeof import("halo2-rsa"), bits_len: number, msg: Uint8Array, times: number) {
//     const privateKey = multiThread.sample_rsa_private_key(bits_len);
//     const publicKey = multiThread.generate_rsa_public_key(privateKey);
//     const signature = multiThread.sign(privateKey, msg);
//     const indexes = [];
//     const benches: number[] = [];
//     const params = await fetch_params();
//     const pk = await fetch_pk();
//     const vk = await fetch_vk();
//     console.log("init");
//     for (let i = 0; i < times; i++) {
//         indexes.push(i);
//         const multiThread = await import(
//             'halo2-rsa'
//         );
//         const initOutput = await multiThread.default();
//         const builder = await multiThread.initThreadPool(navigator.hardwareConcurrency);
//         console.log(builder);
//         const start = performance.now();
//         const proof = multiThread.prove_pkcs1v15_2048_1024_circuit(params, pk, publicKey, msg, signature);
//         const sub = performance.now() - start;
//         console.log(`index: ${ i }, bench: ${ sub } ms`);
//         benches.push(sub);
//         const isValid = multiThread.verify_pkcs1v15_2048_1024_circuit(params, vk, proof);
//         console.log(isValid);
//         // initOutput.__wbg_wbg_rayon_poolbuilder_free(navigator.hardwareConcurrency);
//     }
//     return proxy({
//         indexes: indexes,
//         benches: benches
//     })
// }

// export async function initHandlers(emailStr: string, times: number) {
//     // const multiThread = await import(
//     //     'halo2-zk-email'
//     // );
//     // console.log(multiThread);
//     // await multiThread.default();
//     // console.log(`hardware: ${navigator.hardwareConcurrency}`);
//     // await multiThread.initThreadPool(4);
//     if (multiThread == null) {
//         throw new Error("multiThread is null");
//     }
//     const params = await fetchParams();
//     console.log(params);
//     // const pkChunks = await fetchPk();
//     // console.log(pkChunks);
//     // if (pkChunks == null) {
//     //     throw new Error("pkChunks is null");
//     // }
//     // const vk = await fetchVk();
//     // console.log(vk);
//     // await fetch_save_configs();
//     // const privateKey = multiThread.sample_rsa_private_key(bits_len);
//     // const publicKey = multiThread.generate_rsa_public_key(privateKey);
//     // const signature = multiThread.sign(privateKey, msg);
//     const indexes = [];
//     const benches: number[] = [];
//     // // const results = multiThread.multi_bench_2048_1024_circuit(params, pk, vk, publicKey, msg, signature, times);
//     console.log("init");
//     for (let i = 0; i < times; i++) {
//         indexes.push(i);
//         const multiThread = await import(
//             'halo2-zk-email'
//         );
//         await multiThread.default();
//         // await multiThread.initThreadPool(4);
//         // const start = performance.now();
//         // const proof = await multiThread.prove_email(params, [], emailStr);
//         // const sub = performance.now() - start;
//         // console.log(`index: ${i}, bench: ${sub} ms`);
//         // benches.push(sub);
//         // const isValid = multiThread.verify_pkcs1v15_2048_1024_circuit(params, vk, proof);
//         // console.log(isValid);
//         // initOutput.__wbg_wbg_rayon_poolbuilder_free(navigator.hardwareConcurrency);
//     }
//     return proxy({
//         indexes: indexes,
//         benches: benches
//     })
// }

async function initMultiThread() {
    const multiThread = await import(
        'halo2-zk-email'
    );
    console.log(multiThread);
    await multiThread.default();
    console.log(`hardware: ${navigator.hardwareConcurrency}`);
    // await multiThread.initThreadPool(4);
    return multiThread;
    // return proxy({
    //     multiThread: multiThread,
    // })
    // return multiThread;
}

// async function sample_rsa_private_key(bits_len: number): Promise<any> {
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);

//     const private_key = multiThread.sample_rsa_private_key(bits_len);
//     return private_key
// }

// async function to_public_key(private_key: any): Promise<any> {
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);

//     const public_key = multiThread.generate_rsa_public_key(private_key);
//     return public_key
// }

// async function sign(private_key: any, msg: any): Promise<any> {
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);

//     const sign = multiThread.sign(private_key, msg);
//     return sign
// }

// async function sha256_msg(msg: any): Promise<any> {
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);

//     const ret = multiThread.sha256_msg(msg);
//     return ret
// }

// async function prove_1024_64(
//     pk: any,
//     public_key: any,
//     msg: any,
//     signature: any
// ): Promise<any> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.prove_pkcs1v15_1024_64_circuit(params, pk, public_key, msg, signature);
//     return ret;
// }

// async function verify_1024_64(
//     vk: any,
//     proof: any
// ): Promise<boolean> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.verify_pkcs1v15_1024_64_circuit(params, vk, proof);
//     return ret;
// }


// async function prove_1024_1024(
//     pk: any,
//     public_key: any,
//     msg: any,
//     signature: any
// ): Promise<any> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.prove_pkcs1v15_1024_1024_circuit(params, pk, public_key, msg, signature);
//     return ret;
// }

// async function verify_1024_1024(
//     vk: any,
//     proof: any
// ): Promise<boolean> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.verify_pkcs1v15_1024_1024_circuit(params, vk, proof);
//     return ret;
// }

// async function prove_2048_64(
//     pk: any,
//     public_key: any,
//     msg: any,
//     signature: any
// ): Promise<any> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.prove_pkcs1v15_2048_64_circuit(params, pk, public_key, msg, signature);
//     return ret;
// }

// async function verify_2048_64(
//     vk: any,
//     proof: any
// ): Promise<boolean> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.verify_pkcs1v15_2048_64_circuit(params, vk, proof);
//     return ret;
// }

// async function prove_2048_1024(
//     pk: any,
//     public_key: any,
//     msg: any,
//     signature: any
// ): Promise<any> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.prove_pkcs1v15_2048_1024_circuit(params, pk, public_key, msg, signature);
//     return ret;
// }

// async function verify_2048_1024(
//     vk: any,
//     proof: any
// ): Promise<boolean> {
//     const params = await fetch_params();
//     const multiThread = await import(
//         'halo2-rsa'
//     );
//     await multiThread.default();
//     await multiThread.initThreadPool(navigator.hardwareConcurrency);
//     const ret = multiThread.verify_pkcs1v15_2048_1024_circuit(params, vk, proof);
//     return ret;
// }


const exports = {
    // initHandlers,
    fetchSaveConfigs,
    fetchParams,
    // fetchPk,
    fetchPublicKey,
    genProvingKey,
};
expose(exports);
export type BenchWorker = typeof exports;
