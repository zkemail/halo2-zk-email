import React, { useState, useEffect } from 'react';
import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';
import { mean, sampleVariance } from 'simple-statistics'
// import { fetchParams, } from './bench-worker';
// const Plotly = require('plotly.js-dist');

function App() {
  const worker = new Worker(new URL('./bench-worker', import.meta.url), {
    name: 'bench-worker',
    type: 'module',
  });
  const workerApi = wrap<import('./bench-worker').BenchWorker>(worker);
  // const [ans, setAns] = useState(0);
  // const defaultEmailStr = `Delivered-To: emailwallet.relayer@gmail.com
  // Received: by 2002:a05:7108:8190:b0:35d:a7ed:3d3f with SMTP id c16csp3477575gdv;
  //         Sun, 10 Dec 2023 07:58:41 -0800 (PST)
  // X-Received: by 2002:a0d:d884:0:b0:5d7:1941:a9b with SMTP id a126-20020a0dd884000000b005d719410a9bmr2252254ywe.54.1702223921597;
  //         Sun, 10 Dec 2023 07:58:41 -0800 (PST)
  // ARC-Seal: i=1; a=rsa-sha256; t=1702223921; cv=none;
  //         d=google.com; s=arc-20160816;
  //         b=iFKf5X1Imw98UKB6r0/jT/w+8ZQUwtqYasY7oOktiIaxteVLoJ9Y+WKthOl5h8Zx/p
  //          9QMd78mXdus08G1Uy++d974ufbKAgMNAMqUbfN27C71YLm6/vr6j62hghWqqH/hCsuIp
  //          7NM71n9W9oqymV8VXqd33ljPOk3Q5sxJ/5qHaxKlmzpgD7cog9s+/rMkz/+GY8ADyONX
  //          5Bjl0JjAMZD3O1ZqfyL3ZRQI7KLgFmuwKBR2VTAgO55ODUeAGfQRdCcrFC7ds3rchzpo
  //          F1dWsmJI0wFHhvta2ZMXkWO8VgQ9Wr6HaLKi0vm9En+b9QxiHbTGLLjc4l3fICi8YTYN
  //          XlHg==
  // ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
  //         h=to:subject:message-id:date:from:mime-version:dkim-signature;
  //         bh=GUspwlIIG/sP841vGpwvy3MPgVazLJpd/ow/iYyjBbU=;
  //         fh=AKWw92sdXoMEDdHXKLL06vnizTpObKPGCfYXnoQDKO8=;
  //         b=OwZ/cor6fk/L07nb373YlTMzD+tgh+BbSm6BUz3iElswDuKJCwq/VuPsZlOmdnBwJj
  //          /plClik0nIxkORCzGqqpNDziiI8/TWEXD0ktLgq8CbKx7hLF0BSKPVAWwahF1OLjalm8
  //          +owoh23vmRu0rQ/WDBbCow6gOmp6rt7XLNNJk/0kZdKwUDbIgU1+nxE+a/QV20wUb7gE
  //          Zmco67MdshkQpMHJp7gVYUgiyWbt3BhjRAN9+pk2sf01ItR7aiqiC2ql31VBO5iPydG6
  //          T7W1TJNTPoI8XVkh8fELytg3nVpV8vIRaG+6z5BBaXpMegFX+iWehTRQUTOdDPXg4jFi
  //          dA3g==
  // ARC-Authentication-Results: i=1; mx.google.com;
  //        dkim=pass header.i=@gmail.com header.s=20230601 header.b=MREa0ELt;
  //        spf=pass (google.com: domain of suegamisora@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=suegamisora@gmail.com;
  //        dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
  // Return-Path: <suegamisora@gmail.com>
  // Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
  //         by mx.google.com with SMTPS id g78-20020a0ddd51000000b005d3d815e4ccsor1991901ywe.16.2023.12.10.07.58.41
  //         for <emailwallet.relayer@gmail.com>
  //         (Google Transport Security);
  //         Sun, 10 Dec 2023 07:58:41 -0800 (PST)
  // Received-SPF: pass (google.com: domain of suegamisora@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
  // Authentication-Results: mx.google.com;
  //        dkim=pass header.i=@gmail.com header.s=20230601 header.b=MREa0ELt;
  //        spf=pass (google.com: domain of suegamisora@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=suegamisora@gmail.com;
  //        dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
  // DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  //         d=gmail.com; s=20230601; t=1702223921; x=1702828721; dara=google.com;
  //         h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
  //          :date:message-id:reply-to;
  //         bh=GUspwlIIG/sP841vGpwvy3MPgVazLJpd/ow/iYyjBbU=;
  //         b=MREa0ELt0knVg0s8F6a6rPZNxgJRe7C5fQjpHS+Jlf0l6kKrsHOkf9pPW1aVScf6wt
  //          8rCmaO7mazJF/8u2ObMrZ8v4kL0CmYGRy57/LNdzk7DMBZskajYSRX909sw2DK0w7Znv
  //          BSexoZlIeRqHOsqXA5qJ02hRCi1REnzHOy1oNkBpKqb/iVjCM9GtfSfTDdK7psjBArru
  //          l4wuf7DFxNMdqKgH6VacEnLUQYjHIoiGJKbK3BO/uT2d4eA8Z7flDpYWzak8gAx9lABv
  //          mxKWxKgP6zo08RWoAEGF53WmW+6Ft/nseg1cgJy0U/Yw+KOUy5nsiJLctajuYdhWBhch
  //          FMew==
  // X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  //         d=1e100.net; s=20230601; t=1702223921; x=1702828721;
  //         h=to:subject:message-id:date:from:mime-version:x-gm-message-state
  //          :from:to:cc:subject:date:message-id:reply-to;
  //         bh=GUspwlIIG/sP841vGpwvy3MPgVazLJpd/ow/iYyjBbU=;
  //         b=VLNYRexFGqVaJHdiViwkzXfeFTu/dW8grgXMrqSzeH6vUW39HaOca1w0gm6euKKIQv
  //          v/oSPdqGy+6nD0UrcNFn0Fcz0jTFa5yJ0feiuE6WCjikHOTvQsScLAKhbN97C2mOjjz9
  //          hepDkVxF9GHA2TUBFlAAkd2lSm3BEMrxFk5JCNUfmuQSFIKqT1u8z9ToZ56Vk4R6ODip
  //          rZ737NwB7VGv5YckRXPJH00SfdiO5R8WR8k5uxziYw02oCQ+mk0j8+2hGcodWdR2/eBs
  //          H34DmCJAMkfIo80lTX9QFhqec2lGfA6xGnEy1WLEkB3qEtZEjlr+M0Q57Af85U1h/DK0
  //          tH9A==
  // X-Gm-Message-State: AOJu0YxMAQGL7080EZPDyVk2AIVutc3APVhNDpnBr0vAgJsnGZY3ohqR
  //   +sQorRUF1maMuWadqj9fHzjPpWqxVCS3QMAusn5OA+UgoX8=
  // X-Google-Smtp-Source: AGHT+IE9q/z1n4s5Z13NEuqmBcqki+H5Iev2UiPber/ECbJxVrbO6lRiSHBYTPJWdUIiGpq0SXX5L9MnF3zUv52Eylw=
  // X-Received: by 2002:a81:8406:0:b0:5d4:2ab1:9f0a with SMTP id
  //  u6-20020a818406000000b005d42ab19f0amr2100524ywf.42.1702223920881; Sun, 10 Dec
  //  2023 07:58:40 -0800 (PST)
  // MIME-Version: 1.0
  // From: Sora Suegami <suegamisora@gmail.com>
  // Date: Mon, 11 Dec 2023 00:58:29 +0900
  // Message-ID: <CAJ7Y6jeSK0pOMtGC81JFKzEZf2KE1zxbzcyKuaRvsYROwVP6qQ@mail.gmail.com>
  // Subject: Demo Email
  // To: emailwallet.relayer@gmail.com
  // Content-Type: multipart/alternative; boundary="00000000000021e38e060c29e4a6"

  // --00000000000021e38e060c29e4a6
  // Content-Type: text/plain; charset="UTF-8"

  // Hello zkemail!

  // --00000000000021e38e060c29e4a6
  // Content-Type: text/html; charset="UTF-8"

  // <div dir="ltr">Hello zkemail!<div dir="ltr" class="gmail_signature" data-smartmail="gmail_signature"></div></div>

  // --00000000000021e38e060c29e4a6--`;
  const [emailFile, setEmailFile] = useState<File | null>(null);

  async function bench() {
    // const params = await fetch_params();
    // const pk = await fetch_pk();
    // const vk = await fetch_vk();

    // const multiThread = await import(
    //   'halo2-rsa'
    // );
    // await multiThread.default();
    // await multiThread.initThreadPool(navigator.hardwareConcurrency);
    // console.log("benchmark start");
    // const privateKey = await multiThread.sample_rsa_private_key(1024);
    // let msg = new Uint8Array([0]);
    // const publicKey = await multiThread.generate_rsa_public_key(privateKey);
    // const signature = await multiThread.sign(privateKey, msg);
    // const times = 20;
    // const indexes = [];
    // const benches = [];
    // let sumTime = 0;
    // for (let i = 0; i < times; i++) {
    //   indexes.push(i);
    //   const start = performance.now();
    //   const proof = await multiThread.prove_pkcs1v15_1024_1024_circuit(params, pk, publicKey, msg, signature);
    //   const sub = performance.now() - start;
    //   console.log(`index: ${i}, bench: ${sub} ms`);
    //   benches.push(sub);
    //   // sumTime += sub;
    //   const isValid = await mul.verify_1024_1024(wasm, params, vk, proof);
    //   console.log(isValid)
    // }
    if (emailFile == null) {
      return;
    }
    console.log("bench start");
    // await workerApi.initMultiThread();
    // const multiThread = await initResult.multiThread;
    // await fetchSaveConfigs();
    // localStorage.clear();
    // const configParams = await workerApi.fetchConfigs();
    // localStorage.setItem("EMAIL_VERIFY_CONFIG", configParams);
    // let configParamsJson = JSON.parse(configParams);
    // localStorage.setItem(configParamsJson.header_config.bodyhash_allstr_filepath, await fetchRegexFile(configParamsJson.header_config.bodyhash_allstr_filepath));
    // localStorage.setItem(configParamsJson.header_config.bodyhash_substr_filepath, await fetchRegexFile(configParamsJson.header_config.bodyhash_substr_filepath));
    // for (const filePath of configParamsJson.header_config.allstr_filepathes.flat()) {
    //   localStorage.setItem(filePath, await workerApi.fetchRegexFile(filePath));
    // }
    // for (const filePath of configParamsJson.header_config.substr_filepathes.flat()) {
    //   localStorage.setItem(filePath, await workerApi.fetchRegexFile(filePath));
    // }
    // for (const filePath of configParamsJson.body_config.allstr_filepathes.flat()) {
    //   localStorage.setItem(filePath, await workerApi.fetchRegexFile(filePath));
    // }
    // for (const filePath of configParamsJson.body_config.substr_filepathes.flat()) {
    //   localStorage.setItem(filePath, await workerApi.fetchRegexFile(filePath));
    // }
    // console.log(localStorage.length);

    const params = await workerApi.fetchParams();
    console.log(params);

    const emailStr = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve(reader.result);
        } else {
          reject(new Error('FileReader result is not a string'));
        }
      };
      reader.onerror = () => {
        reject(new Error('FileReader encountered an error'));
      };
      reader.readAsText(emailFile, 'utf-8');
    });
    console.log(emailStr);
    const publicKey = await workerApi.fetchPublicKey(emailStr);
    await workerApi.genProvingKey(params, emailStr, publicKey);
    // const vk = await fetch_vk();
    // console.log(vk);
    // try {
    //   const pkChunks = await fetchPk();
    //   if (pkChunks == null) {
    //     throw new Error("pkChunks is null");
    //   }
    //   console.log(pkChunks);
    // } catch (e) {
    //   console.error(e);
    // }
    // let msg = new Uint8Array(new Array(32).fill(0));
    // console.log(msg);
    // const results = await workerApi.initHandlers(emailStr, 1);
    // console.log(results);
    // const graph = document.getElementById('graph');
    // const avg = await results.avg;
    // const sdv = await results.sdv;
    // const indexes = await results.indexes;
    // const benches = await results.benches;
    // Plotly.newPlot(graph, [{
    //   x: indexes,
    //   y: benches,
    // }], {
    //   margin: { t: 0 }
    // });
    // console.log(`proving time average: ${mean(benches)} ms.`);
    // console.log(`proving time variance: ${sampleVariance(benches)} ms.`);
    // try {
    //   const params = await workerApi.fetch_params();
    //   const pk = await workerApi.fetch_pk();
    //   const vk = await workerApi.fetch_vk();
    //   const wasm = await workerApi.init_wasm();
    //   console.log("benchmark start");
    //   const privateKey = await workerApi.sample_rsa_private_key(wasm, 1024);
    //   let msg = new Uint8Array([0]);
    //   const publicKey = await workerApi.to_public_key(wasm, privateKey);
    //   const signature = await workerApi.sign(wasm, privateKey, msg);
    //   const times = 20;
    //   const indexes = [];
    //   const benches = [];
    //   // let sumTime = 0;
    //   // for (let i = 0; i < times; i++) {
    //   //   indexes.push(i);
    //   //   const start = performance.now();
    //   //   const proof = await workerApi.prove_1024_1024(wasm, params, pk, publicKey, msg, signature);
    //   //   const sub = performance.now() - start;
    //   //   console.log(`index: ${i}, bench: ${sub} ms`);
    //   //   benches.push(sub);
    //   //   // sumTime += sub;
    //   //   const isValid = await workerApi.verify_1024_1024(wasm, params, vk, proof);
    //   //   console.log(isValid)
    //   // }
    //   // const graph = document.getElementById('graph');
    //   // Plotly.newPlot(graph, [{
    //   //   x: indexes,
    //   //   y: benches,
    //   // }], {
    //   //   margin: { t: 0 }
    //   // });
    //   // console.log(`proving time average: ${mean(benches)} ms.`);
    //   // console.log(`proving time variance: ${sampleVariance(benches)} ms.`);
    // } catch (e) {
    //   console.log(e)
    // }
    // const proof = await workerApi.prove_play();
    // console.log('ending', performance.now() - start);
    // console.log('outside proof', proof);

    // const verification = await workerApi.verify_play(proof, diff_js);
    // console.log('verified', verification);
    // console.log('time', performance.now() - start);
  }

  // const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
  //   setEmailStr(event.target.value);
  // }
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setEmailFile(event.target.files[0]);
    }
  }


  return (
    <div className="App">
      <header className="App-header">
        <p>
          Halo2-ZKEmail on browser.
        </p>
        {/* <textarea
          style={{ width: '100%', height: '20vh' }}
          value={emailStr}
          onChange={handleChange}
        /> */}
        <input type="file" onChange={handleFileChange} />
        <button onClick={bench}>test</button>
        {/* <div id="graph"></div> */}
      </header>
    </div>
  );
}

export default App;

