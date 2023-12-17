import React, { useState, useEffect } from 'react';
import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';
import { mean, sampleVariance } from 'simple-statistics'
// import { fetchParams, } from './bench-worker';
const Plotly = require('plotly.js-dist');

function App() {
  const worker = new Worker(new URL('./bench-worker', import.meta.url), {
    name: 'bench-worker',
    type: 'module',
  });
  const workerApi = wrap<import('./bench-worker').BenchWorker>(worker);

  const [defaultEmailFile, setDefaultEmailFile] = useState<File | null>(null);
  const [emailFile, setEmailFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("demo_wasm.eml");
  const [numBench, setNumBench] = useState<number>(1);
  const [isValidRunning, setIsValidRunning] = useState(false);
  const [validLoadMessage, setValidLoadMessage] = useState("");
  const [isInvalidRunning, setIsInvalidRunning] = useState(false);
  const [invalidLoadMessage, setInvalidLoadMessage] = useState("");

  useEffect(() => {
    const fetchDefaultEmail = async () => {
      try {
        const response = await fetch('http://localhost:3000/demo_wasm.eml');
        const data = await response.blob();
        console.log(data);
        const file = new File([data], "demo_wasm.eml", { type: data.type });
        setDefaultEmailFile(file);
        setEmailFile(file);
      } catch (error) {
        console.error("Error:", error);
      }
    };
    fetchDefaultEmail();
  }, []);

  async function runValidTest() {
    setIsValidRunning(true);
    setValidLoadMessage("Running the test of the valid case...");
    if (defaultEmailFile == null) {
      return;
    }
    const emailStr = await emailFile2Str(defaultEmailFile);
    const isValid = await workerApi.runValidTest(emailStr);
    if (isValid) {
      alert("proof is valid");
    } else {
      alert("proof is invalid");
    }
    setIsValidRunning(false);
    setValidLoadMessage("");
  }

  async function runInvalidTest() {
    setIsInvalidRunning(true);
    setInvalidLoadMessage("Running the test of the invalid case...");
    if (defaultEmailFile == null) {
      return;
    }
    const emailStr = await emailFile2Str(defaultEmailFile);
    const isValid = await workerApi.runInvalidTest(emailStr);
    if (isValid) {
      alert("proof is valid");
    } else {
      alert("proof is invalid");
    }
    setIsInvalidRunning(false);
    setInvalidLoadMessage("");
  }

  function handleNumBench(event: React.ChangeEvent<HTMLInputElement>) {
    try {
      const num = parseInt(event.target.value);
      if (num < 1) {
        alert("num bench is an integer less than 1");
      }
      setNumBench(num);
    } catch (e) {
      console.error(e);
      alert("num bench is an integer less than 1");
    }
  }

  async function bench() {
    try {
      if (emailFile == null) {
        return;
      }
      console.log("bench start");
      const emailStr = await emailFile2Str(emailFile);
      console.log(emailStr);
      const results = await workerApi.runBench(emailStr, numBench);
      console.log(results);
      const graph = document.getElementById('graph');
      const indexes = await results.indexes;
      const benches = await results.benches;
      Plotly.newPlot(graph, [{
        x: indexes,
        y: benches,
      }], {
        margin: { t: 0 }
      });
      console.log(`proving time average: ${mean(benches)} ms.`);
      console.log(`proving time variance: ${sampleVariance(benches)} ms.`);
      alert(`proving time average: ${mean(benches)} ms.\nproving time variance: ${sampleVariance(benches)} ms.`);
    } catch (e) {
      alert(e);
    }
  }

  function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    if (event.target.files && event.target.files.length > 0) {
      setEmailFile(event.target.files[0]);
      setFileName(event.target.files[0].name);
    }
  }



  function emailFile2Str(file: File): Promise<string> {
    return new Promise<string>((resolve, reject) => {
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
      reader.readAsText(file, 'utf-8');
    });
  }


  return (
    <div className="App">
      <header className="App-header">
        <h2>
          Halo2-ZKEmail on browser.
        </h2>
        <div>
          <h3>Run test of valid case</h3>
          <button onClick={runValidTest} disabled={isValidRunning}>Run test</button>
          <p>{validLoadMessage}</p>
        </div>

        <div>
          <h3>Run test of invalid case (invalid public key)</h3>
          <button onClick={runInvalidTest} disabled={isInvalidRunning}>Run test</button>
          <p>{invalidLoadMessage}</p>
        </div>

        <div>
          <h3>Run bench</h3>
          <p>The expected regex in the email body is "Hello (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+!"</p>
          <label className="custom-file-upload"
            style={{
              display: 'inline-block',
              padding: '10px',
              border: '1px solid #000',
              cursor: 'pointer',
              backgroundColor: '#f0f0f0', // This is a common default input background color
              color: '#000' // This will make the text color black
            }}
          >
            <input type="file" onChange={handleFileChange} style={{ display: 'none' }} />
            Select an email file.
          </label>
          <span style={{ fontSize: '0.8em', marginLeft: '10px' }}>{fileName}</span><br></br>
          <input type="number" placeholder="Number of bench runs" onChange={handleNumBench} /><br></br>
          <button onClick={bench}>Run bench</button><br></br>
          <div id="graph"></div>
        </div>
      </header>
    </div>
  );
}

export default App;

