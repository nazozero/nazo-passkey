import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const wasi = new WASI({version: 'preview1', args: ['ceremony-bench'], env: {PERF_ITERATIONS: process.env.PERF_ITERATIONS ?? '1000'}, preopens: {}, returnOnExit: true});
const module = await WebAssembly.compile(await readFile(process.argv[2]));
const instance = await WebAssembly.instantiate(module, {wasi_snapshot_preview1: wasi.wasiImport});
const code = wasi.start(instance);
if (code !== 0) process.exit(code);
