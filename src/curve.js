"use strict";

const fs = require("fs");
const path = require("path");
require("../lib/wasm_exec");

let wasmInitialized = false;
let goCryptoInstance = null;

function initWasmSync() {
  if (wasmInitialized) {
    return;
  }

  try {
    const go = new Go();
    const wasmPath = path.resolve(__dirname, "../lib/main.wasm");
    const wasmBytes = fs.readFileSync(wasmPath);

    const module = new WebAssembly.Module(wasmBytes);
    const instance = new WebAssembly.Instance(module, go.importObject);

    go.run = function (instance) {
      this._inst = instance;
      this.mem = new DataView(this._inst.exports.mem.buffer);
      this._values = [NaN, 0, null, true, false, globalThis, this];
      this._goRefCounts = new Array(this._values.length).fill(Infinity);
      this._ids = new Map([
        [0, 1],
        [null, 2],
        [true, 3],
        [false, 4],
        [globalThis, 5],
        [this, 6],
      ]);
      this._idPool = [];
      this.exited = false;

      let offset = 4096;
      const strPtr = (str) => {
        const ptr = offset;
        const bytes = new TextEncoder().encode(str + "\0");
        new Uint8Array(this.mem.buffer, offset, bytes.length).set(bytes);
        offset += bytes.length;
        if (offset % 8 !== 0) {
          offset += 8 - (offset % 8);
        }
        return ptr;
      };

      const argc = this.argv.length;
      const argvPtrs = [];
      this.argv.forEach((arg) => {
        argvPtrs.push(strPtr(arg));
      });
      argvPtrs.push(0);

      const keys = Object.keys(this.env).sort();
      keys.forEach((key) => {
        argvPtrs.push(strPtr(`${key}=${this.env[key]}`));
      });
      argvPtrs.push(0);

      const argv = offset;
      argvPtrs.forEach((ptr) => {
        this.mem.setUint32(offset, ptr, true);
        this.mem.setUint32(offset + 4, 0, true);
        offset += 8;
      });

      this._inst.exports.run(argc, argv);
    };

    go.run(instance);
    goCryptoInstance = global.goCrypto;
    wasmInitialized = true;
  } catch (err) {
    throw new Error(`Failed to initialize WASM: ${err.message}`);
  }
}

initWasmSync();

function validatePrivKey(privKey) {
  if (privKey === undefined) {
    throw new Error("Undefined private key");
  }
  if (!(privKey instanceof Buffer)) {
    throw new Error(`Invalid private key type: ${privKey?.constructor?.name}`);
  }
  if (privKey.byteLength != 32) {
    throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
  }
}

exports.createKeyPair = function (privKey) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }
  validatePrivKey(privKey);
  const keys = goCryptoInstance.createKeyPair(privKey);
  return {
    pubKey: Buffer.from(keys.pubKey),
    privKey: Buffer.from(keys.privKey),
  };
};

exports.generateKeyPair = function () {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }
  const keys = goCryptoInstance.generateKeyPair();
  const fullPrivKey = Buffer.from(keys.privKey);
  return {
    pubKey: Buffer.from(keys.pubKey),
    privKey: fullPrivKey.subarray(0, 32),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }
  validatePrivKey(privKey);
  const shared = goCryptoInstance.calculateAgreement(pubKey, privKey);
  return Buffer.from(shared);
};

exports.calculateSignature = function (privKey, message) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  const signature = goCryptoInstance.calculateSignature(privKey, message);
  return Buffer.from(signature);
};

exports.verifySignature = function (pubKey, msg, sig, isInit = false) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }
  return goCryptoInstance.verifySignature(pubKey, msg, sig, isInit);
};
