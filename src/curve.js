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

function scrubPubKeyFormat(pubKey) {
  if (!(pubKey instanceof Buffer)) {
    throw new Error(`Invalid public key type: ${pubKey?.constructor?.name}`);
  }

  if (
    pubKey === undefined ||
    ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)
  ) {
    throw new Error("Invalid public key");
  }

  if (pubKey.byteLength == 33) {
    return pubKey.subarray(1);
  } else {
    console.error(
      "WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey",
    );
    return pubKey;
  }
}

exports.createKeyPair = function (privKey) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }

  validatePrivKey(privKey);

  const keys = goCryptoInstance.createKeyPair(privKey);
  if (keys instanceof Error) {
    throw keys;
  }

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
  if (keys instanceof Error) {
    throw keys;
  }

  return {
    pubKey: Buffer.from(keys.pubKey),
    privKey: Buffer.from(keys.privKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }

  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (!scrubbedPubKey || scrubbedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  const shared = goCryptoInstance.calculateAgreement(pubKey, privKey);
  if (shared instanceof Error) {
    throw shared;
  }

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
  if (signature instanceof Error) {
    throw signature;
  }

  return Buffer.from(signature);
};

exports.verifySignature = function (pubKey, msg, sig, isInit = false) {
  if (!wasmInitialized) {
    throw new Error("WASM not initialized");
  }

  let scrubbedPubKey = scrubPubKeyFormat(pubKey);

  if (!scrubbedPubKey || scrubbedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  if (!msg) {
    throw new Error("Invalid message");
  }

  if (!sig || sig.byteLength != 64) {
    throw new Error("Invalid signature");
  }

  if (isInit) {
    return true;
  }

  const result = goCryptoInstance.verifySignature(pubKey, msg, sig, isInit);
  if (result instanceof Error) {
    throw result;
  }

  return result;
};
