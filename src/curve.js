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
    throw new Error(`Incorrect private key length: ${privKey?.byteLength}`);
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
  }
  console.error(
    "WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey",
  );
  return pubKey;
}

function uint8ArrayToBuffer(uint8Array) {
  return Buffer.from(uint8Array.buffer, uint8Array.byteOffset, uint8Array.byteLength);
}

exports.createKeyPair = function (privKey) {
  validatePrivKey(privKey);

  const privKeyUint8 = new Uint8Array(privKey);
  const result = goCryptoInstance.createKeyPair(privKeyUint8);

  if (result.error) {
    throw new Error(result.error);
  }

  return {
    pubKey: uint8ArrayToBuffer(result.pubKey),
    privKey: uint8ArrayToBuffer(result.privKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (!scrubbedPubKey || scrubbedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  const pubKeyUint8 = new Uint8Array(pubKey);
  const privKeyUint8 = new Uint8Array(privKey);
  const result = goCryptoInstance.calculateAgreement(pubKeyUint8, privKeyUint8);

  if (result.error) {
    throw new Error(result.error);
  }

  return uint8ArrayToBuffer(result);
};

exports.calculateSignature = function (privKey, message) {
  validatePrivKey(privKey);

  if (!message) {
    throw new Error("Invalid message");
  }

  const privKeyUint8 = new Uint8Array(privKey);
  const messageUint8 = new Uint8Array(message);
  const result = goCryptoInstance.calculateSignature(privKeyUint8, messageUint8);

  if (result.error) {
    throw new Error(result.error);
  }

  return uint8ArrayToBuffer(result);
};

exports.verifySignature = function (pubKey, msg, sig, isInit) {
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

  const pubKeyUint8 = new Uint8Array(pubKey);
  const msgUint8 = new Uint8Array(msg);
  const sigUint8 = new Uint8Array(sig);
  const result = goCryptoInstance.verifySignature(pubKeyUint8, msgUint8, sigUint8, isInit || false);

  if (result.error) {
    throw new Error(result.error);
  }

  return result;
};

exports.generateKeyPair = function () {
  const result = goCryptoInstance.generateKeyPair();

  if (result.error) {
    throw new Error(result.error);
  }

  return {
    pubKey: uint8ArrayToBuffer(result.pubKey),
    privKey: uint8ArrayToBuffer(result.privKey),
  };
};
