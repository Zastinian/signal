"use strict";

require("../lib/wasm_exec");
const fs = require("fs");
const path = require("path");

let wasmInitialized = false;
let go;

function initWasm() {
  if (wasmInitialized) {
    return;
  }

  globalThis.require = require;
  globalThis.fs = fs;
  globalThis.path = path;
  globalThis.TextEncoder = require("util").TextEncoder;
  globalThis.TextDecoder = require("util").TextDecoder;
  globalThis.crypto = require("crypto");

  go = new Go();
  go.argv = [];
  go.env = Object.assign({ TMPDIR: require("os").tmpdir() }, process.env);

  const wasmBuffer = fs.readFileSync(path.join(__dirname, "../lib/main.wasm"));
  const wasmModule = new WebAssembly.Module(wasmBuffer);
  const wasmInstance = new WebAssembly.Instance(wasmModule, go.importObject);

  go.run(wasmInstance);
  wasmInitialized = true;
}

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
  } else {
    console.error(
      "WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey",
    );
    return pubKey;
  }
}

exports.createKeyPair = function (privKey) {
  initWasm();
  validatePrivKey(privKey);

  const privKeyArray = new Uint8Array(privKey);
  const result = globalThis.createKeyPair(privKeyArray);

  return {
    pubKey: Buffer.from(result.pubKey),
    privKey: Buffer.from(result.privKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  initWasm();
  pubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (!pubKey || pubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  const pubKeyArray = new Uint8Array(pubKey);
  const privKeyArray = new Uint8Array(privKey);
  const result = globalThis.calculateAgreement(pubKeyArray, privKeyArray);

  return Buffer.from(result);
};

exports.calculateSignature = function (privKey, message) {
  initWasm();
  validatePrivKey(privKey);

  if (!message) {
    throw new Error("Invalid message");
  }

  const privKeyArray = new Uint8Array(privKey);
  const messageArray = new Uint8Array(message);
  const result = globalThis.calculateSignature(privKeyArray, messageArray);

  return Buffer.from(result);
};

exports.verifySignature = function (pubKey, msg, sig, isInit) {
  initWasm();
  pubKey = scrubPubKeyFormat(pubKey);

  if (!pubKey || pubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }
  if (!msg) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength != 64) {
    throw new Error("Invalid signature");
  }

  const pubKeyArray = new Uint8Array(pubKey);
  const msgArray = new Uint8Array(msg);
  const sigArray = new Uint8Array(sig);

  return globalThis.verifySignature(pubKeyArray, msgArray, sigArray, isInit);
};

exports.generateKeyPair = function () {
  initWasm();
  const result = globalThis.generateKeyPair();

  return {
    pubKey: Buffer.from(result.pubKey),
    privKey: Buffer.from(result.privKey),
  };
};
