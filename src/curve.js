"use strict";

const fs = require("fs");
const path = require("path");
require("../lib/wasm_exec");

let wasmModulePromise = null;

function loadWasm() {
  if (wasmModulePromise) {
    return wasmModulePromise;
  }
  wasmModulePromise = new Promise(async (resolve, reject) => {
    try {
      // biome-ignore lint/correctness/noUndeclaredVariables: off
      const go = new Go();
      const wasmPath = path.resolve(__dirname, "../lib/main.wasm");
      const wasmBytes = fs.readFileSync(wasmPath);
      const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
      go.run(instance);
      resolve();
    } catch (err) {
      reject(err);
    }
  });
  return wasmModulePromise;
}

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

exports.createKeyPair = async function (privKey) {
  await loadWasm();
  validatePrivKey(privKey);
  const keys = await global.goCrypto.createKeyPair(privKey);
  return {
    pubKey: Buffer.from(keys.pubKey),
    privKey: Buffer.from(keys.privKey),
  };
};

exports.generateKeyPair = async function () {
  await loadWasm();
  const keys = await global.goCrypto.generateKeyPair();
  // In Go, the generated private key is 64 bytes (seed + public key).
  // To match the original JS, we return only the first 32 bytes (the seed).
  const fullPrivKey = Buffer.from(keys.privKey);
  return {
    pubKey: Buffer.from(keys.pubKey),
    privKey: fullPrivKey.subarray(0, 32),
  };
};

exports.calculateAgreement = async function (pubKey, privKey) {
  await loadWasm();
  validatePrivKey(privKey);
  const shared = await global.goCrypto.calculateAgreement(pubKey, privKey);
  return Buffer.from(shared);
};

exports.calculateSignature = async function (privKey, message) {
  await loadWasm();
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  const signature = await global.goCrypto.calculateSignature(privKey, message);
  return Buffer.from(signature);
};

exports.verifySignature = async function (pubKey, msg, sig, isInit = false) {
  await loadWasm();
  return await global.goCrypto.verifySignature(pubKey, msg, sig, isInit);
};
