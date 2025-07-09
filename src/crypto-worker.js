"use strict";

const { workerData, parentPort } = require("worker_threads");
const sodium = require("sodium-native");

function validatePrivKey(privKey) {
  if (privKey === undefined) {
    throw new Error("Undefined private key");
  }
  if (!(privKey instanceof Buffer)) {
    throw new Error(`Invalid private key type: ${privKey?.constructor?.name}`);
  }
  if (privKey.byteLength !== 32) {
    throw new Error(`Incorrect private key length: ${privKey?.byteLength}`);
  }
}

function scrubPubKeyFormat(pubKey) {
  if (!(pubKey instanceof Buffer)) {
    throw new Error(`Invalid public key type: ${pubKey?.constructor?.name}`);
  }
  if (
    pubKey === undefined ||
    ((pubKey.byteLength !== 33 || pubKey[0] !== 5) && pubKey.byteLength !== 32)
  ) {
    throw new Error("Invalid public key");
  }
  return pubKey.byteLength === 33 ? pubKey.subarray(1) : pubKey;
}

function createKeyPair({ privKey }) {
  validatePrivKey(privKey);
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, privKey);

  const pub = Buffer.alloc(33);
  publicKey.copy(pub, 1);
  pub[0] = 5;

  return { pubKey: pub, privKey: privKey };
}

function calculateAgreement({ pubKey, privKey }) {
  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);
  if (!scrubbedPubKey || scrubbedPubKey.byteLength !== 32) {
    throw new Error("Invalid public key");
  }

  const x25519Sk = Buffer.alloc(sodium.crypto_scalarmult_BYTES);
  const x25519Pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES);
  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES);

  const signSk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(Buffer.alloc(32), signSk, privKey);

  sodium.crypto_sign_ed25519_sk_to_curve25519(x25519Sk, signSk);
  sodium.crypto_sign_ed25519_pk_to_curve25519(x25519Pk, scrubbedPubKey);

  sodium.crypto_scalarmult(sharedSecret, x25519Sk, x25519Pk);
  return sharedSecret;
}

function calculateSignature({ privKey, message }) {
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(Buffer.alloc(32), secretKey, privKey);
  sodium.crypto_sign_detached(signature, message, secretKey);
  return signature;
}

function verifySignature({ pubKey, msg, sig }) {
  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  if (!scrubbedPubKey || scrubbedPubKey.byteLength !== 32) {
    throw new Error("Invalid public key");
  }
  if (!msg) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength !== 64) {
    throw new Error("Invalid signature");
  }
  return sodium.crypto_sign_verify_detached(sig, msg, scrubbedPubKey);
}

const tasks = {
  createKeyPair,
  calculateAgreement,
  calculateSignature,
  verifySignature,
};

try {
  const result = tasks[workerData.task](workerData.args);
  parentPort.postMessage(result);
} catch (e) {
  parentPort.postMessage({ error: e.message });
}
