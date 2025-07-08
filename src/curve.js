"use strict";

const { ed25519, x25519 } = require("@noble/curves/ed25519");
const nodeCrypto = require("crypto");

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
  validatePrivKey(privKey);
  const origPub = ed25519.getPublicKey(privKey);
  const pub = new Uint8Array(33);
  pub.set(origPub, 1);
  pub[0] = 5;
  return {
    pubKey: Buffer.from(pub),
    privKey: privKey,
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  const cleanedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);
  if (!cleanedPubKey || cleanedPubKey.byteLength != 32) {
    throw new Error("Invalid public key for agreement");
  }
  const sharedSecret = x25519.getSharedSecret(privKey, cleanedPubKey);
  return Buffer.from(sharedSecret);
};

exports.calculateSignature = function (privKey, message) {
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  return Buffer.from(ed25519.sign(message, privKey));
};

exports.verifySignature = function (pubKey, msg, sig, isInit) {
  const cleanedPubKey = scrubPubKeyFormat(pubKey);
  if (!cleanedPubKey || cleanedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }
  if (!msg) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength != 64) {
    throw new Error("Invalid signature");
  }
  return isInit ? true : ed25519.verify(sig, msg, cleanedPubKey);
};

exports.generateKeyPair = function () {
  const privKey = nodeCrypto.randomBytes(32);
  return exports.createKeyPair(privKey);
};
