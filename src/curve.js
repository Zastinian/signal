"use strict";

const { ed25519: ed, x25519 } = require("@noble/curves/ed25519");
const nodeCrypto = require("crypto");

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
  if (pubKey.byteLength === 33 && pubKey[0] === 5) {
    return pubKey.subarray(1);
  }
  if (pubKey.byteLength === 32) {
    return pubKey;
  }
  throw new Error("Invalid public key");
}

exports.createKeyPair = function (privKey) {
  validatePrivKey(privKey);
  const publicKeyBytes = ed.getPublicKey(privKey);

  const pub = Buffer.alloc(33);
  pub.set(publicKeyBytes, 1);
  pub[0] = 5;

  return {
    pubKey: pub,
    privKey: Buffer.from(privKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  let scrubbedPubKey;
  if (pubKey instanceof Buffer && pubKey.byteLength === 33 && pubKey[0] === 5) {
    scrubbedPubKey = pubKey.subarray(1);
  } else if (pubKey instanceof Buffer && pubKey.byteLength === 32) {
    scrubbedPubKey = pubKey;
  } else {
    throw new Error("Invalid public key for X25519");
  }
  validatePrivKey(privKey);

  const sharedSecret = x25519.getSharedSecret(privKey, scrubbedPubKey);
  return Buffer.from(sharedSecret);
};

exports.calculateSignature = function (privKey, message) {
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  const signature = ed.sign(message, privKey);
  return Buffer.from(signature);
};

exports.verifySignature = function (pubKey, msg, sig, isInit) {
  if (isInit) {
    return true;
  }
  const scrubbedPubKey = scrubPubKeyFormat(pubKey);
  if (!scrubbedPubKey || scrubbedPubKey.byteLength !== 32) {
    throw new Error("Invalid public key");
  }
  if (!msg) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength !== 64) {
    throw new Error("Invalid signature");
  }
  return ed.verify(sig, msg, scrubbedPubKey);
};

exports.generateKeyPair = function () {
  const privKey = nodeCrypto.randomBytes(32);
  return exports.createKeyPair(privKey);
};
