"use strict";
const { generateKeyPair: x25519GenerateKeyPair, sharedKey } = require("@stablelib/x25519");
const { generateKeyPair: ed25519GenerateKeyPair, sign, verify } = require("@stablelib/ed25519");
const { randomBytes } = require("@stablelib/random");

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

  const keyPair = x25519GenerateKeyPair(new Uint8Array(privKey));

  const pub = new Uint8Array(33);
  pub.set(keyPair.publicKey, 1);
  pub[0] = 5;

  return {
    pubKey: Buffer.from(pub),
    privKey: Buffer.from(keyPair.secretKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (!scrubbedPubKey || scrubbedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  const shared = sharedKey(new Uint8Array(privKey), new Uint8Array(scrubbedPubKey));
  return Buffer.from(shared);
};

exports.calculateSignature = function (privKey, message) {
  validatePrivKey(privKey);

  if (!message) {
    throw new Error("Invalid message");
  }

  const keyPair = ed25519GenerateKeyPair(new Uint8Array(privKey));
  const signature = sign(keyPair.secretKey, new Uint8Array(message));

  return Buffer.from(signature);
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

  return verify(new Uint8Array(scrubbedPubKey), new Uint8Array(msg), new Uint8Array(sig));
};

exports.generateKeyPair = function () {
  const privKey = randomBytes(32); // Usar randomBytes de stablelib es más rápido
  return exports.createKeyPair(Buffer.from(privKey));
};
