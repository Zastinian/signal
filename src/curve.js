"use strict";
const nacl = require("tweetnacl");
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

  const publicKey = nacl.scalarMult.base(privKey);

  const pub = new Uint8Array(33);
  pub.set(publicKey, 1);
  pub[0] = 5;

  return {
    pubKey: Buffer.from(pub),
    privKey: Buffer.from(privKey),
  };
};

exports.calculateAgreement = function (pubKey, privKey) {
  let scrubbedPubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (!scrubbedPubKey || scrubbedPubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }

  const shared = nacl.scalarMult(privKey, scrubbedPubKey);
  return Buffer.from(shared);
};

exports.calculateSignature = function (privKey, message) {
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }

  const keyPair = nacl.sign.keyPair.fromSeed(privKey);
  const signature = nacl.sign.detached(message, keyPair.secretKey);

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

  try {
    return nacl.sign.detached.verify(msg, sig, scrubbedPubKey);
  } catch (e) {
    return false;
  }
};

exports.generateKeyPair = function () {
  const privKey = nodeCrypto.randomBytes(32);
  return exports.createKeyPair(privKey);
};
