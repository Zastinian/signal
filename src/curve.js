"use strict";

const { Worker } = require("worker_threads");
const path = require("path");
const crypto = require("crypto");

const workerPath = path.resolve(__dirname, "crypto-worker.js");

function runInWorker(task, args) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath, {
      workerData: { task, args },
    });
    worker.on("message", resolve);
    worker.on("error", reject);
    worker.on("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}

exports.createKeyPair = function (privKey) {
  return runInWorker("createKeyPair", { privKey });
};

exports.calculateAgreement = function (pubKey, privKey) {
  return runInWorker("calculateAgreement", { pubKey, privKey });
};

exports.calculateSignature = function (privKey, message) {
  return runInWorker("calculateSignature", { privKey, message });
};

exports.verifySignature = function (pubKey, msg, sig, isInit) {
  if (isInit) {
    return Promise.resolve(true);
  }
  return runInWorker("verifySignature", { pubKey, msg, sig });
};

exports.generateKeyPair = function () {
  const privKey = crypto.randomBytes(32);
  return exports.createKeyPair(privKey);
};
