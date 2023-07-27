const secp = require("ethereum-cryptography/secp256k1.js");
const keccak = require("ethereum-cryptography/keccak.js");
const cryptoUtils = require("ethereum-cryptography/utils.js");
const utils = require("./utils");
const KECCAK256 = keccak.keccak256;
const SECP256k1 = secp.secp256k1;
const utf8ToBytes = cryptoUtils.utf8ToBytes;
const bytesToHex = cryptoUtils.bytesToHex;

// This is a dummy private key from Hardhat for testing:
const privKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const message = {
    id: 3,
    prevId: 2,
    recipient: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    amount: 10  }

const signature = SECP256k1.sign(KECCAK256(utf8ToBytes(JSON.stringify(message))), privKey);
console.log(signature);

message.signature = utils.addHexPrefix(signature.toCompactHex());
message.recovery = signature.recovery;

console.log(message);
