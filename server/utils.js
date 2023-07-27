const keccak = require("ethereum-cryptography/keccak.js");
const cryptoUtils = require("ethereum-cryptography/utils.js");
const hexToBytes = cryptoUtils.hexToBytes;
const bytesToHex = cryptoUtils.bytesToHex;
const KECCAK256 = keccak.keccak256;

module.exports = {
    removeHexPrefix(str) {
        return (!str || str.length < 3) ? str : str.substring(2);
    },
    addHexPrefix(str) {
        return "0x" + str;
    },
    publicKeyToEthAddress(pubKey) {
        const pubKeyNoPrefix = pubKey.substring(2);
        const keccakHash = bytesToHex(KECCAK256(hexToBytes(pubKeyNoPrefix)));
        const ethAddress = "0x" + keccakHash.slice(-40);
        return ethAddress;
    }
}