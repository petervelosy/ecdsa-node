const express = require("express");
const app = express();
const cors = require("cors");
const secp = require("ethereum-cryptography/secp256k1.js");
const keccak = require("ethereum-cryptography/keccak.js");
const cryptoUtils = require("ethereum-cryptography/utils.js");
const utils = require("./utils");
const KECCAK256 = keccak.keccak256;
const SECP256k1 = secp.secp256k1;
const utf8ToBytes = cryptoUtils.utf8ToBytes;

const port = 3042;

app.use(cors());
app.use(express.json());

//TODO: add check: in case of id:0, we are creating money, thus not deducting the funds being transferred from anywhere.
//TODO: The genesis transaction must be signed by the minter address below:
const minterAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

const transactions = [
  {
    id: 0,
    prevId: null,
    recipient: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    amount: 225,
    signature: "0x189fe565250606f7704cfd297c24aef6d355ca600aee3f483dffb747bbaac307552a627a5b248b03d0c565155c1c549b93a047f4f9df33ddc5d2ab0fdd51edfe",
    recovery: 0
  },
  {
    id: 1,
    prevId: 0,
    recipient: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    amount: 50,
    signature: "0xc2272cf09d7e8c56fef0a90584605387a7d5b8a3864ba41c32408c0ce4db23743d8a777c04d9de7cbb5fcab7499d5cf2624f2d344b465a253806be8b3f83b9c5",
    recovery: 0
  },
  {
    id: 2,
    prevId: 1,
    recipient: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    amount: 75,
    signature: "0x28f11afe0105361fb76a263032f892e38a3ec791a425dd06544c81041d3f96de7c13dbbb1418782dad2676b04fbde18c36633c918b0176b2b3eb9d7f18642d81",
    recovery: 0
  }
];

// TODO: Optionally calculate the case based checksums everywhere
app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const {validatedLedger} = validateLedger(transactions);
  let balances = getBalancesFromLedger(validatedLedger);
  const balance = balances[address.toLowerCase()] || 0;
  res.send({ balance });
});

app.get("/transactions", (req, res) => {
  const {validatedLedger} = validateLedger(transactions);
  res.send({ transactions: validatedLedger });
});

app.post("/send", (req, res) => {
  const { id, prevId, recipient, amount, signature, recovery } = req.body;

  const { validatedLedger, lastValidTxId } = validateLedger(transactions);
  let balances = getBalancesFromLedger(validatedLedger);

  const newTransaction = {
    id,
    prevId,
    recipient,
    amount,
    signature,
    recovery
  };

  if (isTransactionValid(newTransaction, lastValidTxId)) {

    const signatureStr = newTransaction.signature;
    let signature = SECP256k1.Signature.fromCompact(utils.removeHexPrefix(signatureStr));
    signature = signature.addRecoveryBit(newTransaction.recovery);
    const msgHash = getMsgHashFromTransaction(newTransaction);
    const pubKey = signature.recoverPublicKey(msgHash).toHex(false);
    let sender = utils.publicKeyToEthAddress(pubKey);

    setInitialBalance(sender.toLowerCase(), balances);
    setInitialBalance(recipient.toLowerCase(), balances);

    if (balances[sender.toLowerCase()] < amount) {
      // TODO handle not enough funds error in isTransactionValid?
      res.status(400).send({ message: "Not enough funds!" });
    } else {
      balances[sender.toLowerCase()] -= amount;
      balances[recipient.toLowerCase()] += amount;
      transactions.push(newTransaction);
      res.send({ balance: balances[sender.toLowerCase()] });
    }
  } else {
    res.status(400).send({ message: "The transaction is formally invalid (invalid signature or previous transaction ID)" });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function getBalancesFromLedger(ledger) {
  let balances = {};
  ledger.forEach(tx => {
    const signatureStr = tx.signature;
    let signature = SECP256k1.Signature.fromCompact(utils.removeHexPrefix(signatureStr));
    signature = signature.addRecoveryBit(tx.recovery);
    const msgHash = getMsgHashFromTransaction(tx);
    const pubKey = signature.recoverPublicKey(msgHash).toHex(false);
    let sender = utils.publicKeyToEthAddress(pubKey);
    setInitialBalance(sender.toLowerCase(), balances);
    setInitialBalance(tx.recipient.toLowerCase(), balances);
    balances[sender.toLowerCase()] -= tx.amount;
    balances[tx.recipient.toLowerCase()] += tx.amount;
  });
  console.log(balances);
  return balances;
}

function validateLedger(ledger) {
  let validatedLedger = [];
  let lastValidTxId = null;
  ledger.forEach(tx => {
    if (isTransactionValid(tx, lastValidTxId, validatedLedger)) {
      validatedLedger.push(tx);
      lastValidTxId = tx.id;
    }
  });
  return {validatedLedger, lastValidTxId};
}

function isTransactionValid(tx, lastValidTxId) {
  if (tx.prevId === lastValidTxId) {
    const signatureStr = tx.signature;
    const msgHash = getMsgHashFromTransaction(tx);
    let signature = SECP256k1.Signature.fromCompact(utils.removeHexPrefix(signatureStr));
    signature = signature.addRecoveryBit(tx.recovery);
    const pubKey = signature.recoverPublicKey(msgHash).toHex();
    if (SECP256k1.verify(signature, msgHash, pubKey)) {
      return true;
    } else {
      console.error("Transaction ID %d is invalid: invalid signature.", tx.id);
      return false;
    }
  } else {
    console.error("Transaction ID %d is invalid: previous transaction id is incorrect.", tx.id);
    return false;
  }
}

function getMsgHashFromTransaction(tx) {
  let txWithoutSig = Object.assign({}, tx);
  delete txWithoutSig.signature;
  delete txWithoutSig.recovery;
  const msgHash = KECCAK256(utf8ToBytes(JSON.stringify(txWithoutSig)));
  return msgHash;
}

function setInitialBalance(address, balances) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
