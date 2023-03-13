const { ethers, config } = require("hardhat");
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const convert = schnorr.convert;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const { randomBytes } = require('crypto');
const G = curve.G;
const hexToBN = s => ethers.BigNumber.from(s);
const Q = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
const halfQ = hexToBN(Q).div(2).add(ethers.BigNumber.from(1));

const groupOrder = hexToBN(
  // Number of points in secp256k1
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
)
const two = BigInteger.valueOf(2);
const zero = BigInteger.ZERO;

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

describe("ChainLinkSchnorr", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Netw;ork to that snapshot in every test.
  async function deployContract() {

    // Contracts are deployed using the first signer/account by default
    const [signer, otherAccount] = await ethers.getSigners();
    const ChainLinkSchnorr = await ethers.getContractFactory("ChainLinkSchnorr");
    const contract = await ChainLinkSchnorr.deploy();
    expect(contract.address).to.not.be.null;

    return { contract, signer, otherAccount };
  }

  it("should generate a schnorr signature and pass the chainlink contract verifier", async function () {
    const { contract, signer, otherAccount } = await loadFixture(deployContract);

    // get the message
    const msg = 'just a test message';
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);

    // get the private -> pub key
    const accounts = config.networks.hardhat.accounts
    const accountIndex = 0
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)

    // the PKx needs to be below halfQ in order to pass ecrecover
    let isPKxAboveHalfQ = true;
    let counter = -1;
    let privateKey, privateKeyHex, P, PKx;
    while (isPKxAboveHalfQ) {
      counter++;
      privateKey = ethers.utils.hexlify(ethers.BigNumber.from(wallet.privateKey).add(ethers.BigNumber.from(counter)));
      privateKeyHex = BigInteger.fromHex(privateKey.replace(/^0[xX]/, ''));
      P = G.multiply(privateKeyHex);
      PKx = convert.intToBuffer(P.affineX);
      isPKxAboveHalfQ = ethers.BigNumber.from(PKx).sub(halfQ) > 0;
    }
    const pubKeyYParity = P.affineY.mod(two).equals(zero) ? 0 : 1

    const k = hexToBN(randomBytes(32));
    const kTimesGAddress = ethers.utils.computeAddress(k);

    const e = hexToBN(
      ethers.utils.solidityKeccak256(
        ['bytes', 'bytes', 'bytes', 'bytes'],
        [
          ethers.utils.hexlify(PKx),
          ethers.utils.hexlify(pubKeyYParity ? '0x01' : '0x00'),
          ethers.utils.hexlify(msgHash),
          ethers.utils.hexlify(kTimesGAddress)
        ]
      )
    )

    const s = k.sub(e.mul(privateKey)).mod(groupOrder);

    const isValid = await contract.verifySignature(
      PKx,
      pubKeyYParity,
      s,
      msgHash,
      kTimesGAddress
    );
    expect(isValid).to.be.true;
  })
});
