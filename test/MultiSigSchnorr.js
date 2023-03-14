const { ethers, config } = require("hardhat");
const secp256k1 = require('secp256k1')
const { randomBytes } = require('crypto');
const ERC1271_MAGICVALUE_BYTES32 = "0x1626ba7e";
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const convert = schnorr.convert;

const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const two = BigInteger.valueOf(2);
const zero = BigInteger.ZERO;
const p = curve.p;
const n = curve.n;

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

async function signAmbireSchnorr(sigRaw) {
	// assert.equal(hash.length, 32, 'hash must be 32byte array buffer')
	// was 01 originally but to avoid prefixing in solidity, we changed it to 00
	return `${sigRaw}${'04'}`
}

describe("MultiSigSchnorr", function () {
    // multi sig schnorr

    // make two different public keys from 2 different private keys;
    // craft a signature for each;
    // sum up s1, s2 = s prime;
    // sum up the private keys and multiply them by G to get P prime;
    // the Px of P prime should be in the contract priviledges;
  async function deployContract() {

    // Contracts are deployed using the first signer/account by default
    const [signer, otherAccount] = await ethers.getSigners();
    const AmbireAccount = await ethers.getContractFactory("AmbireAccount");

    // get the public key
    const combinedPublicKey = getCombinedPubKey();
    const px = ethers.utils.hexlify(combinedPublicKey.slice(1,33));
    const pxGeneratedAddress = "0x" + px.slice(px.length - 40, px.length);
    const contract = await AmbireAccount.deploy([pxGeneratedAddress]);
    const isSigner = await contract.privileges(pxGeneratedAddress);
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001');

    return { contract, signer };
  }

  function challenge(R, m, publicKey) {
    // convert R to address
    // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
    var R_uncomp = secp256k1.publicKeyConvert(R, false);
    var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);
  
    // e = keccak256(address(R) || compressed publicKey || m)
    var e = ethers.utils.arrayify(ethers.utils.solidityKeccak256(
        ["address", "uint8", "bytes32", "bytes32"],
        [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), m]));
  
    return e;
  }

  function sign(x, k, e) {
    // xe = x * e
    var xe = secp256k1.privateKeyTweakMul(x, e);
  
    // s = k + xe
    return secp256k1.privateKeyTweakAdd(k, xe);
  }

  function getCombinedPubKey() {
    const accounts = config.networks.hardhat.accounts
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${0}`)
    const wallet2 = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${1}`)
    const publicKeyOne = secp256k1.publicKeyCreate(ethers.utils.arrayify(wallet.privateKey));
    const publicKeyTwo = secp256k1.publicKeyCreate(ethers.utils.arrayify(wallet2.privateKey));
    return secp256k1.publicKeyCombine([publicKeyOne, publicKeyTwo]);
  }

  function getKeyPair(accountIndex) {
    const accounts = config.networks.hardhat.accounts
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)
    const privateKey = ethers.utils.arrayify(wallet.privateKey);
    const privateKeyHex = BigInteger.fromHex(ethers.utils.hexlify(privateKey).replace(/^0[xX]/, ''));
    const P = G.multiply(privateKeyHex);
    return {privateKey, P};
  }

  it("should generate a schnorr signature", async function () {
    // deploy the contract
    const { contract, signer } = await loadFixture(deployContract);

    // craft signatures for private keys 0 and 1
    const msg = 'just a test message';
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);

    // get private key and secrets
    const {privateKey: privateKeyOne} = getKeyPair(0);
    const {privateKey: privateKeyTwo} = getKeyPair(1);
    const kOne = randomBytes(32);
    const kTwo = randomBytes(32);

    // R is the combined public key of the k secrets
    const R = secp256k1.publicKeyCombine([secp256k1.publicKeyCreate(kOne), secp256k1.publicKeyCreate(kTwo)]);
    // e = h(address(R) || compressed pubkey || m)
    const combinedPublicKey = getCombinedPubKey();
    const e = challenge(R, msgHash, combinedPublicKey);
    const sigOne = sign(privateKeyOne, kOne, e);
    const sigTwo = sign(privateKeyTwo, kTwo, e);

    const sSummedAsInt = BigInteger.fromBuffer(sigOne).add(BigInteger.fromBuffer(sigTwo)).mod(n);
    const sSummed = convert.intToBuffer(sSummedAsInt);

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sSummed,
      parity
    ]);
    const ambireSignature = await signAmbireSchnorr(sigData);
    const result = await contract.isValidSignature(msgHash, ambireSignature);
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  })
});
