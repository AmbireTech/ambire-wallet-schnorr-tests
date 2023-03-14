const { ethers, config } = require("hardhat");
const secp256k1 = require('secp256k1')
const { randomBytes } = require('crypto');
const ERC1271_MAGICVALUE_BYTES32 = "0x1626ba7e";

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

async function signAmbireSchnorr(sigRaw) {
	// assert.equal(hash.length, 32, 'hash must be 32byte array buffer')
	// was 01 originally but to avoid prefixing in solidity, we changed it to 00
	return `${sigRaw}${'04'}`
}

describe("SchnorrTests", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Netw;ork to that snapshot in every test.
  async function deployContract() {

    // Contracts are deployed using the first signer/account by default
    const [signer, otherAccount] = await ethers.getSigners();
    const AmbireAccount = await ethers.getContractFactory("AmbireAccount");

    // get the public key
    const accounts = config.networks.hardhat.accounts
    const accountIndex = 0
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)
    const privateKey = ethers.utils.arrayify(wallet.privateKey);
    // 0x8fc45f9687181b4fdfc625bd1a753fa7397fed75
    const publicKey = secp256k1.publicKeyCreate(privateKey);
    const px = publicKey.slice(1, 33);
    const pxGeneratedAddress = ethers.utils.hexlify(px);
    const address = "0x" + pxGeneratedAddress.slice(pxGeneratedAddress.length - 40, pxGeneratedAddress.length);
    const contract = await AmbireAccount.deploy([address]);
    const isSigner = await contract.privileges(address);
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001');

    return { contract, signer, otherAccount };
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

  function sign(m, x) {
    var publicKey = secp256k1.publicKeyCreate(x);
  
    // R = G * k
    var k = randomBytes(32);
    var R = secp256k1.publicKeyCreate(k);
  
    // e = h(address(R) || compressed pubkey || m)
    var e = challenge(R, m, publicKey);
  
    // xe = x * e
    var xe = secp256k1.privateKeyTweakMul(x, e);
  
    // s = k + xe
    var s = secp256k1.privateKeyTweakAdd(k, xe);
    return {R, s, e};
  }

  it("should generate a schnorr signature", async function () {
    // deploy the contract
    const { contract, signer } = await loadFixture(deployContract);

    // get the Private key
    const accounts = config.networks.hardhat.accounts
    const accountIndex = 0
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)
    const privateKey = ethers.utils.arrayify(wallet.privateKey);
    const publicKey = secp256k1.publicKeyCreate(privateKey);

    // get the message
    const msg = 'just a test message';
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const sig = sign(msgHash, privateKey);
    const px = publicKey.slice(1, 33);
    const parity = publicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      sig.e,
      sig.s,
      parity
    ]);
    const ambireSignature = await signAmbireSchnorr(sigData);
    const result = await contract.isValidSignature(msgHash, ambireSignature);
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  })
});
