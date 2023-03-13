const { ethers, config } = require("hardhat");
const { sign, getPubKey } = require("../schnorr/sign");
const Buffer = require('safe-buffer').Buffer; 
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const convert = schnorr.convert;

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

function mapSignatureV(sigRaw) {
	const sig = ethers.utils.arrayify(sigRaw)
	if (sig[64] < 27) sig[64] += 27
	return ethers.utils.hexlify(sig)
}

function concatTypedArrays(a, b) { // a, b TypedArray of same type
  var c = new (a.constructor)(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

function wrapMagicBytes(sigRaw) {
  const magicBytes = '0x6492649264926492649264926492649264926492649264926492649264926492';
  const magicBytesArray = ethers.utils.arrayify(magicBytes);
  const sig = ethers.utils.arrayify(sigRaw);
  return ethers.utils.hexlify(concatTypedArrays(sig, magicBytesArray));
}

async function signAmbireSchnorr(sigRaw) {
	// assert.equal(hash.length, 32, 'hash must be 32byte array buffer')
	// was 01 originally but to avoid prefixing in solidity, we changed it to 00
	return `${sigRaw}${'04'}`
}

describe("UniversalSigValidator", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Netw;ork to that snapshot in every test.
  async function deployValidator() {

    // Contracts are deployed using the first signer/account by default
    const [signer, otherAccount] = await ethers.getSigners();
    const AmbireAccount = await ethers.getContractFactory("AmbireAccount");

    // get the public key
    const accounts = config.networks.hardhat.accounts
    const accountIndex = 0
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)
    const privateKey = wallet.privateKey
    const privateKeyHex = BigInteger.fromHex(privateKey.substring(2, privateKey.length));
    const publicKey = getPubKey(privateKeyHex);
    const schnorrAddress = ethers.utils.computeAddress(publicKey);
    const contract = await AmbireAccount.deploy([schnorrAddress]);
    const isSigner = await contract.privileges(schnorrAddress);
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001');

    return { contract, signer, otherAccount };
  }

  it("should generate a schnorr signature", async function () {
    const privateKeyHex = 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF';
    const privateKey = BigInteger.fromHex(privateKeyHex);
    const message = convert.hash(Buffer.from('i want to be free', 'utf8'));
    const createdSignature = schnorr.sign(privateKey, message);
    const createdSignatureFromHex = schnorr.sign(privateKeyHex, message);
  })
  it("should generate a schnorr signature", async function () {
    // deploy the contract
    const { contract, signer } = await loadFixture(deployValidator);

    // craft the signature
    const accounts = config.networks.hardhat.accounts
    const accountIndex = 0
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${accountIndex}`)
    const privateKey = wallet.privateKey
    const privateKeyHex = BigInteger.fromHex(privateKey.substring(2, privateKey.length));
    const bufferMsg = Buffer.from('i want to be free', 'utf8');
    // console.log(convert.hash(bufferMsg));
    // console.log(convert.hash('i want to be free'));
    // console.log(ethers.utils.hashMessage('i want to be free'));
    const {Px, e, s, parity} = sign(privateKeyHex, convert.hash(bufferMsg));

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      ethers.utils.hexlify(Px),
      ethers.utils.hexlify(convert.intToBuffer(e)),
      ethers.utils.hexlify(s),
      parity ? 28 : 27
    ]);
    const ambireSignature = await signAmbireSchnorr(sigData);
    const result = await contract.isValidSignature(convert.hash(bufferMsg), ambireSignature);
    console.log(result);
  })
});
