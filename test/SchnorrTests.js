const { ethers } = require("hardhat");

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

var fs = require('fs');
var path = require('path');

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

async function signMsg(wallet, message, useFinalDigestSigMode = false) {
	// assert.equal(hash.length, 32, 'hash must be 32byte array buffer')
	// was 01 originally but to avoid prefixing in solidity, we changed it to 00
	return `${mapSignatureV(await wallet.signMessage(message))}${useFinalDigestSigMode ? '00' : '01'}`
}

describe("UniversalSigValidator", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployValidator() {

    // Contracts are deployed using the first signer/account by default
    const [signer, otherAccount] = await ethers.getSigners();

    // const UniversalSigValidator = await ethers.getContractFactory("UniversalSigValidator");
    // const contract = await UniversalSigValidator.deploy();

    return { signer, otherAccount };
  }

  it("Should deploy validator", async function () {
    const { signer } = await loadFixture(deployValidator);
    const AmbireAccount = await ethers.getContractFactory("AmbireAccount");
    const accounntSC = await AmbireAccount.deploy([signer.address]);

    // confirm set priviledges
    const isSigner = await accounntSC.privileges(signer.address);
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001');
  });
});
