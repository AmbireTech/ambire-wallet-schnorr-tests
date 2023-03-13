const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const schnorr = require('bip-schnorr');
const { ethers } = require('hardhat');
const math = schnorr.math
const check = schnorr.check
const convert = schnorr.convert

const concat = Buffer.concat;
const G = curve.G;
const n = curve.n;

function getPubKey(privateKey) {
  const P = G.multiply(privateKey);
  const Px = convert.intToBuffer(P.affineX);
  return ethers.utils.hexlify(Px);
}

function sign(privateKey, message, aux) {
  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#signing
  check.checkSignParams(privateKey, message);
  privateKey = typeof (privateKey) == 'string' ? BigInteger.fromHex(privateKey) : privateKey;

  const P = G.multiply(privateKey);
  const Px = convert.intToBuffer(P.affineX);

  const d = privateKey;
  let kPrime
  if (aux) {
    check.checkAux(aux);

    const t = convert.intToBuffer(d.xor(convert.bufferToInt(math.taggedHash('BIP0340/aux', aux))));
    const rand = math.taggedHash('BIP0340/nonce', concat([t, Px, message]))
    kPrime = convert.bufferToInt(rand).mod(n);
  } else {
    kPrime = math.deterministicGetK0(d, Px, message);
  }

  if (kPrime.signum() === 0) {
    throw new Error('kPrime is zero');
  }

  const k = kPrime;
  const R = G.multiply(k);
  const Rx = convert.intToBuffer(R.affineX);
  const parity = math.isEven(P);
  const e = getE(Rx, Px, parity, message);

  // R = G*k
  // e = h(address(R) || m)
  // s = k + x*e
  // Signature = (e, s) or (R, s)

  return {
    s: convert.intToBuffer(k.add(e.multiply(d)).mod(n)),
    Px,
    e,
    parity
  }
}

function getE(Rx, Px, parity, m) {
  // we can try h(address(R) || m)
  // and one other option...
  // h can be ethers.utils.hexlify...
  // it can also be a taggedHash.
  // also, I don't know if we need mod(n) or not
  const addressR = Buffer.from(ethers.utils.computeAddress(Rx));
  const intParity = Buffer.from([parity ? 28 : 27]);
  const hash = convert.hash(concat([addressR, Px, intParity, m])); // think whether this hash is OK
  return convert.bufferToInt(hash).mod(n);
}

module.exports = {
  sign,
  getPubKey
};
  