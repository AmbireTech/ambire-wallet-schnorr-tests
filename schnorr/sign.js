const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const schnorr = require('bip-schnorr');
const math = schnorr.math
const check = schnorr.check
const convert = schnorr.convert

const concat = Buffer.concat;
const G = curve.G;
const n = curve.n;

function sign(privateKey, message, aux) {
  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#signing
  check.checkSignParams(privateKey, message);
  privateKey = typeof (privateKey) == 'string' ? BigInteger.fromHex(privateKey) : privateKey;

  const P = G.multiply(privateKey);
  const Px = convert.intToBuffer(P.affineX);

  const d = math.getEvenKey(P, privateKey);
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

  const R = G.multiply(kPrime);
  const k = math.getEvenKey(R, kPrime);
  const Rx = convert.intToBuffer(R.affineX);
  const e = math.getE(Rx, Px, message);
  return {
    s: concat([Rx, convert.intToBuffer(k.add(e.multiply(d)).mod(n))]),
    // s: convert.intToBuffer(k.add(e.multiply(d)).mod(n)),
    Px,
    e,
    parity: math.isEven(P)
  }
}

module.exports = {
  sign
};
  