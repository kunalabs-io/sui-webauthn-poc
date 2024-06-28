import { BCS, getSuiMoveConfig, fromB64, toHEX } from '@mysten/bcs'
import { secp256r1 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'

const bcs = new BCS(getSuiMoveConfig())

bcs.registerStructType('PasskeyAuthenticator', {
  authenticatorData: [BCS.VECTOR, BCS.U8],
  clientDataJson: BCS.STRING,
  userSignature: [BCS.VECTOR, BCS.U8],
})

export interface PasskeyAuthenticator {
  authenticatorData: Uint8Array
  clientDataJson: string
  userSignature: Uint8Array
}

const WEBAUTHN_FLAG = 0x06

/**
 * Encode a Sui WebAuthn signature from a authenticator response and the corresponding pubkey
 *
 * @param pubkey - either compressed or uncompressed
 * @param response - authenticator response
 */
export function encodeWebAuthnSignature(
  pubkey: Uint8Array, // either compressed or uncompressed
  response: AuthenticatorAssertionResponse
) {
  const authenticatorData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON) // response.clientDataJSON is already UTF-8 encoded JSON
  const decoder = new TextDecoder('utf-8');
  const clientDataJSONString: string = decoder.decode(clientDataJSON);

  const sig = secp256r1.Signature.fromDER(
    new Uint8Array(response.signature)
  )
  let before = sig.toCompactRawBytes()
  let normalized = sig.normalizeS().toCompactRawBytes()
  console.log(`before (hex): ${toHEX(before)}`)
  console.log(`after (hex): ${toHEX(normalized)}`)
  const compressedPubkey = secp256r1.ProjectivePoint.fromHex(pubkey).toRawBytes(true)
  const concatenatedArray = new Uint8Array(1+normalized.length + compressedPubkey.length);
  concatenatedArray.set([0x02]); // r1
  concatenatedArray.set(normalized, 1);
  concatenatedArray.set(compressedPubkey, 1+ normalized.length);

  let bytes = bcs
  .ser('PasskeyAuthenticator', {
    authenticatorData: authenticatorData,
    clientDataJson: clientDataJSONString,
    userSignature: concatenatedArray,
  })
  .toBytes();

  const zkloginSignatureArray = new Uint8Array(1+bytes.length);
  zkloginSignatureArray.set([WEBAUTHN_FLAG]);
  zkloginSignatureArray.set(bytes, 1);
  return zkloginSignatureArray;
}


export function serializePasskeySignature(
  authenticatorData: Uint8Array,
  clientDataJSON: String,
  signature: Uint8Array,
  pubkey: Uint8Array
) {
  const concatenatedArray = new Uint8Array(1+signature.length + pubkey.length);
  concatenatedArray.set([0x02]); // r1
  concatenatedArray.set(signature, 1);
  concatenatedArray.set(pubkey, 1+ signature.length);

  let bytes = bcs
    .ser('PasskeyAuthenticator', {
      authenticatorData: authenticatorData,
      clientDataJson: clientDataJSON,
      userSignature: concatenatedArray,
    })
    .toBytes();
    const signatureBytes = new Uint8Array(bytes.length + 1);
    signatureBytes.set([WEBAUTHN_FLAG]);
    signatureBytes.set(bytes, 1);
    return signatureBytes;
}

/**
 * Decode a Sui WebAuthn signature
 */
export function decodeWebAuthnSignature(signature: Uint8Array): PasskeyAuthenticator {
  const dec = bcs.de('PasskeyAuthenticator', signature.slice(1))
  return {
    authenticatorData: new Uint8Array(dec.authenticatorData),
    clientDataJson: dec.clientDataJson,
    userSignature: new Uint8Array(dec.userSignature),
  }
}

// POC, don't use in production, might be unsafe
export function base64UrlToBase64(base64Url: string): string {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
  const padding = base64.length % 4
  if (padding) {
    if (padding === 2) {
      base64 += '=='
    } else if (padding === 3) {
      base64 += '='
    }
  }
  return base64
}

// POC, don't use in production, might be unsafe
export function fromB64Url(base64Url: string): Uint8Array {
  return fromB64(base64UrlToBase64(base64Url))
}

export function bytesEqual(a: Uint8Array, b: Uint8Array) {
  if (a === b) return true

  if (a.length !== b.length) {
    return false
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

/**
 * Verifies a Sui WebAuthn signature
 *
 * @param challenge - the challenge that was sent to the authenticator (TX digest)
 */
export function verifyEncodedSignature(challenge: Uint8Array, signature: Uint8Array): boolean {
  const decoded = decodeWebAuthnSignature(signature)
  const clientDataJSON = JSON.parse(decoded.clientDataJson)
  const parsedChallenge = fromB64Url(clientDataJSON.challenge)
  if (!bytesEqual(challenge, parsedChallenge)) {
    return false
  }

  const message = new Uint8Array([...decoded.authenticatorData, ...sha256(decoded.clientDataJson)])
  console.log('sig', decoded.userSignature);
  let sig = decoded.userSignature.slice(1, 64 + 1);
  let pk = decoded.userSignature.slice(1 + 64);
  // ES256 (ECDSA w/ SHA-256)
  return secp256r1.verify(sig, sha256(message), pk)
}
