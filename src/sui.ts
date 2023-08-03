import { BCS, getSuiMoveConfig, fromB64 } from '@mysten/bcs'
import { secp256r1 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'

const bcs = new BCS(getSuiMoveConfig())

// `@mysten/bcs` library doesn't have a generic fixed length sequence type
// so we need to register the "signature" and "pubkey" types manually
bcs.registerType(
  'signature',
  function encodeSignature(writer, data: Uint8Array) {
    if (data.length !== 64) {
      throw new Error(`Signature must be 64 bytes, got ${data.length}`)
    }
    for (const byte of data) {
      writer.write8(byte)
    }
    return writer
  },
  function decodePubkey(reader) {
    return reader.readBytes(64)
  }
)

bcs.registerType(
  'pubkey',
  function encodePubkey(writer, data: Uint8Array) {
    if (data.length !== 33) {
      throw new Error(`Signature must be 64 bytes, got ${data.length}`)
    }
    for (const byte of data) {
      writer.write8(byte)
    }
    return writer
  },
  function decodePubkey(reader) {
    return reader.readBytes(33)
  }
)

bcs.registerStructType('WebAuthnSignature', {
  flag: BCS.U8,
  authenticatorData: [BCS.VECTOR, BCS.U8],
  clientDataJSON: [BCS.VECTOR, BCS.U8],
  signature: 'signature',
  pubkey: 'pubkey',
})

export interface WebAuthnSignature {
  flag: number
  authenticatorData: Uint8Array
  clientDataJSON: Uint8Array
  signature: Uint8Array
  pubkey: Uint8Array
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
  const signature = secp256r1.Signature.fromDER(
    new Uint8Array(response.signature)
  ).toCompactRawBytes()
  const compressedPubkey = secp256r1.ProjectivePoint.fromHex(pubkey).toRawBytes(true)

  return bcs
    .ser('WebAuthnSignature', {
      flag: WEBAUTHN_FLAG,
      authenticatorData,
      clientDataJSON,
      signature,
      pubkey: compressedPubkey,
    })
    .toBytes()
}

/**
 * Decode a Sui WebAuthn signature
 */
export function decodeWebAuthnSignature(signature: Uint8Array): WebAuthnSignature {
  const dec = bcs.de('WebAuthnSignature', signature)

  return {
    flag: dec.flag,
    authenticatorData: new Uint8Array(dec.authenticatorData),
    clientDataJSON: new Uint8Array(dec.clientDataJSON),
    signature: new Uint8Array(dec.signature),
    pubkey: new Uint8Array(dec.pubkey),
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

  const clientDataJSON = JSON.parse(new TextDecoder().decode(decoded.clientDataJSON))
  const parsedChallenge = fromB64Url(clientDataJSON.challenge)
  if (!bytesEqual(challenge, parsedChallenge)) {
    return false
  }

  const message = new Uint8Array([...decoded.authenticatorData, ...sha256(decoded.clientDataJSON)])

  // ES256 (ECDSA w/ SHA-256)
  return secp256r1.verify(decoded.signature, sha256(message), decoded.pubkey)
}
