import * as simplewebauthn from '@simplewebauthn/server/helpers'
import { cose } from '@simplewebauthn/server/helpers'
import { AsnParser } from '@peculiar/asn1-schema'
import { ECDSASigValue } from '@peculiar/asn1-ecc'

export function decodeClientDataJSON(data: ArrayBuffer) {
  const decoder = new TextDecoder('utf-8')
  return JSON.parse(decoder.decode(data))
}

export function decodeAttestationObject(data: ArrayBuffer) {
  const map = simplewebauthn.decodeAttestationObject(new Uint8Array(data))
  return {
    fmt: map.get('fmt'),
    attStmt: mapToObject(map.get('attStmt') as Map<string, any>),
    authData: simplewebauthn.parseAuthenticatorData(map.get('authData')),
  }
}

function mapToObject(map: Map<string, any>) {
  const obj: Record<string, any> = {}

  for (const [key, value] of map) {
    if (value instanceof Map) {
      obj[key] = mapToObject(value) // Handle recursion for nested maps
    } else {
      obj[key] = value
    }
  }

  return obj
}

export function decodeCredentialPublicKey(data: ArrayBuffer): Uint8Array {
  const parsed = simplewebauthn.decodeCredentialPublicKey(new Uint8Array(data))

  if (!cose.isCOSEPublicKeyEC2(parsed)) {
    throw new Error('Expected EC2 public key')
  }

  const x = parsed.get(cose.COSEKEYS.x)
  const y = parsed.get(cose.COSEKEYS.y)

  if (!x || !y) {
    throw new Error('Expected x and y')
  }

  return new Uint8Array([0x04, ...x, ...y]) // https://stackoverflow.com/a/67085192
}

export function decodeAuthenticatorData(data: ArrayBuffer) {
  return simplewebauthn.parseAuthenticatorData(new Uint8Array(data))
}

/**
 * Parses a DER SubjectPublicKeyInfo into an uncompressed public key. This also verifies
 * that the curve used is P-256 (secp256r1).
 *
 * @param data: DER SubjectPublicKeyInfo
 * @returns uncompressed public key (`0x04 || x || y`)
 */
export async function parseDerSPKI(der: ArrayBuffer): Promise<Uint8Array> {
  const key = await window.crypto.subtle.importKey(
    'spki',
    der,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    []
  )
  return new Uint8Array(await window.crypto.subtle.exportKey('raw', key))
}

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 *
 * This code is taken from https://github.com/MasterKale/SimpleWebAuthn/blob/f21955a5947f575858db0cd9ee728abc6b5f4310/packages/server/src/helpers/iso/isoCrypto/unwrapEC2Signature.ts
 */
export function unwrapSignature(signature: BufferSource): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue)
  let rBytes = new Uint8Array(parsedSignature.r)
  let sBytes = new Uint8Array(parsedSignature.s)

  /**
   * Determine if the DER-specific `00` byte at the start of an ECDSA signature byte sequence
   * should be removed based on the following logic:
   *
   * "If the leading byte is 0x0, and the the high order bit on the second byte is not set to 0,
   * then remove the leading 0x0 byte"
   */
  const shouldRemoveLeadingZero = (bytes: Uint8Array) =>
    bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1)
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1)
  }

  // const finalSignature = isoUint8Array.concat([rBytes, sBytes])

  return new Uint8Array([...rBytes, ...sBytes])
}
