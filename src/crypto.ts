import { AuthenticatorAssertionResponse } from '@simplewebauthn/typescript-types'
import { secp256r1 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'
import { unwrapSignature } from './util'

/**
 *  This is an example of how to verify a WebAuthn signature using the the native WebCrypto API.
 */
export async function verifySignatureWebCrypto(
  pubkeyUncompressed: Uint8Array,
  response: AuthenticatorAssertionResponse
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    'raw',
    pubkeyUncompressed,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  )

  const authenticatorData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = response.clientDataJSON
  const signature = unwrapSignature(response.signature)

  const clientDataJSONDigest = new Uint8Array(
    await window.crypto.subtle.digest('SHA-256', clientDataJSON)
  )

  const message = new Uint8Array([...authenticatorData, ...clientDataJSONDigest])

  return await window.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    publicKey,
    signature,
    message
  )
}

/**
 * WARNING: this is a POC and should not be used in production as it might be unsafe.
 *
 * Finds all possible public keys that could have been used to sign a message.
 * There might be a more efficient way to do this https://github.com/richardkiss/pycoin/blob/b41ad7d02e52d9869a8c9f0dbd7d3b2b496c98c0/pycoin/ecdsa/Generator.py#L79-L111
 */
export function findPossiblePublicKeys(sig: Uint8Array, message: Uint8Array): Uint8Array[] {
  const res = []

  for (let i = 0; i < 4; i++) {
    const s = secp256r1.Signature.fromCompact(sig).addRecoveryBit(i)
    try {
      const pubkey = s.recoverPublicKey(message)
      res.push(pubkey.toRawBytes(true))
    } catch {
      continue
    }
  }

  return res
}

/**
 * Constructs the message that the WebAuthn signature is produced over.
 */
export function messageFromAssertionResponse(response: AuthenticatorAssertionResponse): Uint8Array {
  const authenticatorData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON)

  const clientDataJSONDigest = sha256(clientDataJSON)

  return new Uint8Array([...authenticatorData, ...clientDataJSONDigest])
}
