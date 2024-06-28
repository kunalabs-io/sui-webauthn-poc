import './index.css'
import { AuthenticationCredential, RegistrationCredential } from '@simplewebauthn/typescript-types'
import { sha256 } from '@noble/hashes/sha256'
import { toHEX, toB64 } from '@mysten/bcs'
import { secp256r1 } from '@noble/curves/p256'
import { findPossiblePublicKeys, messageFromAssertionResponse } from './crypto'
import { decodeWebAuthnSignature, encodeWebAuthnSignature, verifyEncodedSignature } from './sui'
import { parseDerSPKI } from './util'
import { blake2b } from '@noble/hashes/blake2b';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { getFullnodeUrl, SuiClient } from '@mysten/sui.js/client';
import { getFaucetHost, requestSuiFromFaucetV0 } from '@mysten/sui.js/faucet';
import { bytesToHex } from '@noble/hashes/utils'
import { SUI_ADDRESS_LENGTH, normalizeSuiAddress } from '@mysten/sui.js/utils'

function clearOutput() {
  document.getElementById('output')!.innerText = ''
}

function log(message: string | string[]) {
  if (typeof message === 'string') {
    message = [message]
  }

  for (const line of message) {
    document.getElementById('output')!.innerText += line + '\n\n'
  }
}

const toggleButton = (id: string, enabled: boolean) => {
  const btn = document.getElementById(id) as HTMLButtonElement
  btn.disabled = !enabled
}

class Store {
  #pubkey?: Uint8Array
  credentialId?: Uint8Array
  supportsLargeBlob?: boolean
  address?: string
  txBytes?: Uint8Array
  client = new SuiClient({ url: getFullnodeUrl('localnet') });

  ecdsaRecovery: {
    credentialId?: Uint8Array
    sig1?: Uint8Array
    message1?: Uint8Array
  } = { credentialId: undefined, sig1: undefined, message1: undefined }

  set pubkey(value: Uint8Array | undefined) {
    this.#pubkey = value
    toggleButton('sign', !!value)
    toggleButton('store-largeBlob', !!value)
  }

  get pubkey() {
    return this.#pubkey
  }
}

const store = new Store()

addEventListener('load', () => {
  const onClick = (id: string, onClick: () => void) =>
    document.getElementById(id)!.addEventListener('click', onClick)

  // Register click handlers
  onClick('create', () => createHandler())
  onClick('fund-and-create-tx', () => createTxHandler())
  onClick('sign', () => signHandler())
  onClick('recover-ecdsa', () => recoverEcdsa())
  onClick('recover-largeBlob', () => recoverLargeBlobHandler())
  onClick('store-largeBlob', () => storeLargeBlobHandler())

  toggleButton('sign', false)
  toggleButton('store-largeBlob', false)
})

async function createHandler() {
  clearOutput()

  const randomString = (length: number) => {
    return Array(length)
      .fill('')
      .map(() => String.fromCharCode(Math.random() * 26 + 65))
      .join('')
  }
  const credential = (await navigator.credentials.create({
    publicKey: {
      // The challenge is not important here. It would normally be used to verify the attestation.
      challenge: new TextEncoder().encode("Don't trust, verify!"),
      rp: {
        name: 'Sui WebAuthn POC'
      },
      user: {
        id: Uint8Array.from(randomString(10), c => c.charCodeAt(0)),
        name: 'wallet-user',
        displayName: 'Wallet User',
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // -7 is ES256
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'required',
        requireResidentKey: true, // this may already be default
        userVerification: 'required',
      },
      timeout: 60000,
      extensions: {
        largeBlob: {
          support: 'preferred',
        },
      } as any,
    },
  })) as RegistrationCredential

  // decode the pubkey
  const derSPKI = credential.response.getPublicKey()!
  const pubkeyUncompressed = await parseDerSPKI(derSPKI) // this also verifies that the P-256 (secp256r1) curve is used

  const pubkey = secp256r1.ProjectivePoint.fromHex(pubkeyUncompressed)

  const pubkeyCompressed = pubkey.toRawBytes(true)
  const credentialId = new Uint8Array(credential.rawId)

  const supportsLargeBlob =
    (credential.getClientExtensionResults() as any).largeBlob.supported === true
  let pk_bytes = pubkey.toRawBytes(true);
  let extended = new Uint8Array(34);
  extended.set([6]);
  extended.set(pk_bytes, 1);
  let address = normalizeSuiAddress(
    bytesToHex(blake2b(extended, { dkLen: 32 })).slice(0, SUI_ADDRESS_LENGTH * 2),
  );

    log([
    'Passkey created!',
    `pubkey (hex): ${toHEX(pubkeyCompressed)}`,
    `credential ID (base64): ${toB64(credentialId)}`,
    `sui address: ${address}`,
    `supports largeBlob: ${supportsLargeBlob}`,
  ])

  store.pubkey = pubkey.toRawBytes(true)
  store.credentialId = credentialId
  store.supportsLargeBlob = supportsLargeBlob
  store.address = address

  /*
  Alternate way of decoding the pubkey (through parsing attestationObject):

  const clientDataJSON = decodeClientDataJSON(credential.response.clientDataJSON)
  const attestationObject = decodeAttestationObject(credential.response.attestationObject)

  if (!attestationObject.authData.credentialPublicKey) {
    throw new Error('No credentialPublicKey')
  }

  const credentialPublicKey = decodeCredentialPublicKey(
    attestationObject.authData.credentialPublicKey
  )

  // TODO: make sure P-256 (secp256r1) curve is used

  const x = credentialPublicKey[-2] as Uint8Array
  const y = credentialPublicKey[-3] as Uint8Array
  const pubkeyUncompressed = new Uint8Array([4, ...x, ...y]) // https://stackoverflow.com/a/67085192
  */
}

async function createTxHandler() {
  let address = store.address!;
	const tx = new TransactionBlock();

  await requestSuiFromFaucetV0({
    host: getFaucetHost('localnet'),
    recipient: address,
  });
  let coins = await store.client.getCoins({
    owner: address,
    coinType: "0x2::sui::SUI",
  });
  const coin = coins.data[3];

	tx.setSender(address);
	tx.setGasPrice(1000);
	tx.setGasBudget(2000000);
  tx.setGasPayment([
    {
      objectId: coin.coinObjectId,
      version: coin.version,
      digest: coin.digest,
    },
  ]);
  let bytes = await tx.build();
  store.txBytes = bytes;
  log([
    'Address funded and prepared a test txn!',
    `sui address: ${address}`,
    `tx: ${toB64(bytes)}`,
  ])
}

async function signHandler() {
  clearOutput()

  const digest = blake2b(store.txBytes!, { dkLen: 32 });
  let extended = new Uint8Array(35);
  extended.set([0, 0, 0]);
  extended.set(digest, 3);

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: extended,
      // allowCredentials, // optional
      userVerification: 'discouraged',
    },
  })) as AuthenticationCredential

  const encoded = encodeWebAuthnSignature(store.pubkey!, credential.response)
  const decoded = decodeWebAuthnSignature(encoded)

  const result = verifyEncodedSignature(extended, encoded)
  console.log('result', result)
  const onchainResult = await store.client.executeTransactionBlock({
	transactionBlock: toB64(store.txBytes!),
	signature: toB64(encoded),
	options: {
		showEffects: true,
	},
});

  log([
    `credential id (base64): ${toB64(new Uint8Array(credential.rawId))}`,
    `pubkey (hex): ${toHEX(store.pubkey!)}`,
    `sui address: ${store.address}`,
    `tx bytes: ${toB64(store.txBytes!)}`,
    `tx digest (hex): ${toHEX(extended)}`,
    `authenticatorData (hex): ${toHEX(decoded.authenticatorData)}`,
    `clientDataJSON: \`${decoded.clientDataJson}\``,
    `r1 signature (hex): ${toHEX(decoded.userSignature)}`,
    `encoded sui signature (base64): ${toB64(encoded)}`,
    `encoded webuahthn signature length: ${encoded.length}`,
    `signature verified: ${result}`,
    `localnet onchain verified, digest: ${onchainResult.digest}`,
    `localnet onchain verified, sig: ${onchainResult.transaction?.txSignatures}`,
  ])
}


async function recoverEcdsa() {
  clearOutput()

  store.pubkey = undefined
  store.credentialId = undefined

  const challenge = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    challenge[i] = Math.floor(Math.random() * 256)
  }

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: 'required',
    },
  })) as AuthenticationCredential

  const rawId = new Uint8Array(credential.rawId)
  const signature = secp256r1.Signature.fromDER(
    new Uint8Array(credential.response.signature)
  ).toCompactRawBytes()
  const message = messageFromAssertionResponse(credential.response)

  const uint8ArrayEqual = (a: Uint8Array, b: Uint8Array) => {
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
  if (
    !store.ecdsaRecovery.credentialId ||
    !uint8ArrayEqual(store.ecdsaRecovery.credentialId, rawId) ||
    !store.ecdsaRecovery.message1
  ) {
    store.ecdsaRecovery.credentialId = rawId
    store.ecdsaRecovery.sig1 = signature
    store.ecdsaRecovery.message1 = message

    log('First signature received, press "Recover pubkey (ECDSA recover)" button again!')
    return
  }

  const sig1 = store.ecdsaRecovery.sig1!
  const message1 = store.ecdsaRecovery.message1!
  const sig2 = signature
  const message2 = message

  console.log('sig1', sig1)
  console.log('sig2', sig2)
  console.log('message1', message1)
  console.log('message2', message2)

  log([
    'Both signatures received',
    `sig 1 (hex): ${toHEX(store.ecdsaRecovery.sig1!)}`,
    `sig 2 (hex): ${toHEX(signature)}`,
    `message 1 (hex): ${toHEX(message1)}`,
    `message 2 (hex): ${toHEX(message2)}`,
  ])

  const potential1 = findPossiblePublicKeys(sig1, sha256(message1))
  const potential2 = findPossiblePublicKeys(sig2, sha256(message2))

  console.log('potential1', potential1)
  console.log('potential2', potential2)

  log(
    `potential pubkeys 1 (hex): ${JSON.stringify(
      potential1.map(p => toHEX(p)),
      null,
      2
    )}`
  )
  log(
    `potential pubkeys 2 (hex): ${JSON.stringify(
      potential2.map(p => toHEX(p)),
      null,
      2
    )}`
  )

  const matchingPubkeys: Uint8Array[] = []
  for (const pubkey1 of potential1) {
    for (const pubkey2 of potential2) {
      if (uint8ArrayEqual(pubkey1, pubkey2)) {
        matchingPubkeys.push(pubkey1)
      }
    }
  }

  store.ecdsaRecovery.credentialId = undefined
  store.ecdsaRecovery.sig1 = undefined
  store.ecdsaRecovery.message1 = undefined

  if (matchingPubkeys.length !== 1) {
    log(
      `matching pubkeys (hex): ${JSON.stringify(
        matchingPubkeys.map(p => toHEX(p)),
        null,
        2
      )}`
    )

    log('No pubkey recovered -- num matching pubkeys != 1')
    return
  }

  const recoveredPubkey = matchingPubkeys[0]

  log(`recovered pubkey (hex): ${toHEX(recoveredPubkey)}`)

  store.credentialId = rawId
  store.pubkey = recoveredPubkey
}

async function storeLargeBlobHandler() {
  clearOutput()

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(0),
      allowCredentials: [
        {
          id: store.credentialId!,
          type: 'public-key',
        },
      ],
      extensions: {
        largeBlob: {
          write: store.pubkey,
        },
      } as any,
      userVerification: 'required',
    },
  })) as AuthenticationCredential

  if (!(credential.getClientExtensionResults() as any).largeBlob.written) {
    log('Failed to write blob')
    return
  }

  log(`credential id (base64): ${toB64(new Uint8Array(credential.rawId))}`)
  log(`pubkey stored (hex): ${toHEX(store.pubkey!)}`)
}

async function recoverLargeBlobHandler() {
  clearOutput()

  store.pubkey = undefined
  store.credentialId = undefined

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(0),
      extensions: {
        largeBlob: {
          read: true,
        },
      } as any,
      userVerification: 'required',
    },
  })) as AuthenticationCredential

  const blob = (credential.getClientExtensionResults() as any).largeBlob.blob as
    | undefined
    | ArrayBuffer
  if (!blob) {
    log('No blob found')
    return
  }

  console.log('pubkey', new Uint8Array(blob))

  log(`credential id (base64): ${toB64(new Uint8Array(credential.rawId))}`)
  log(`pubkey recovered (hex): ${toHEX(new Uint8Array(blob))}`)

  store.credentialId = new Uint8Array(credential.rawId)
  store.pubkey = new Uint8Array(blob)
}