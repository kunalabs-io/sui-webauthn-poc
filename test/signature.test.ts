// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromB64, fromHEX, toB64, toHEX } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';
import {
	serializePasskeySignature, decodeWebAuthnSignature
} from '../src/sui';

describe('valid serde for passkey authenticator', () => {
	it('parse valid', () => {
		const client_data = `{"type":"webauthn.get","challenge":"AAAAt_mjIB1vbVpYM6WV6Y_oix6J8aN_9sb8SKFbukBfiQw","origin":"http://localhost:5173","crossOrigin":false}`;
		const encoded = fromB64("BiVJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XYx0AAAAAigF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCJjaGFsbGVuZ2UiOiJBQUFBdF9taklCMXZiVnBZTTZXVjZZX29peDZKOGFOXzlzYjhTS0ZidWtCZmlRdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZX1iApjskL9Xyfopyg9Av7MSrcchSpfWqAYoJ+qfSId4gNmoQ1YNgj2alDpRIbq9kthmyGY25+k24FrW114PEoy5C+8DPRcOCTtACi3ZywtZ4UILhwV+Suh79rWtbKqDqhBQwxM=");
		const decoded = decodeWebAuthnSignature(encoded);
		expect(decoded.clientDataJson).toBe(client_data);
	});
});
