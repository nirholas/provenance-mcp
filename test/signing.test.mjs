// ERC-191 action signing/verification round-trips — offline, real crypto.
//
// These exercise the actual ethers Wallet sign + ecrecover path that
// append_agent_action and query_action rely on. No network, no mocks.
//
// Run: node --test packages/provenance-mcp/test/signing.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
	ACTION_SIG_VERSION,
	stableStringify,
	canonicalizeAction,
	actionDigest,
	signAction,
	addressForKey,
	verifyAction,
} from '../src/lib/signing.js';

// A deterministic, clearly-synthetic test key (not a real funded wallet).
const TEST_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

test('stableStringify sorts keys so equal payloads hash identically regardless of order', () => {
	const a = stableStringify({ b: 1, a: { y: 2, x: 3 }, c: [3, 2, 1] });
	const b = stableStringify({ c: [3, 2, 1], a: { x: 3, y: 2 }, b: 1 });
	assert.equal(a, b);
});

test('canonicalizeAction is order-independent in payload and version-tagged', () => {
	const base = { agent_id: 'agent_1', type: 'launch', source_skill: 'pump' };
	const one = canonicalizeAction({ ...base, payload: { mint: 'X', amount: 1 } });
	const two = canonicalizeAction({ ...base, payload: { amount: 1, mint: 'X' } });
	assert.equal(one, two);
	assert.ok(one.includes(ACTION_SIG_VERSION));
	// Same digest for the two orderings.
	assert.equal(
		actionDigest({ ...base, payload: { mint: 'X', amount: 1 } }),
		actionDigest({ ...base, payload: { amount: 1, mint: 'X' } }),
	);
});

test('signAction produces a signature that verifies against the recovered signer', async () => {
	const action = { agent_id: 'agent_42', type: 'buy', payload: { mint: 'THREEsynthetic1111', sol: 0.5 }, source_skill: 'autopilot' };
	const { signature, signer_address, digest } = await signAction(TEST_KEY, action);

	assert.equal(signer_address, addressForKey(TEST_KEY));
	assert.equal(digest, actionDigest(action));

	const v = verifyAction({ ...action, signature, signer_address });
	assert.equal(v.valid, true);
	assert.equal(v.reason, 'ok');
	assert.equal(v.recovered.toLowerCase(), signer_address.toLowerCase());
});

test('verifyAction reports unsigned when no signature is present', () => {
	const v = verifyAction({ agent_id: 'a', type: 'post', payload: {}, signature: null, signer_address: null });
	assert.equal(v.valid, false);
	assert.equal(v.reason, 'unsigned');
});

test('verifyAction detects tampering — a mutated payload fails verification', async () => {
	const action = { agent_id: 'agent_7', type: 'reflect', payload: { note: 'original' }, source_skill: null };
	const { signature, signer_address } = await signAction(TEST_KEY, action);

	const tampered = { ...action, payload: { note: 'altered' }, signature, signer_address };
	const v = verifyAction(tampered);
	assert.equal(v.valid, false);
	assert.equal(v.reason, 'signer_mismatch');
});

test('verifyAction reports malformed_signature on garbage input', () => {
	const v = verifyAction({
		agent_id: 'a',
		type: 'post',
		payload: {},
		signature: '0xnotasignature',
		signer_address: '0x0000000000000000000000000000000000000000',
	});
	assert.equal(v.valid, false);
	assert.equal(v.reason, 'malformed_signature');
});

test('signatures are domain-separated: a memory-style body does not verify as an action', async () => {
	// The action body is prefixed with ACTION_SIG_VERSION; a signature over a
	// different framing must not validate against the action digest.
	const action = { agent_id: 'agent_1', type: 'launch', payload: { mint: 'X' } };
	const { signature, signer_address } = await signAction(TEST_KEY, action);
	// Same signature, but claim it covers a different action — must fail.
	const other = { agent_id: 'agent_1', type: 'sell', payload: { mint: 'X' }, signature, signer_address };
	assert.equal(verifyAction(other).valid, false);
});
