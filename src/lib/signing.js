// Signed provenance — the authorship + integrity layer for agent actions.
//
// Mirrors the three.ws server-side signing primitive (api/_lib/brain-sign.js):
// an action is canonicalized into stable bytes, SHA-256 digested, framed with a
// domain-separating version prefix, and ERC-191 `personal_sign`-signed by the
// agent's EVM wallet (the same secp256k1 key behind its ERC-8004 on-chain
// identity). Anyone holding the action record + the agent's address can
// `ecrecover` the signer and confirm the action was authored by that agent and
// has not been tampered with — provable provenance, not a database claim.
//
// These functions are pure crypto (no network, no DB): the same primitive a
// third party runs offline to verify another agent's trail. query_action calls
// verifyAction; append_agent_action calls signAction.

import { createHash } from 'node:crypto';

import { Wallet, verifyMessage, computeAddress } from 'ethers';

// Bump this prefix on any breaking change to the canonical form or message
// framing — old signatures stay verifiable against their own version string.
export const ACTION_SIG_VERSION = 'threews:action:v1';

/**
 * Deterministic, recursive JSON serialization with sorted object keys. Two
 * logically equal payloads always produce the same bytes regardless of key
 * insertion order — the precondition for a reproducible digest and signature.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function stableStringify(value) {
	if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
	const keys = Object.keys(value).sort();
	const body = keys
		.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
		.join(',');
	return `{${body}}`;
}

/**
 * Stable serialization of the signable fields of an action. Only the authorship
 * content is covered — the server-generated id and created_at are excluded
 * because the signature is produced before the action is appended, and a
 * verifier recomputes this same form from the stored record. Accepts the
 * snake_case ledger row shape or a camelCase equivalent.
 *
 * @param {object} action
 * @returns {string} canonical JSON string
 */
export function canonicalizeAction(action) {
	const agentId = action.agent_id ?? action.agentId ?? '';
	const type = action.type ?? '';
	const payload = action.payload ?? {};
	const sourceSkill = action.source_skill ?? action.sourceSkill ?? null;

	return stableStringify({
		v: ACTION_SIG_VERSION,
		agentId: String(agentId),
		type: String(type),
		payload,
		sourceSkill: sourceSkill == null ? null : String(sourceSkill),
	});
}

/**
 * SHA-256 (hex) of the canonical action form — a fast tamper check that needs
 * no elliptic-curve math.
 *
 * @param {object} action
 * @returns {string} 64-char lowercase hex digest
 */
export function actionDigest(action) {
	return createHash('sha256').update(canonicalizeAction(action)).digest('hex');
}

/**
 * The exact string that gets ERC-191 signed. Framing the digest with a
 * domain-separating prefix prevents an action signature from being replayed as
 * a signature over some other three.ws message (e.g. a memory).
 *
 * @param {string} digest hex digest from actionDigest
 * @returns {string}
 */
export function signMessageBody(digest) {
	return `${ACTION_SIG_VERSION}:${digest}`;
}

/**
 * Sign an action with a raw EVM private key. Pure crypto, no network. Returns
 * the ERC-191 signature, the recovered signer address, and the digest.
 *
 * @param {string} privKeyHex 0x-prefixed 32-byte private key
 * @param {object} action the action to sign (agent_id, type, payload, source_skill)
 * @returns {Promise<{ signature: string, signer_address: string, digest: string }>}
 */
export async function signAction(privKeyHex, action) {
	const wallet = new Wallet(normalizeKey(privKeyHex));
	const digest = actionDigest(action);
	const signature = await wallet.signMessage(signMessageBody(digest));
	return { signature, signer_address: wallet.address, digest };
}

/**
 * Derive the EVM address for a private key without signing — used to label the
 * signer in dry runs and to validate a configured key at append time.
 *
 * @param {string} privKeyHex 0x-prefixed 32-byte private key
 * @returns {string} checksummed 0x address
 */
export function addressForKey(privKeyHex) {
	return computeAddress(normalizeKey(privKeyHex));
}

/**
 * Verify an action record against a signature + claimed signer. Pure crypto —
 * the function any agent runs offline to trust another agent's provenance.
 *
 * @param {object} action the action (ledger row or decorated)
 * @param {object} [proof]
 * @param {string} [proof.signature] ERC-191 signature (defaults to action.signature)
 * @param {string} [proof.signer_address] claimed signer (defaults to action.signer_address)
 * @returns {{ valid: boolean, recovered: string|null, digest: string, reason: string }}
 */
export function verifyAction(action, proof = {}) {
	const signature = proof.signature ?? action.signature ?? null;
	const signerAddress = proof.signer_address ?? action.signer_address ?? null;
	const digest = actionDigest(action);

	if (!signature || !signerAddress) {
		return { valid: false, recovered: null, digest, reason: 'unsigned' };
	}

	let recovered = null;
	try {
		recovered = verifyMessage(signMessageBody(digest), signature);
	} catch {
		return { valid: false, recovered: null, digest, reason: 'malformed_signature' };
	}

	const valid = recovered.toLowerCase() === String(signerAddress).toLowerCase();
	return {
		valid,
		recovered,
		digest,
		reason: valid ? 'ok' : 'signer_mismatch',
	};
}

// ethers accepts a 0x-prefixed key; tolerate a bare 64-hex key by adding 0x.
function normalizeKey(privKeyHex) {
	const k = String(privKeyHex || '').trim();
	if (!k) {
		throw Object.assign(new Error('signer private key is empty'), { code: 'bad_signer_key' });
	}
	return k.startsWith('0x') ? k : `0x${k}`;
}
