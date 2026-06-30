// Centralized env + HTTP base for the provenance MCP.
//
// This server wraps the three.ws agent action-provenance ledger
// (/api/agent-actions): an append-only, owner-scoped history of every action an
// agent took. The ledger authenticates every call, so a bearer token is
// required for all tools. The append tool can additionally ERC-191-sign each
// action with an EVM key, making authorship publicly verifiable on-chain.

export function env(key, fallback) {
	const v = process.env[key];
	return v !== undefined && String(v).trim() !== '' ? String(v).trim() : fallback;
}

// Base URL of the three.ws API. Override only when self-hosting or pointing at a
// preview deployment.
export const THREE_WS_BASE = env('THREE_WS_BASE', 'https://three.ws').replace(/\/+$/, '');

// Per-request timeout (ms). The ledger reads are cursor-paginated index scans
// and the append is a single insert — fast, but generous enough to ride out a
// cold edge.
export const HTTP_TIMEOUT_MS = (() => {
	const raw = env('THREE_WS_TIMEOUT_MS');
	if (raw === undefined) return 20000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n <= 0) {
		throw Object.assign(new Error(`THREE_WS_TIMEOUT_MS must be a positive number (got "${raw}")`), {
			code: 'bad_config',
		});
	}
	return n;
})();

// Bearer token for the ledger. Every /api/agent-actions call — read and write —
// authenticates, and the ledger is owner-scoped (you only see agents your token
// owns). A three.ws API key (sk_live_…) or an OAuth access token. Read lazily at
// call time (not load time) so buildServer() stays env-free for tests.
export function authToken() {
	return env('THREE_WS_TOKEN', '');
}

// Optional default EVM signer for append_agent_action. When present, each
// appended action is ERC-191-signed so its authorship is publicly verifiable.
// A per-call `signer_key` arg overrides this. Read lazily for the same reason.
export function signerKey() {
	return env('THREE_WS_SIGNER_KEY') || env('THREE_WS_SIGNER') || '';
}

// Identifies this client to the API in request logs.
export const USER_AGENT = '@three-ws/provenance-mcp';
