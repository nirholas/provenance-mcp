#!/usr/bin/env node
// @three-ws/provenance-mcp — MCP server entry point.
//
// Exposes the three.ws agent action-provenance ledger over stdio — the trust
// layer where every agent action is recorded append-only, ERC-191-signed, and
// on-chain verifiable:
//   • list_agent_actions   — read an agent's action trail (paginated, verified)
//   • query_action         — fetch one action by id and verify its signature
//   • append_agent_action  — sign + append a new action to the immutable ledger
//
// The ledger authenticates every call, so THREE_WS_TOKEN (a three.ws API key or
// OAuth access token) is required for all tools and the trail is owner-scoped.
// Set THREE_WS_SIGNER_KEY to ERC-191-sign appended actions.
//
// Run standalone:
//   THREE_WS_TOKEN=sk_live_… node packages/provenance-mcp/src/index.js
//
// Or wire into Claude Code / Cursor — see README.md.

import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { def as listAgentActions } from './tools/list-agent-actions.js';
import { def as queryAction } from './tools/query-action.js';
import { def as appendAgentAction } from './tools/append-agent-action.js';

// Single source of truth for the advertised server version — package.json.
const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require('../package.json');

export const TOOLS = [
	listAgentActions,
	queryAction,
	appendAgentAction,
];

/**
 * Construct a fully-registered McpServer without connecting a transport.
 * Registration is env-free, so this is safe to import from tests.
 * @returns {McpServer}
 */
export function buildServer() {
	const server = new McpServer(
		{ name: 'provenance-mcp', title: 'three.ws Provenance', version: PKG_VERSION },
		{
			capabilities: { tools: {} },
			instructions:
				'three.ws Provenance MCP — the agent trust layer. Every agent action lives in an ' +
				'append-only, ERC-191-signed, on-chain-verifiable ledger. list_agent_actions reads an ' +
				"agent's action trail newest-first (cursor-paginated), verifying each record's signature " +
				'inline. query_action fetches one action by id and recovers its signer to prove the named ' +
				'agent authored that exact action, untampered. append_agent_action signs a new action with ' +
				'an EVM key and appends it — an immutable record that can never be edited or deleted. The ' +
				'ledger authenticates every call: set THREE_WS_TOKEN (a three.ws API key or OAuth access ' +
				'token); the trail is owner-scoped to the agents that token owns. Set THREE_WS_SIGNER_KEY ' +
				'to sign appended actions (otherwise they append unsigned). append_agent_action is the only ' +
				'write tool; it never overwrites or deletes.',
		},
	);

	for (const tool of TOOLS) {
		server.registerTool(
			tool.name,
			{
				title: tool.title,
				description: tool.description,
				inputSchema: tool.inputSchema,
				annotations: tool.annotations,
			},
			async (args, extra) => {
				try {
					const result = await tool.handler(args, extra);
					const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
					return { content: [{ type: 'text', text }] };
				} catch (err) {
					const payload = {
						ok: false,
						error: err?.code || 'unhandled',
						message: err?.message || String(err),
						...(err?.status ? { status: err.status } : {}),
					};
					return {
						content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
						isError: true,
					};
				}
			},
		);
	}

	return server;
}

async function main() {
	const server = buildServer();
	const transport = new StdioServerTransport();
	await server.connect(transport);
	console.error(`[provenance-mcp@${PKG_VERSION}] connected over stdio with ${TOOLS.length} tools`);
}

// Connect stdio ONLY when this file is the process entry point. Importing the
// module (tests, embedding) must not grab the transport. realpath both sides:
// npm bin shims are symlinks, so argv[1] may differ from import.meta.url.
function isProcessEntryPoint() {
	if (!process.argv[1]) return false;
	try {
		return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
	} catch {
		return false;
	}
}

if (isProcessEntryPoint()) {
	main().catch((err) => {
		console.error('[provenance-mcp] fatal:', err);
		process.exit(1);
	});
}
