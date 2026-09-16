export const presets = [
  {
    id: 'basic-user',
    name: 'Basic user token',
    category: 'Core',
    description: 'A normal user access token with subject, audience and scopes.',
    claims: {
      sub: 'alice',
      aud: 'https://api.example.com',
      scope: 'profile.read orders.read'
    }
  },
  {
    id: 'machine-client',
    name: 'Machine / client token',
    category: 'Core',
    description: 'A workload-style token with no human subject semantics.',
    claims: {
      sub: 'inventory-sync-service',
      client_id: 'inventory-sync-service',
      aud: 'https://inventory.example.com',
      scope: 'inventory.read inventory.write'
    }
  },
  {
    id: 'mcp-user',
    name: 'MCP user access token',
    category: 'MCP',
    description: 'A user token targeted at an MCP server with tool-oriented scopes.',
    claims: {
      sub: 'alice',
      client_id: 'claude-desktop',
      aud: 'https://mcp.example.com',
      scope: 'customers.read transactions.read'
    }
  },
  {
    id: 'mcp-agent',
    name: 'MCP agent identity',
    category: 'MCP',
    description: 'A token representing an agent/workload calling an MCP server.',
    claims: {
      sub: 'investment-advisor-agent',
      client_id: 'investment-advisor-agent',
      agent_type: 'investment-advisor',
      aud: 'https://mcp.example.com',
      scope: 'portfolio.read market.read'
    }
  },
  {
    id: 'delegated-agent',
    name: 'Delegated user → agent',
    category: 'Delegation',
    description: 'Looks like the result of token exchange: user subject plus RFC 8693 act claim.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'portfolio.read',
      act: {
        sub: 'investment-advisor-agent'
      }
    }
  },
  {
    id: 'nested-delegation',
    name: 'Nested delegation chain',
    category: 'Delegation',
    description: 'A nested act chain for user → orchestrator → specialist agent tests.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'payments.read',
      act: {
        sub: 'payment-specialist',
        act: {
          sub: 'orchestrator-agent'
        }
      }
    }
  },
  {
    id: 'missing-scope',
    name: 'Insufficient scope',
    category: 'Negative tests',
    description: 'A valid token that intentionally lacks the privileged scope.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'payments.read'
    }
  },
  {
    id: 'wrong-audience',
    name: 'Wrong audience',
    category: 'Negative tests',
    description: 'A valid signed token with an intentionally incorrect audience.',
    claims: {
      sub: 'alice',
      aud: 'https://wrong-resource.example.com',
      scope: 'customers.read'
    }
  },
  {
    id: 'expired',
    name: 'Expired token',
    category: 'Negative tests',
    description: 'A token whose exp is already in the past.',
    claims: {
      sub: 'alice',
      aud: 'https://api.example.com',
      scope: 'profile.read'
    },
    options: {
      expiresIn: -300
    }
  },
  {
    id: 'multi-audience',
    name: 'Multiple audiences',
    category: 'Edge cases',
    description: 'JWT aud represented as an array.',
    claims: {
      sub: 'alice',
      aud: ['https://api.example.com', 'https://mcp.example.com'],
      scope: 'profile.read tools.read'
    }
  }
];

export function getPreset(id) {
  return presets.find((preset) => preset.id === id);
}
