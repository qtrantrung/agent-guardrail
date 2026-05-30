{
  "rules": [
    {
      "id": "deny-shell",
      "effect": "deny",
      "tool": "shell.*",
      "priority": 10,
      "description": "No agent may execute shell commands under any circumstances."
    },
    {
      "id": "allow-kb-read",
      "effect": "allow",
      "tool": "fs.read",
      "priority": 50,
      "conditions": [
        { "arg": "path", "matches": "/srv/knowledge_base/.*" }
      ],
      "description": "Read-only access, scoped to the knowledge base directory."
    },
    {
      "id": "allow-vendor-api",
      "effect": "allow",
      "tool": "http.get",
      "priority": 50,
      "description": "Outbound HTTP GET is permitted; the egress allowlist bounds the destination."
    },
    {
      "id": "allow-ticket-create",
      "effect": "allow",
      "tool": "tickets.create",
      "agents": ["ops-assistant"],
      "priority": 50,
      "conditions": [
        { "arg": "severity", "one_of": ["low", "medium"] }
      ],
      "description": "Only the ops assistant may open tickets, and not at high severity."
    }
  ]
}
