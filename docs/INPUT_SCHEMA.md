# Local JSON Input Schema

`POST /api/analyze` and `--input` accept a UTF-8 JSON object up to 2 MB and 10,000 aggregate list records. Unknown fields are rejected. The current project intentionally requires `metadata.synthetic: true`.

## Top-level collections

- `users`, `groups`, `roles`, `permissions`, `resources`
- `user_groups`, `nested_groups`, `user_roles`, `group_roles`, `role_permissions`
- `authentication_events`

Every entity has a stable string `id`. Assignments use `source_id` and `target_id`. Permission `resource_id` values must reference a resource (or `*` for an explicitly broad model). Authentication events reference an existing username.

```json
{
  "metadata": {"synthetic": true, "seed": 42},
  "users": [{
    "id": "usr-1", "username": "user.demo", "display_name": "User Demo",
    "department": "Research", "account_type": "human", "enabled": true,
    "privileged": false, "mfa_enabled": true,
    "last_login": "2025-01-01T12:00:00Z", "created_at": "2024-01-01T12:00:00Z"
  }],
  "groups": [], "roles": [], "permissions": [], "resources": [],
  "user_groups": [], "nested_groups": [], "user_roles": [],
  "group_roles": [], "role_permissions": [], "authentication_events": []
}
```

The importer rejects malformed JSON, duplicate IDs or usernames, duplicate assignments, unknown references, invalid enums/ranges, oversized content, and authentication events for unknown users. It never evaluates code or loads executable configuration.
