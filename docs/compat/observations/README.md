# Management API Observations

Behavioral notes from firewalled observation of Auth0's Management API.
Read the rules in [CLEAN_ROOM.md](../../../CLEAN_ROOM.md) before adding anything.

One file per endpoint group (for example `users.md`, `clients.md`), using this layout:

```markdown
# <Endpoint group>

- **Observed:** YYYY-MM-DD
- **Docs:** <public doc URL(s) this complements>

## <METHOD> <path>

- Status codes:
- Request fields (type, required, default, validation):
- Response fields (type, presence rules):
- Pagination / sorting:
- Error codes (identifier only, no verbatim messages):
- Differences from public docs:
```

Do not include credentials, tenant domains or IDs, personal data, verbatim
error messages, or anything captured from the dashboard UI.
