# The permission catalog

Permissions are written `<resource>.<verb>`. `Permissions()` lists them in a stable order, and
`ParsePermission` checks a name read from outside.

| Permission | Scoped | Means |
|---|---|---|
| `policy.read` | | read documents (every signed-in subject) |
| `policy.read_sensitive` | | read documents marked sensitive |
| `policy.author` | yes | create and edit drafts |
| `policy.submit` | yes | submit a draft for approval |
| `policy.approve` | yes | decide on a draft in a workflow |
| `template.manage` | | manage templates |
| `workflow.manage` | | manage workflows |
| `group.manage` | | manage groups |
| `user.manage` | | manage users |
| `role.manage` | | manage role assignments |
| `audit.read` | | read the audit log |
| `compliance.manage` | | manage acknowledgement campaigns |
| `compliance.report` | | read completion reports |
| `settings.manage` | | change settings |
| `delivery.manage` | | manage shared links and exports |
| `session.manage` | | manage sessions |

A scoped permission takes effect only in the categories a subject holds a scoped grant for, and
everything below them (see [the access model](access-model.md)).

## Roles

| Role | Grants |
|---|---|
| `reader` | `policy.read`. Implicit for every signed-in subject, never stored. |
| `author` | `policy.read`, `policy.author`, `policy.submit` |
| `approver` | `policy.read`, `policy.approve` |
| `template-admin` | `policy.read`, `template.manage`, `workflow.manage` |
| `compliance-admin` | `policy.read`, `policy.read_sensitive`, `compliance.manage`, `compliance.report`, `audit.read` |
| `site-admin` | everything, including permissions added to the catalog later |

There is no `admin` role. An unknown role grants nothing beyond the reader baseline, and
`ParseRole` refuses it.

The role table is a responsibility matrix from `github.com/Bugs5382/go-authz`, with the role as the
subject, the permission's resource and verb as the other two dimensions, and a wildcard cell for
site admin.

## Error codes

The library's codes sit in band 9 (9000 to 9999). A service adds `Entries()` to the go-apperr
registry it builds at startup.

| Code | Symbol | Category | User-safe message |
|---|---|---|---|
| 9001 | `AUTHZ_DENIED` | permission-denied | You don't have permission to do that. |
| 9002 | `AUTHZ_INVALID_RULE` | invalid | Access rule {rule} in {category} is not valid ({problem}). |
| 9003 | `AUTHZ_UNKNOWN_PERMISSION` | invalid | {permission} is not a known permission. |
| 9004 | `AUTHZ_UNKNOWN_ROLE` | invalid | {role} is not a known role. |

The `{…}` placeholders are filled from the error's wire metadata.
