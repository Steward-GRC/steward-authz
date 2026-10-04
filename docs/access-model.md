# The access model

steward-authz makes two kinds of decision, both in-process and with no I/O. The caller loads the
data (the subject's roles and groups, the category chain) and passes it in.

## Subjects and resources

A `Subject` is the signed-in person: their user ID, catalog roles, directory group names, scoped
grants, per-document overrides, the individual read-sensitive grant, whether they are root, and any
active break-glass grants. Every signed-in subject is a reader; the reader role is never stored.

A `Resource` is one document: its ID (for example `POL-FACILITIES-000001`), its category, the
category lineage from that category up to the root, whether it is sensitive, and the user IDs of
the authors and approvers assigned to it.

## Category rules

Each category has owners and an ordered list of rules. A rule names a subject (everyone, a group,
or one user) and holds a grant per action: allow, deny or blank. The four actions are read,
acknowledge, approve and author.

`Compile(chain)` takes the target category first, then its ancestors up to the root. For each
action it checks, in order:

1. site admins and root always read;
2. an owner of any category in the chain reads, approves and authors (never acknowledges);
3. every rule, target category first, top-down within each category. The first rule that matches
   the subject and has a non-blank cell for the action decides;
4. anything left is denied.

A rule in a child category is evaluated before any rule of its parent, so a child can override what
it inherits, and a parent's rules apply wherever the child is silent.

`Resolve` then applies the read gate:

- an allowed author or approve confers read (no one authors or approves what they can't read);
  acknowledge confers nothing;
- with no read, acknowledge, approve and author are all denied (`requires_read`).

`Acknowledgement` is the acknowledge decision without the read gate, for a caller that settles read
another way, such as a per-document override.

Group names match ignoring case; user IDs match exactly. Every decision carries a stable `Reason`
code and, when a rule decided, a `RuleRef` (category, depth and index). `RuleDecision.String()`
gives the words the access simulator shows, such as `↳ Workplace #1 deny group Finance team`.

### The access simulator

The simulator is the same function: compile a draft chain (the unsaved rules) instead of the saved
one. There is no separate dry-run path.

### Validating rules

`CategoryRuleset.Validate` checks a ruleset read from storage or the admin editor: known subject
kinds, a name for group and user subjects and none for everyone, known actions and grants, and no
blank owner IDs. The error is coded `AUTHZ_INVALID_RULE` and carries the category, the rule number
and the problem as wire metadata.

## Authorize

`Authorize(subject, permission, resource)` decides one catalog permission:

1. **Capability.** The subject must hold the permission through a role, the read-sensitive grant,
   or, for a scoped permission, any scoped grant. Otherwise `missing_capability`.
2. **Scope.** For the scoped permissions (`policy.author`, `policy.submit`, `policy.approve`), the
   subject needs the matching scoped role (author, or approver for approve) on the resource's
   category or any ancestor in its lineage: a grant on a category covers every category below it.
   A site admin authors and submits anywhere, but approves only where an approver grant says so.
   Otherwise `out_of_category_scope`.
3. **Other permissions** are granted by the capability alone.
4. **Read of a document:** an override allow shows it; an override deny excludes it (a site admin
   still sees that it exists: `obfuscate`); an active break-glass grant shows it; a sensitive
   document follows the rule below.

### Sensitive documents

A sensitive document is read only by:

- the authors and approvers assigned to that document (`Resource.Authors`, `Resource.Approvers`):
  reason `assigned`;
- explicit grants: the individual read-sensitive grant (`Subject.ReadSensitive`), an override
  allow on that document, or an active break-glass grant on it.

Everyone else is denied (`sensitive`): an author or approver of the category who isn't assigned to
the document, a compliance admin, a site admin, a reader. No role grants `policy.read_sensitive`.
The Rego bundles apply the same rule (`steward.common.can_read_sensitive`).

`HasCapability` is the coarse check from step 1, for work that spans categories (a bulk decision,
say); the service still calls `Authorize` per resource.

`Decision.Err()` turns a denial into an error coded `AUTHZ_DENIED` that matches `ErrDenied`. The
reason stays in the internal cause and is never sent to the client.

## Decision logging

`Compile(chain, WithLogger(logger))` logs every rule decision at debug level through `log/slog`,
with the subject, the category, the action, the effect and the deciding rule.
