# The Rego bundles

`policies/` holds one Rego package per service, `steward.<svc>`, each with a single `allow` rule
and `default allow := false`, plus the shared helpers in `steward.common`. The rules are Rego v1
and need OPA 1.x. They describe a coarse gate on each gRPC method.

## Status: not enforced

No Steward service loads a Rego bundle today. No service image builds or copies one, no service
depends on OPA, and nothing queries `data.steward.<svc>.allow`. Access is enforced by this module's
Go engine, which the services call in-process (see [the access model](access-model.md)). The
method gates below are therefore enforced nowhere: a rule here that is stricter than the Go engine
doesn't stop a call. The packages are kept, tested and buildable, but treat them as a
specification, not as a layer of the access model.

| File | Package | Covers |
|---|---|---|
| `common.rego` | `steward.common` | role, group and scoped-role helpers |
| `core.rego` | `steward.core` | PolicyService, TemplateService, GroupService |
| `workflow.rego` | `steward.workflow` | WorkflowService |
| `obligations.rego` | `steward.obligations` | CampaignService, AckService, NotifPrefService, ReportingService |
| `audit.rego` | `steward.audit` | AuditService |
| `delivery.rego` | `steward.delivery` | DeliveryService |
| `ai.rego` | `steward.ai` | AiService <!-- scrub:allow=fqdn --> |
| `gateway.rego` | `steward.gateway` | CollabTokenService and the gateway's HTTP edge |

The method names follow each service's proto package, `steward.<svc>.v1.<Service>/<RPC>`. When a
service's proto changes, its package here changes in the same release.

## Input

```json
{
  "method": "steward.core.v1.PolicyService/SaveDraft",
  "claims": {
    "user_id": "bob",
    "email": "bob@example.org",
    "roles": ["author"],
    "scoped_roles": [{"role": "author", "category": "Finance"}],
    "groups": ["g1"]
  },
  "request": {"group_id": "g1"}
}
```

Roles are the catalog roles ([the catalog](catalog.md)); there is no platform-wide `admin` role.
Query `data.steward.<svc>.allow`; anything but `true` is a denial.

## Posture

- **Default deny** in every package.
- **Read-permissive, write-strict:** reads need an authenticated caller; writes need a role and,
  where it applies, group scope.
- **Fail closed:** a missing field makes every helper false.
- **Sensitive content:** `can_read_sensitive(claims, policy)` is true only for the policy's assigned
  authors and approvers (`assigned_author_ids`, `assigned_approver_ids`), the individual grant
  (`claims.read_sensitive`) or a grant on that policy (`claims.sensitive_grants`, policy IDs). No
  role passes it. Across policies (an AI search with `include_sensitive`), only the individual
  grant counts.
- **AI read scope:** the AI service's calls carry a `scope` of category ids the gateway computed
  from the category rules (the input doesn't hold the rules, so the ids aren't checked here).
  The AI package refuses only a scope that widens past the caller: `include_sensitive` without the
  individual grant, or `all_categories` without the site admin role. The module's settings calls
  need the site admin role; assist and authoring jobs need an author grant.

## Test and build

```bash
task rego:test    # opa fmt --fail, opa check --strict, opa test, the bundle build tests
task rego:bundle  # scripts/build-bundle.sh: bundle.tar.gz, without the *_test.rego files
opa eval --bundle policies/ --input input.json 'data.steward.core.allow'
```

CI runs the same checks in `.github/workflows/rego.yml`. Nothing publishes the bundle, and no
service image includes it.
