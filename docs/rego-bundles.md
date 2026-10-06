# The Rego bundles

`policies/` holds one Rego package per service, `steward.<svc>`, each with a single `allow` rule
and `default allow := false`, plus the shared helpers in `steward.common`. The rules are Rego v1
and need OPA 1.x. They gate each gRPC method coarsely; the per-document decision is the in-process
engine's job (see [the access model](access-model.md)).

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

CI runs the same checks in `.github/workflows/rego.yml`.

## Building the bundle into a service image

There is no bundle store and nothing publishes bundles. Each service builds the bundle into its own
image at build time, from the steward-authz commit it pins, so the Go engine and the Rego rules in
one image always come from the same commit.

`scripts/build-bundle.sh [output]` runs `opa build` over `policies/` without the tests, with the
bundle rooted at `steward` (`policies/.manifest`) and the manifest revision set from
`BUNDLE_REVISION` (default: the checked-out commit). The same commit and OPA version build the same
bytes; the script's test checks that. Use OPA 1.21.1, the version CI pins.

### In a service's Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
ARG STEWARD_AUTHZ_REF  # the steward-authz commit the service pins (the one its go.mod resolves to)

FROM openpolicyagent/opa:1.21.1-debug AS authz-bundle
ARG STEWARD_AUTHZ_REF
ADD --keep-git-dir=false https://github.com/Steward-GRC/steward-authz.git#${STEWARD_AUTHZ_REF} /src
RUN BUNDLE_REVISION="${STEWARD_AUTHZ_REF}" sh /src/scripts/build-bundle.sh /out/bundle.tar.gz

FROM <the service's runtime stage>
COPY --from=authz-bundle /out/bundle.tar.gz /opt/steward/authz/bundle.tar.gz
```

The `-debug` OPA image carries the shell the script needs; the runtime stage needs only the copied
file.

### Loading it

**In-process**, with OPA's Go module:

```go
import "github.com/open-policy-agent/opa/v1/rego"

pq, err := rego.New(
	rego.Query("data.steward.core.allow"),
	rego.LoadBundle("/opt/steward/authz/bundle.tar.gz"),
).PrepareForEval(ctx)
// rs, err := pq.Eval(ctx, rego.EvalInput(input)); allowed := rs.Allowed()
```

**As a sidecar**, the bundle comes from the service image through a shared volume: an init
container from the service image copies `/opt/steward/authz/bundle.tar.gz` into an `emptyDir`, and
the OPA container serves it from there, with no bundle service and no polling:

```bash
opa run --server --addr=127.0.0.1:8181 /bundles/bundle.tar.gz
```

A new policy version ships as a new service image.
