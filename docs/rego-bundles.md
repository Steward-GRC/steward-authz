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

## Test and build

```bash
task rego:test    # opa fmt --fail, opa check --strict, opa test, publish script tests
task rego:bundle  # opa build into bundle.tar.gz, without the *_test.rego files
opa eval --bundle policies/ --input input.json 'data.steward.core.allow'
```

CI runs the same checks in `.github/workflows/rego.yml`.

## Publishing

`scripts/publish-bundle.sh` uploads a built bundle to any S3-compatible store with the MinIO client
(`mc`), in two places:

- `<bucket>/versions/<revision>/bundle.tar.gz`, immutable, for rollback and comparison; uploaded
  first, so the channel never points at a bundle with no versioned copy;
- `<bucket>/<channel>/bundle.tar.gz`, the mutable channel OPA polls.

| Variable | Default | |
|---|---|---|
| `BUNDLE_PATH` | `bundle.tar.gz` | the built bundle |
| `BUNDLE_S3_ENDPOINT` | | the store's URL |
| `BUNDLE_S3_ACCESS_KEY` | | |
| `BUNDLE_S3_SECRET_KEY` | | |
| `BUNDLE_BUCKET` | `steward-authz-bundles` | |
| `BUNDLE_CHANNEL` | | e.g. `stable` |
| `BUNDLE_REVISION` | | normally the commit SHA |

Channel, revision and bucket must be plain names. No CI job publishes yet: where and when bundles
are published is set by the release, not this repo.
