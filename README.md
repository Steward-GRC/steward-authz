# steward-authz 🐹

> 🧭 Access-rule engine and permission catalog shared by Steward services

The Go module every Steward service imports to make access decisions in-process, plus the Rego
policy bundles the services' OPA sidecars load.

- **Category rules:** ordered rules per category, inherited down the tree. The first rule with an
  opinion wins, and anything no rule decides is denied.
- **Permission catalog:** the permissions, the roles that grant them, and `Authorize` for one
  permission on one document.
- **Rego bundles:** per-service method gates in `policies/`, built into one OPA bundle.

## 📦 Install

```bash
go get github.com/Steward-GRC/steward-authz
```

## 🚀 Use

```go
import authz "github.com/Steward-GRC/steward-authz"

ev := authz.Compile(chain) // the target category first, then its ancestors
res := ev.Resolve(ctx, authz.Subject{UserID: "erin", Groups: []string{"All staff"}})
if res.Read.Allowed { /* ... */ }

d := authz.Authorize(subject, authz.PolicyApprove, &authz.Resource{Category: "Finance"})
if err := d.Err(); err != nil { return err } // coded AUTHZ_DENIED
```

## 📚 Docs

- [The access model](docs/access-model.md): the rule engine and `Authorize`, step by step.
- [The permission catalog](docs/catalog.md): permissions, roles, error codes.
- [The Rego bundles](docs/rego-bundles.md): the input shape, testing, building and publishing.

## 🛠 Develop

```bash
task build       # go build ./...
task test        # go test ./...
task lint        # gofmt check + golangci-lint + yamllint
task license     # check Apache-2.0 headers (golic)
task rego:test   # opa fmt, opa check, opa test, and the publish script's tests
task rego:bundle # build bundle.tar.gz from policies/
```

## ⚖️ License

Apache-2.0 (c) 2026 The Steward Authors
