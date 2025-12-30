# Project Structure - Go Standard Layout

## Overview

Phantom Grid follows the **official Go standard project layout** used by major Go projects like Kubernetes, Docker, Prometheus, and etcd.

## Directory Structure

### `cmd/` - Application Entry Points

**Purpose**: Contains main applications for your project.

**Convention**: Each subdirectory is a separate application with its own `main.go`.

**Example**:
```
cmd/
├── agent/          # phantom-grid binary
│   └── main.go
└── spa-client/     # spa-client binary
    └── main.go
```

**Why**: 
- Clear separation of multiple binaries
- Standard location that Go developers expect
- Easy to build: `go build ./cmd/agent`

**Used by**: Kubernetes (`cmd/kubectl`, `cmd/kubelet`), Docker (`cmd/docker`, `cmd/containerd`), Prometheus (`cmd/prometheus`, `cmd/promtool`)

---

### `internal/` - Private Application Code

**Purpose**: Contains private application and library code that you don't want other projects to import.

**Special Feature**: Go compiler **automatically prevents** importing packages from `internal/` directories from outside the module. This is a language feature, not just a convention.

**Example**:
```
internal/
├── agent/          # Agent core logic (private)
├── config/         # Configuration (private)
├── dashboard/      # Dashboard UI (private)
├── ebpf/           # eBPF loader (private)
└── honeypot/       # Honeypot implementation (private)
```

**Why**:
- **Privacy**: External projects cannot import these packages
- **Encapsulation**: Internal implementation details stay hidden
- **Breaking changes**: You can refactor internal code without affecting external users

**Used by**: Kubernetes (`internal/`), Docker (`internal/`), Prometheus (`internal/`), etcd (`internal/`)

**Go Language Feature**:
```go
// From another module (e.g., github.com/other/project):
import "github.com/your-org/phantom-grid/internal/agent"  // ERROR: cannot import internal package
```

---

### `pkg/` - Public Library Code

**Purpose**: Contains library code that is intended for use by external applications.

**Convention**: These packages can be imported by other projects.

**Example**:
```
pkg/
└── spa/            # Reusable SPA client (public API)
    ├── client.go
    └── client_test.go
```

**Why**:
- **Reusability**: Other projects can import and use these packages
- **Public API**: These are your exported, stable APIs
- **Versioning**: Changes here affect external users (semver)

**Used by**: Kubernetes (`pkg/`), Docker (`pkg/`), Prometheus (`pkg/`)

**Usage from external project**:
```go
// From another module:
import "github.com/your-org/phantom-grid/pkg/spa"  // OK: public API
```

---

## Comparison with Major Go Projects

### Kubernetes
```
kubernetes/
├── cmd/            # kubectl, kubelet, kube-apiserver, etc.
├── pkg/            # Public APIs (client-go, api, etc.)
└── internal/      # Private implementation
```

### Docker
```
docker/
├── cmd/            # docker, dockerd, docker-compose
├── pkg/            # Public libraries
└── internal/       # Private implementation
```

### Prometheus
```
prometheus/
├── cmd/            # prometheus, promtool
├── pkg/            # Public libraries
└── internal/       # Private implementation
```

### Phantom Grid (Current)
```
phantom-grid/
├── cmd/            # agent, spa-client
├── pkg/            # spa (public API)
└── internal/       # agent, config, dashboard, ebpf, honeypot, etc. (private)
```

**Conclusion**: Phantom Grid follows the exact same structure as these major projects.

---

## Why This Structure?

### 1. **Go Compiler Support**
- `internal/` is a **language feature**, not just convention
- Go compiler enforces privacy automatically
- No need for manual access control

### 2. **Industry Standard**
- Used by all major Go projects
- New contributors immediately understand the structure
- Tooling (IDEs, linters) expects this layout

### 3. **Clear Separation**
- **cmd/**: "What can I run?"
- **pkg/**: "What can I import?"
- **internal/**: "Implementation details (don't import)"

### 4. **Maintainability**
- Easy to find code
- Clear boundaries between public and private APIs
- Safe to refactor internal code

---

## Should You Change It?

### ❌ **Don't Change** - Current Structure is Correct

**Reasons**:
1. ✅ Follows Go standard project layout
2. ✅ Matches major Go projects (Kubernetes, Docker, etc.)
3. ✅ Go compiler enforces `internal/` privacy
4. ✅ Industry best practice
5. ✅ Tooling support (IDEs, go tools)

### Alternative Structures (Not Recommended)

**Bad Example 1**: Flat structure
```
phantom-grid/
├── agent.go
├── honeypot.go
├── dashboard.go
└── main.go
```
**Problem**: No separation, everything is public, hard to scale

**Bad Example 2**: Custom names
```
phantom-grid/
├── applications/    # Instead of cmd/
├── private/        # Instead of internal/
└── public/         # Instead of pkg/
```
**Problem**: Non-standard, confusing for contributors, no compiler support

---

## Best Practices

### ✅ Do:
- Keep `cmd/` for all main applications
- Use `internal/` for private implementation
- Use `pkg/` only for truly reusable public APIs
- Document public APIs in `pkg/`

### ❌ Don't:
- Put library code in `cmd/`
- Put main applications in `internal/` or `pkg/`
- Make `internal/` packages importable
- Create custom directory names

---

## References

- [Go Standard Project Layout](https://github.com/golang-standards/project-layout)
- [Go Blog: Organizing Go Code](https://go.dev/blog/organizing-go-code)
- [Go Wiki: Package Names](https://github.com/golang/go/wiki/CodeReviewComments#package-names)

---

## Conclusion

**Your current structure (`cmd/`, `internal/`, `pkg/`) is correct and follows Go best practices.**

No changes needed - this is exactly how major Go projects are structured.

