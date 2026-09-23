# che-mcp-kit-swift

Shared building blocks for PsychQuant's macOS MCP servers written in Swift, such as
[`che-ical-mcp`](https://github.com/PsychQuant/che-ical-mcp). Each server used to carry
its own copy of this code, and security fixes landed in one copy but not the others.
This package is meant to be the single copy they all depend on; servers are moving to it
one at a time.

Library product: `CheMCPKit`. Requires macOS 14 and
[`modelcontextprotocol/swift-sdk`](https://github.com/modelcontextprotocol/swift-sdk) 0.12.x.

```swift
.package(url: "https://github.com/PsychQuant/che-mcp-kit-swift.git", .upToNextMinor(from: "0.1.0"))
```

## Contents

| Component | What it does |
|---|---|
| `SelfUpdate` | `--self-update`: fetch the latest GitHub release, check its SHA-256 companion, verify the Developer ID signature and notarization, then atomically replace the running binary. Everything project-specific comes in through `SelfUpdate.Configuration`. |
| `SystemSignatureVerifier` | `codesign` designated-requirement check pinned to one Developer ID team, plus `spctl` notarization check, both with timeouts. |
| `SelfUpdate.compareVersions` | SemVer 2.0.0 §11 precedence (pre-releases sort below the release). |
| `CLIRunner` | `--cli <tool> --key value` / positional JSON / stdin JSON → one tool call through any `CLIToolExecutor`. String-typed schema parameters keep their text verbatim. Failures print the shared error envelope, or a server's own line via `errorFormatter:` when it already has an established `--cli` output format. |
| `ErrorSanitizer`, `ErrorEnvelope`, `TrustedErrorMessage`, `CodedError` | Keep framework error text out of responses, escape stderr, and emit `{"error":{"code","message"}}`. |
| `formatJSON` | JSON responses that throw instead of crashing on non-serializable values. |
| `BinaryPathResolver` | Resolve `argv[0]` (symlinks, bare names via `$PATH`) to the real binary path. |
| `Shutdown` | One exit path for signals, CLI completion and server end, so cleanup runs exactly once. |

Release scripts (signing, notarization, `.mcpb` packing) stay in each server's repo.

## Tests

```bash
swift test
```

Two tests exercise a real signed and notarized binary and are skipped by default. Point
`CHE_MCP_KIT_SIGNED_FIXTURE` at one (network access is needed for the notarization check):

```bash
CHE_MCP_KIT_SIGNED_FIXTURE=/path/to/a/notarized/binary swift test --filter SignatureVerifierTests
```

## License

MIT
