import Foundation
import Testing
@testable import CheMCPKit

/// Shutdown on signals: one exit, conventional status for the CLI.
struct ShutdownTests {
    @Test func `Only the first claimant of the exit gate proceeds`() async {
        let gate = ExitGate()
        let winners = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<32 { group.addTask { gate.claim() } }
            return await group.reduce(0) { $0 + ($1 ? 1 : 0) }
        }
        #expect(winners == 1)
    }

    @Test func `Signal exit status is 0 for the server and 128 plus signo for the CLI`() {
        #expect(SignalExitPolicy.server.status(for: SIGTERM) == 0)
        #expect(SignalExitPolicy.server.status(for: SIGINT) == 0)
        #expect(SignalExitPolicy.cli.status(for: SIGINT) == 130)
        #expect(SignalExitPolicy.cli.status(for: SIGTERM) == 143)
        #expect(SignalExitPolicy.cli.status(for: SIGHUP) == 129)
    }

    @Test func `The gate reports whether termination has begun`() {
        let gate = ExitGate()
        #expect(!gate.isClaimed)
        #expect(gate.claim())
        #expect(gate.isClaimed)
    }
}

struct BinaryPathResolverTests {
    @Test func `A symlink chain resolves to the final file`() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bpr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let real = dir.appendingPathComponent("real")
        FileManager.default.createFile(atPath: real.path, contents: Data())
        let hop = dir.appendingPathComponent("hop")
        let link = dir.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: hop, withDestinationURL: real)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: hop)
        let expected = try #require(realpath(real.path, nil).map { p in defer { free(p) }; return String(cString: p) })
        #expect(BinaryPathResolver.resolveArgv0(link.path) == expected)
    }

    @Test func `A missing path falls back to the standardized input`() {
        #expect(BinaryPathResolver.resolveArgv0("/no/such/dir/../bin") == "/no/such/bin")
    }

    @Test func `A bare name not on PATH is unresolvable`() {
        #expect(throws: BinaryPathResolverError.unresolvable) {
            try BinaryPathResolver.resolveWithPATHFallback("definitely-not-a-binary-\(UUID().uuidString)")
        }
    }
}
