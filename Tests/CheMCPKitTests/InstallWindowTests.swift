import Foundation
import Testing
@testable import CheMCPKit

/// #1 — the file `rename(2)` installs must be the one that was hashed and signature-checked.
/// These tests show that a substitution *before* the final identity check is detected (a
/// different file, a symlink, a FIFO), that `chmod` never follows a link, and that the download is
/// written and staged privately. The window between the final identity check and `rename(2)`
/// remains; it is reachable only by accounts outside the threat model (see `verifyAndInstall`).
struct InstallWindowTests {

    private struct PassingVerifier: SignatureVerifying {
        let expectedTeamID = "TEAM000000"
        func verify(binaryAt path: String) throws {}
    }

    private static func setUp() throws -> (dir: URL, temp: String, target: String, hash: String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let target = dir.appendingPathComponent("Binary").path
        let temp = dir.appendingPathComponent(".Binary.update-x").path
        try Data("old".utf8).write(to: URL(fileURLWithPath: target))
        try Data("new".utf8).write(to: URL(fileURLWithPath: temp))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temp)
        return (dir, temp, target, try SelfUpdate.sha256OfFile(at: temp))
    }

    @Test func `A different file swapped in after the final hash is refused before rename`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let other = s.dir.appendingPathComponent("other").path
        try Data("new".utf8).write(to: URL(fileURLWithPath: other))   // same bytes, different file
        do {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                            verifier: PassingVerifier(), beforeRename: {
                try FileManager.default.removeItem(atPath: s.temp)
                try FileManager.default.moveItem(atPath: other, toPath: s.temp)
            })
            Issue.record("expected refusal")
        } catch SelfUpdate.SelfUpdateError.installFailed(let detail) {
            #expect(detail.contains("was replaced"), "got: \(detail)")
        }
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
    }

    @Test func `A symlink swapped in after the final hash is refused before rename`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let genuine = s.dir.appendingPathComponent("genuine").path
        try FileManager.default.copyItem(atPath: s.temp, toPath: genuine)
        #expect(throws: SelfUpdate.SelfUpdateError.self) {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                            verifier: PassingVerifier(), beforeRename: {
                try FileManager.default.removeItem(atPath: s.temp)
                try FileManager.default.createSymbolicLink(atPath: s.temp, withDestinationPath: genuine)
            })
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: s.target)
        #expect(attrs[.type] as? FileAttributeType == .typeRegular)
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
        // The link target's mode was never touched: no path-based chmod followed the link.
        let genuineMode = try FileManager.default.attributesOfItem(atPath: genuine)[.posixPermissions] as? Int
        #expect(genuineMode == 0o600)
    }

    @Test func `A symlink in place before the final check is refused without touching its target`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let genuine = s.dir.appendingPathComponent("genuine").path
        try FileManager.default.copyItem(atPath: s.temp, toPath: genuine)
        try FileManager.default.removeItem(atPath: s.temp)
        try FileManager.default.createSymbolicLink(atPath: s.temp, withDestinationPath: genuine)
        #expect(throws: SelfUpdate.SelfUpdateError.self) {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                            verifier: PassingVerifier())
        }
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
        #expect(try FileManager.default.attributesOfItem(atPath: genuine)[.posixPermissions] as? Int == 0o600)
    }

    private final class SwapDuringCheck: SignatureVerifying, @unchecked Sendable {
        let expectedTeamID = "TEAM000000"
        let replacement: String
        init(replacement: String) { self.replacement = replacement }
        func verify(binaryAt path: String) throws {
            try FileManager.default.removeItem(atPath: path)
            try FileManager.default.copyItem(atPath: replacement, toPath: path)   // same bytes, new file
        }
    }

    @Test func `A file swapped in during the signature check is refused`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let copy = s.dir.appendingPathComponent("copy").path
        try FileManager.default.copyItem(atPath: s.temp, toPath: copy)
        do {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                            verifier: SwapDuringCheck(replacement: copy))
            Issue.record("expected refusal")
        } catch SelfUpdate.SelfUpdateError.installFailed(let detail) {
            #expect(detail.contains("was replaced"), "got: \(detail)")
        }
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
    }

    @Test func `A FIFO at the staged path is refused without blocking`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        try FileManager.default.removeItem(atPath: s.temp)
        #expect(mkfifo(s.temp, 0o600) == 0)
        let done = DispatchSemaphore(value: 0)
        let outcome = Outcome()
        DispatchQueue.global().async {
            do {
                try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                                verifier: PassingVerifier())
            } catch { outcome.set(error) }
            done.signal()
        }
        guard done.wait(timeout: .now() + 5) == .success else {
            Issue.record("verifyAndInstall blocked on a FIFO")
            let w = open(s.temp, O_WRONLY | O_NONBLOCK); if w >= 0 { close(w) }   // unblock the reader
            return
        }
        #expect(outcome.get() is SelfUpdate.SelfUpdateError)
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
    }

    private final class Outcome: @unchecked Sendable {
        private let lock = NSLock(); private var error: Error?
        func set(_ e: Error) { lock.lock(); error = e; lock.unlock() }
        func get() -> Error? { lock.lock(); defer { lock.unlock() }; return error }
    }

    @Test func `The download is written only to a new, non-link file`() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let victim = dir.appendingPathComponent("victim").path
        try Data("keep".utf8).write(to: URL(fileURLWithPath: victim))

        let linked = dir.appendingPathComponent("linked").path
        try FileManager.default.createSymbolicLink(atPath: linked, withDestinationPath: victim)
        #expect(throws: SelfUpdate.SelfUpdateError.self) { try SelfUpdate.writeStaged(Data("new".utf8), to: linked) }
        #expect(try String(contentsOfFile: victim, encoding: .utf8) == "keep")

        let existing = dir.appendingPathComponent("existing").path
        try Data("keep".utf8).write(to: URL(fileURLWithPath: existing))
        #expect(throws: SelfUpdate.SelfUpdateError.self) { try SelfUpdate.writeStaged(Data("new".utf8), to: existing) }
        #expect(try String(contentsOfFile: existing, encoding: .utf8) == "keep")

        let fresh = dir.appendingPathComponent("fresh").path
        try SelfUpdate.writeStaged(Data("new".utf8), to: fresh)
        #expect(try String(contentsOfFile: fresh, encoding: .utf8) == "new")
        #expect(try FileManager.default.attributesOfItem(atPath: fresh)[.posixPermissions] as? Int == 0o600)
    }

    @Test func `The staging directory is removed whether the body succeeds or throws`() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("Binary").path

        let used = try await SelfUpdate.withStagingDirectory(nextTo: target) { staging in
            try Data("x".utf8).write(to: URL(fileURLWithPath: staging).appendingPathComponent("f"))
            return staging
        }
        #expect(!FileManager.default.fileExists(atPath: used))

        struct Boom: Error {}
        var thrownFrom = ""
        do {
            _ = try await SelfUpdate.withStagingDirectory(nextTo: target) { staging -> Int in
                thrownFrom = staging
                throw Boom()
            }
        } catch is Boom {}
        #expect(!thrownFrom.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: thrownFrom))
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
    }

    @Test func `The staging directory drops ACL entries inherited from its parent`() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = ["+a", "everyone allow add_file,add_subdirectory,delete_child,directory_inherit,file_inherit", dir.path]
        try chmod.run(); chmod.waitUntilExit()
        #expect(chmod.terminationStatus == 0)

        let staging = try SelfUpdate.makeStagingDirectory(nextTo: dir.appendingPathComponent("Binary").path)
        let acl = acl_get_file(staging, ACL_TYPE_EXTENDED)
        defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
        var entry: acl_entry_t?
        let hasEntry = acl != nil && acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == 0
        #expect(!hasEntry, "staging directory still carries an inherited ACL entry")
    }

    @Test func `An open failure names its cause, and a symlink reads as not a regular file`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let missing = s.dir.appendingPathComponent("gone").path
        do {
            try SelfUpdate.verifyAndInstall(temp: missing, target: s.target, expectedHash: s.hash, verifier: PassingVerifier())
            Issue.record("expected refusal")
        } catch SelfUpdate.SelfUpdateError.installFailed(let detail) {
            #expect(detail == "could not open downloaded file at \(missing): No such file or directory — refusing to install")
        }
        let link = s.dir.appendingPathComponent("link").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: s.temp)
        do {
            try SelfUpdate.verifyAndInstall(temp: link, target: s.target, expectedHash: s.hash, verifier: PassingVerifier())
            Issue.record("expected refusal")
        } catch SelfUpdate.SelfUpdateError.installFailed(let detail) {
            #expect(detail == "downloaded file is no longer a regular file at \(link) — refusing to install")
        }
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
    }

    @Test func `The installed file is executable (0755)`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash,
                                        verifier: PassingVerifier())
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "new")
        #expect(try FileManager.default.attributesOfItem(atPath: s.target)[.posixPermissions] as? Int == 0o755)
    }

    /// Opt-in (`CHE_MCP_KIT_SIGNED_FIXTURE=<notarized binary>`, needs network): the real verifier
    /// accepts a genuine binary staged in the private directory, and it installs as 0755.
    @Test(.enabled(if: SignatureVerifierTests.signedFixture != nil))
    func `A genuine binary staged privately passes the real checks and installs`() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("Binary").path
        try Data("old".utf8).write(to: URL(fileURLWithPath: target))
        let staging = try SelfUpdate.makeStagingDirectory(nextTo: target)
        let staged = URL(fileURLWithPath: staging).appendingPathComponent("Binary").path
        try FileManager.default.copyItem(atPath: SignatureVerifierTests.signedFixture!, toPath: staged)

        try SelfUpdate.verifyAndInstall(temp: staged, target: target,
                                        expectedHash: try SelfUpdate.sha256OfFile(at: staged),
                                        verifier: SystemSignatureVerifier(expectedTeamID: SignatureVerifierTests.team))
        #expect(try FileManager.default.attributesOfItem(atPath: target)[.posixPermissions] as? Int == 0o755)
        #expect(try SelfUpdate.sha256OfFile(at: target) == SelfUpdate.sha256OfFile(at: SignatureVerifierTests.signedFixture!))
    }

    @Test func `The staging directory is private, next to the target, and on the same volume`() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("iw-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("Binary").path

        let staging = try SelfUpdate.makeStagingDirectory(nextTo: target)
        #expect(URL(fileURLWithPath: staging).deletingLastPathComponent().standardizedFileURL.path
                == dir.standardizedFileURL.path)
        #expect(URL(fileURLWithPath: staging).lastPathComponent.hasPrefix(".Binary.update-"))
        let attrs = try FileManager.default.attributesOfItem(atPath: staging)
        #expect(attrs[.type] as? FileAttributeType == .typeDirectory)
        #expect(attrs[.posixPermissions] as? Int == 0o700)
        let parentDevice = try FileManager.default.attributesOfItem(atPath: dir.path)[.systemNumber] as? Int
        #expect(attrs[.systemNumber] as? Int == parentDevice)
    }
}
