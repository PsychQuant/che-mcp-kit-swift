import Foundation
import Testing
@testable import CheMCPKit

/// `--self-update` must refuse a downloaded binary that is not Developer ID signed by the expected
/// team and notarized. Fixtures are built at test time in a private temp directory; no signed
/// binary is committed.
struct SignatureVerifierTests {
    /// The team the opt-in real-binary fixture is signed by.
    static let team = "6W377FS7BS"

    // MARK: - fixtures

    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sigverify-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Writes an executable shell script and returns its path.
    private static func makeStub(_ body: String, in dir: URL, name: String) throws -> String {
        let url = dir.appendingPathComponent(name)
        try "#!/bin/sh\n\(body)\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url.path
    }

    private static func run(_ tool: String, _ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
    }

    private static func isSignatureInvalid(_ error: Error) -> Bool {
        if case SelfUpdate.SelfUpdateError.signatureInvalid = error { return true }
        return false
    }

    /// codesign exits 3 when the code is readable but fails the requirement, and 1 for a malformed
    /// requirement or unreadable signature. Offline refusals must be the former, or they pass for the
    /// wrong reason (a requirement codesign cannot parse refuses everything, including our releases).
    private static func refusedByRequirement(_ error: Error) -> Bool {
        if case SelfUpdate.SelfUpdateError.signatureInvalid(let detail, _) = error { return detail.hasPrefix("exit 3") }
        return false
    }

    static let signedFixture = ProcessInfo.processInfo.environment["CHE_MCP_KIT_SIGNED_FIXTURE"]

    // MARK: - identity (real codesign, offline)

    @Test func `An ad-hoc signed binary is refused as signatureInvalid`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let bin = dir.appendingPathComponent("adhoc").path
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: bin)
        try Self.run("/usr/bin/codesign", ["--force", "--sign", "-", bin])

        #expect(throws: (any Error).self) { try SystemSignatureVerifier(expectedTeamID: Self.team).verify(binaryAt: bin) }
        do { try SystemSignatureVerifier(expectedTeamID: Self.team).verify(binaryAt: bin) } catch {
            #expect(Self.refusedByRequirement(error), "got \(error)")
        }
    }

    @Test func `An Apple platform binary is refused because it is not our team`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let bin = dir.appendingPathComponent("platform").path
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: bin)

        do {
            try SystemSignatureVerifier(expectedTeamID: Self.team).verify(binaryAt: bin)
            Issue.record("expected refusal for an Apple-signed, non-team binary")
        } catch {
            #expect(Self.refusedByRequirement(error), "got \(error)")
        }
    }

    @Test func `The designated requirement pins the Developer ID chain and our team`() {
        let req = SystemSignatureVerifier(expectedTeamID: "6W377FS7BS").designatedRequirement
        #expect(req == SystemSignatureVerifier.designatedRequirement(teamID: "6W377FS7BS"))
        #expect(req.contains("anchor apple generic"))
        #expect(req.contains("1.2.840.113635.100.6.2.6"))   // Developer ID CA
        #expect(req.contains("1.2.840.113635.100.6.1.13"))  // Developer ID Application leaf
        #expect(req.contains("leaf[subject.OU] = \"6W377FS7BS\""))
    }

    // MARK: - notarization (stub codesign/spctl, offline)

    @Test func `spctl output without the Notarized Developer ID source is refused as notNotarized`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let ok = try Self.makeStub("exit 0", in: dir, name: "codesign")
        let spctl = try Self.makeStub("echo \"$4: accepted\"; echo 'source=Developer ID'; exit 0", in: dir, name: "spctl")
        let verifier = SystemSignatureVerifier(expectedTeamID: Self.team, codesignPath: ok, spctlPath: spctl, spctlTimeoutSeconds: 5)

        do {
            try verifier.verify(binaryAt: "/tmp/whatever")
            Issue.record("expected notNotarized")
        } catch SelfUpdate.SelfUpdateError.notNotarized {
            // expected
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test func `A non-zero spctl exit is refused even if the source line is present`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let ok = try Self.makeStub("exit 0", in: dir, name: "codesign")
        let spctl = try Self.makeStub("echo 'source=Notarized Developer ID'; exit 3", in: dir, name: "spctl")
        let verifier = SystemSignatureVerifier(expectedTeamID: Self.team, codesignPath: ok, spctlPath: spctl, spctlTimeoutSeconds: 5)

        do {
            try verifier.verify(binaryAt: "/tmp/whatever")
            Issue.record("expected notNotarized")
        } catch SelfUpdate.SelfUpdateError.notNotarized {
            // expected
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test func `Exact Notarized Developer ID source with exit 0 passes`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let ok = try Self.makeStub("exit 0", in: dir, name: "codesign")
        let spctl = try Self.makeStub("echo 'x: accepted'; echo 'source=Notarized Developer ID'; exit 0", in: dir, name: "spctl")
        let verifier = SystemSignatureVerifier(expectedTeamID: Self.team, codesignPath: ok, spctlPath: spctl, spctlTimeoutSeconds: 5)

        try verifier.verify(binaryAt: "/tmp/whatever")
    }

    @Test func `A hung spctl is terminated and refused as an spctl timeout`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let ok = try Self.makeStub("exit 0", in: dir, name: "codesign")
        let spctl = try Self.makeStub("exec sleep 30", in: dir, name: "spctl")
        let verifier = SystemSignatureVerifier(expectedTeamID: Self.team, codesignPath: ok, spctlPath: spctl, spctlTimeoutSeconds: 1)

        let start = Date()
        do {
            try verifier.verify(binaryAt: "/tmp/whatever")
            Issue.record("expected timeout")
        } catch SelfUpdate.SelfUpdateError.verificationTimedOut(let tool, let seconds) {
            #expect(tool == "spctl")
            #expect(seconds == 1)
        } catch {
            Issue.record("wrong error: \(error)")
        }
        #expect(Date().timeIntervalSince(start) < 10)
    }

    @Test func `A hung codesign is refused as a codesign timeout, not as a bad signature`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let codesign = try Self.makeStub("exec sleep 30", in: dir, name: "codesign")
        let spctl = try Self.makeStub("exit 0", in: dir, name: "spctl")
        let verifier = SystemSignatureVerifier(expectedTeamID: Self.team, codesignPath: codesign, spctlPath: spctl,
                                               spctlTimeoutSeconds: 30, codesignTimeoutSeconds: 1)
        do {
            try verifier.verify(binaryAt: "/tmp/whatever")
            Issue.record("expected timeout")
        } catch SelfUpdate.SelfUpdateError.verificationTimedOut(let tool, let seconds) {
            #expect(tool == "codesign")
            #expect(seconds == 1)
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test func `SPCTL_TIMEOUT_SECONDS accepts positive integers and falls back to 60 otherwise`() {
        #expect(SystemSignatureVerifier.timeoutSeconds(from: [:]) == 60)
        #expect(SystemSignatureVerifier.timeoutSeconds(from: ["SPCTL_TIMEOUT_SECONDS": "120"]) == 120)
        #expect(SystemSignatureVerifier.timeoutSeconds(from: ["SPCTL_TIMEOUT_SECONDS": "99999999"]) == SystemSignatureVerifier.maxTimeoutSeconds)
        for bad in ["0", "-5", "+5", " 5", "abc", "1.5", ""] {
            #expect(SystemSignatureVerifier.timeoutSeconds(from: ["SPCTL_TIMEOUT_SECONDS": bad]) == 60, "value \(bad)")
        }
    }

    // MARK: - real signed binary (opt-in: CHE_MCP_KIT_SIGNED_FIXTURE=<path>, needs network)

    @Test(.enabled(if: SignatureVerifierTests.signedFixture != nil))
    func `A real Developer ID signed and notarized binary passes`() throws {
        try SystemSignatureVerifier(expectedTeamID: Self.team).verify(binaryAt: Self.signedFixture!)
    }

    @Test(.enabled(if: SignatureVerifierTests.signedFixture != nil))
    func `A signed binary with one byte flipped is refused as signatureInvalid`() throws {
        let dir = try Self.makeTempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let bin = dir.appendingPathComponent("tampered").path
        try FileManager.default.copyItem(atPath: Self.signedFixture!, toPath: bin)
        let h = try FileHandle(forUpdating: URL(fileURLWithPath: bin))
        let size = try h.seekToEnd()
        try h.seek(toOffset: size / 2)
        let byte = try h.read(upToCount: 1) ?? Data([0])
        try h.seek(toOffset: size / 2)
        try h.write(contentsOf: Data([byte[0] ^ 0xFF]))
        try h.close()

        do {
            try SystemSignatureVerifier(expectedTeamID: Self.team).verify(binaryAt: bin)
            Issue.record("expected refusal for a tampered binary")
        } catch {
            #expect(Self.isSignatureInvalid(error), "got \(error)")
        }
    }
}

/// The post-download sequence runs hash → signature → install, and any refusal leaves the
/// installed binary untouched.
struct VerifyAndInstallOrderingTests {

    private final class FakeVerifier: SignatureVerifying, @unchecked Sendable {
        let expectedTeamID = "TEAM000000"
        var calls: [String] = []
        let error: Error?
        init(throwing error: Error? = nil) { self.error = error }
        func verify(binaryAt path: String) throws {
            calls.append(path)
            if let error { throw error }
        }
    }

    private static func setUp() throws -> (dir: URL, temp: String, target: String, hash: String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("vai-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let target = dir.appendingPathComponent("Binary").path
        let temp = dir.appendingPathComponent(".Binary.update-x").path
        try Data("old".utf8).write(to: URL(fileURLWithPath: target))
        try Data("new".utf8).write(to: URL(fileURLWithPath: temp))
        return (dir, temp, target, try SelfUpdate.sha256OfFile(at: temp))
    }

    @Test func `A refused signature leaves the target untouched and removes the temp file`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let verifier = FakeVerifier(throwing: SelfUpdate.SelfUpdateError.signatureInvalid("ad-hoc", teamID: "TEAM000000"))

        #expect(throws: SelfUpdate.SelfUpdateError.self) {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash, verifier: verifier)
        }
        #expect(verifier.calls == [s.temp])
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
        #expect(!FileManager.default.fileExists(atPath: s.temp))
    }

    @Test func `A hash mismatch refuses before the signature check runs`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let verifier = FakeVerifier()

        #expect(throws: SelfUpdate.SelfUpdateError.self) {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: String(repeating: "0", count: 64), verifier: verifier)
        }
        #expect(verifier.calls.isEmpty)
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
        #expect(!FileManager.default.fileExists(atPath: s.temp))
    }

    /// A verifier that replaces the file it was asked to check — the TOCTOU the re-hash closes.
    private final class SwappingVerifier: SignatureVerifying, @unchecked Sendable {
        let expectedTeamID = "TEAM000000"
        func verify(binaryAt path: String) throws {
            try Data("evil".utf8).write(to: URL(fileURLWithPath: path))
        }
    }

    @Test func `A temp file swapped after the signature check is refused before rename`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }

        do {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash, verifier: SwappingVerifier())
            Issue.record("expected refusal")
        } catch SelfUpdate.SelfUpdateError.checksumMismatch {
            // expected
        } catch {
            Issue.record("wrong error: \(error)")
        }
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
        #expect(!FileManager.default.fileExists(atPath: s.temp))
    }

    /// Replaces the temp file with a symlink to a copy of the genuine bytes: a path-following
    /// re-hash still matches, but rename(2) would install the link itself.
    private final class SymlinkSwappingVerifier: SignatureVerifying, @unchecked Sendable {
        let expectedTeamID = "TEAM000000"
        func verify(binaryAt path: String) throws {
            let fm = FileManager.default
            let genuine = path + ".genuine"
            try fm.copyItem(atPath: path, toPath: genuine)
            try fm.removeItem(atPath: path)
            try fm.createSymbolicLink(atPath: path, withDestinationPath: genuine)
        }
    }

    @Test func `A temp file swapped for a symlink to genuine bytes is refused before rename`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }

        #expect(throws: SelfUpdate.SelfUpdateError.self) {
            try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash, verifier: SymlinkSwappingVerifier())
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: s.target)
        #expect(attrs[.type] as? FileAttributeType == .typeRegular)
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "old")
    }

    @Test func `Hash and signature both passing replaces the target`() throws {
        let s = try Self.setUp(); defer { try? FileManager.default.removeItem(at: s.dir) }
        let verifier = FakeVerifier()

        try SelfUpdate.verifyAndInstall(temp: s.temp, target: s.target, expectedHash: s.hash, verifier: verifier)
        #expect(verifier.calls == [s.temp])
        #expect(try String(contentsOfFile: s.target, encoding: .utf8) == "new")
        #expect(!FileManager.default.fileExists(atPath: s.temp))
    }
}
