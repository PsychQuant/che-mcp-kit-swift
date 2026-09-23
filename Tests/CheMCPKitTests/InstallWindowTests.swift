import Foundation
import Testing
@testable import CheMCPKit

/// #1 — after the checks, the file that `rename(2)` installs must be the one that was hashed:
/// no swap between the final hash and the rename, no symlink, no path-based `chmod`, and the
/// download staged in a directory only the updater's account can enter.
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
