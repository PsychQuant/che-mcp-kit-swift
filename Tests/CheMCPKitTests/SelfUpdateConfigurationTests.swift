import Foundation
import Testing
@testable import CheMCPKit

private struct StubVerifier: SignatureVerifying {
    let expectedTeamID = "6W377FS7BS"
    func verify(binaryAt path: String) throws {}
}

/// The values a server passes in must reproduce, character for character, what the servers
/// hard-coded before this package existed.
struct SelfUpdateConfigurationTests {
    private let cheICal = SelfUpdate.Configuration(
        owner: "PsychQuant", repository: "che-ical-mcp", assetName: "CheICalMCP",
        displayName: "CheICalMCP", currentVersion: "0.1.0", verifier: StubVerifier())

    @Test func `URLs and User-Agent match the previously hard-coded values`() {
        #expect(cheICal.latestReleaseURL.absoluteString
                == "https://api.github.com/repos/PsychQuant/che-ical-mcp/releases/latest")
        #expect(cheICal.assetDownloadURL(tag: "v0.2.0", assetName: "CheICalMCP.sha256").absoluteString
                == "https://github.com/PsychQuant/che-ical-mcp/releases/download/v0.2.0/CheICalMCP.sha256")
        #expect(cheICal.userAgent == "CheICalMCP/0.1.0 (self-update)")
    }

    @Test func `Messages that name the binary or the team use the values they carry`() {
        #expect(SelfUpdate.SelfUpdateError.binaryPathUnresolvable(binaryName: "CheICalMCP").localizedDescription
                == "Could not resolve current binary path. Run as `~/bin/CheICalMCP --self-update` so the binary path is unambiguous.")
        let signature = SelfUpdate.SelfUpdateError.signatureInvalid("exit 3", teamID: "6W377FS7BS").localizedDescription
        #expect(signature.contains("Application certificate for team 6W377FS7BS (codesign: exit 3). "))
        let checksum = SelfUpdate.SelfUpdateError.checksumUnavailable("HTTP 404", teamID: "6W377FS7BS").localizedDescription
        #expect(checksum.contains("-R '=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
                                  + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
                                  + " and certificate leaf[subject.OU] = \"6W377FS7BS\"' <file>"))
        #expect(checksum.contains("(expect `source=Notarized Developer ID`)"))
    }

    @Test func `The checksum companion parser returns nil when no digest is present`() {
        #expect(SelfUpdate.parseSHA256CompanionFile("not a hash") == nil)
        let digest = String(repeating: "Ab", count: 32)
        #expect(SelfUpdate.parseSHA256CompanionFile("\u{FEFF}\(digest)  CheICalMCP\n") == digest.lowercased())
    }
}

struct SelfUpdateFailureLineTests {
    /// `SelfUpdateError` is deliberately not `TrustedErrorMessage`, so
    /// `sanitizeForResponse(...).code` collapses to `error_unknown`. The
    /// stderr line must carry the authored message (via `rawLog`), escaped.
    @Test func `Failure line carries the authored message and escapes control characters`() {
        let error = SelfUpdate.SelfUpdateError.checksumMismatch(expected: "aa", actual: "bb")
        let line = SelfUpdate.failureLine(for: error)
        #expect(line.hasPrefix("self-update failed: SHA-256 verification FAILED"))
        #expect(line.contains("Expected: aa  Actual: bb"))
        #expect(!line.contains("error_unknown"))

        let injected = NSError(domain: "URLError", code: 1,
                               userInfo: [NSLocalizedDescriptionKey: "boom\n\u{1b}[2Jfake"])
        let escaped = SelfUpdate.failureLine(for: injected)
        #expect(!escaped.contains("\n"))
        #expect(escaped.contains("boom\\n\\x1b[2Jfake"))
    }
}
