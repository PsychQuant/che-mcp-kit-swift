import Testing
@testable import CheMCPKit

/// `--self-update` must offer the final release to users on a prerelease (SemVer §11).
struct VersionOrderingTests {
    private static let newerPairs: [(String, String)] = [
        ("1.0.0", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.1"),
        ("1.0.0-beta.11", "1.0.0-beta.2"),     // numeric identifiers compare numerically
        ("1.0.0-rc.1", "1.0.0-beta"),          // alphanumeric identifiers compare in ASCII order
        ("1.0.0-alpha.1", "1.0.0-alpha"),      // longer identifier list wins when the prefix is equal
        ("1.0.0-alpha.beta", "1.0.0-alpha.1"), // alphanumeric > numeric
        ("0.10.0", "0.9.0"),
        ("0.10.0", "0.9.0-rc1"),
        ("1.0.1-beta", "1.0.0"),               // core decides before prerelease
        ("1.1", "1.0.9"),                      // missing components count as 0
    ]

    @Test func `A version is newer than its predecessors`() {
        for (candidate, current) in Self.newerPairs {
            #expect(SelfUpdate.isNewer(candidate: candidate, than: current), "\(candidate) > \(current)")
            #expect(!SelfUpdate.isNewer(candidate: current, than: candidate), "\(current) !> \(candidate)")
        }
    }

    @Test func `Equal versions are not newer, and build metadata is ignored`() {
        #expect(!SelfUpdate.isNewer(candidate: "1.0.0", than: "1.0.0"))
        #expect(!SelfUpdate.isNewer(candidate: "1.0.0-beta.1", than: "1.0.0-beta.1"))
        #expect(!SelfUpdate.isNewer(candidate: "1.0.0+build.7", than: "1.0.0+build.3"))
        #expect(!SelfUpdate.isNewer(candidate: "1.0", than: "1.0.0"))
    }

    @Test func `Non-SemVer tags still compare without crashing`() {
        #expect(SelfUpdate.isNewer(candidate: "2026.10", than: "2026.9"))
        #expect(!SelfUpdate.isNewer(candidate: "", than: "0.1.0"))
    }
}
