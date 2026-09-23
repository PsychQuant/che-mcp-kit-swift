import Foundation
import Testing
@testable import CheMCPKit

/// #4 — every way the downloaded `.sha256` companion can be unusable must refuse the install
/// with `checksumUnavailable`; only a 200 response holding a digest yields a hash. Expected
/// messages are copied from the implementation as it stood before the extraction.
struct CompanionChecksumTests {
    private let url = URL(string: "https://github.com/o/r/releases/download/v1.0.0/Bin.sha256")!
    private let team = "ABCDE12345"
    private static let digest = String(repeating: "0123456789abcdef", count: 4)

    private func detail(of body: Data, status: Int) -> String? {
        do {
            _ = try SelfUpdate.expectedHash(fromCompanionBody: body, statusCode: status, url: url, teamID: team)
            return nil
        } catch SelfUpdate.SelfUpdateError.checksumUnavailable(let detail, let teamID) {
            #expect(teamID == team)
            return detail
        } catch {
            Issue.record("wrong error: \(error)")
            return nil
        }
    }

    @Test func `A 200 response with a digest yields the lowercase hash`() throws {
        let body = Data("\(Self.digest.uppercased())  Bin\n".utf8)
        #expect(try SelfUpdate.expectedHash(fromCompanionBody: body, statusCode: 200, url: url, teamID: team) == Self.digest)
    }

    @Test func `A non-200 status refuses and names the status and URL`() {
        #expect(detail(of: Data(Self.digest.utf8), status: 404) == "HTTP 404 from \(url.absoluteString)")
        #expect(detail(of: Data(Self.digest.utf8), status: -1) == "HTTP -1 from \(url.absoluteString)")
    }

    @Test func `A body that is not UTF-8 refuses`() {
        #expect(detail(of: Data([0xFF, 0xFE, 0xFD]), status: 200) == "companion file is not UTF-8 text")
    }

    @Test(arguments: ["", "not a hash", String(repeating: "a", count: 63)])
    func `A body without a 64-character digest refuses`(body: String) {
        #expect(detail(of: Data(body.utf8), status: 200) == "no 64-char hex SHA-256 token found in companion file content")
    }

    @Test func `A bad status is reported before a bad body`() {
        #expect(detail(of: Data([0xFF, 0xFE]), status: 500) == "HTTP 500 from \(url.absoluteString)")
        #expect(detail(of: Data(), status: 403) == "HTTP 403 from \(url.absoluteString)")
    }

    @Test(arguments: [String(repeating: "g", count: 64),          // 64 characters, not hex
                      String(repeating: "a", count: 65),          // hex, one too long
                      "  \n\t  "])                                  // whitespace only
    func `Near-miss digests are refused`(body: String) {
        #expect(detail(of: Data(body.utf8), status: 200) == "no 64-char hex SHA-256 token found in companion file content")
    }

    @Test func `The refusal message names the manual verification commands`() {
        let message = SelfUpdate.SelfUpdateError.checksumUnavailable("x", teamID: team).localizedDescription
        #expect(message.contains("`codesign --verify --strict -R '=anchor apple generic"))
        #expect(message.contains("certificate leaf[subject.OU] = \"\(team)\"' <file>`"))
        #expect(message.contains("`spctl -a -vvv -t install <file>`"))
    }
}
