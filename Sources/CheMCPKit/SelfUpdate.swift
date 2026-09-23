import CommonCrypto
import Foundation

// MARK: - Self-update (che-ical-mcp#49 Option 3)
//
// User-invoked upgrade path: `<Binary> --self-update` queries
// GitHub Releases API for the latest tag, compares against
// `Configuration.currentVersion`, and (if newer) atomically replaces the
// running binary at its own path.
//
// **Why discoverable + explicit, not auto**: per che-ical-mcp#49 design
// discussion, automatic upgrades risk swapping a binary mid-MCP-call
// and break running sessions. Explicit `--self-update` flag is
// listed in `--help` and README so users find it on demand.
//
// **Why atomic replace via POSIX `rename(2)` (che-ical-mcp#49 verify Finding 2)**:
// the download is staged in a private (0700) directory inside the target's
// directory, so `rename(staged → targetPath)` is guaranteed same-filesystem
// and atomic; see `verifyAndInstall` for the threat model (#1). POSIX rename(2) semantics: target either points at the
// new file or the old file at all times — never absent. This fixes
// the original (rm -f + mv) approach which had a window where the
// target didn't exist and could brick the install if mv failed.
//
// Per che-ical-mcp#62 upgrade-trap discovery: rename(2) ALSO swaps the directory
// entry (not the inode), so running MCP processes that hold the old
// inode keep their reference until exit; the new binary gets a fresh
// inode by construction (the temp file's). No stale code-signature
// cache hazard.

public enum SelfUpdate {

    /// Errors surfaced from `--self-update` invocation. **NOT** conforming
    /// to `TrustedErrorMessage` (che-ical-mcp#49 verify Finding 4): the `detail`
    /// strings come from URLSession / FileManager `localizedDescription`
    /// which is framework-controlled, not author-controlled. Per che-ical-mcp#85's
    /// `CLIError.invalidJSON` doc-comment guidance, `TrustedErrorMessage`
    /// is for messages whose entire content is author-written and safe
    /// to forward verbatim. Self-update errors interpolate framework
    /// text → must go through the standard `escapeForStderr` path on
    /// stderr write to defend against CWE-117 control-char injection.
    /// `sanitizeForInterpolation` is still applied here as defense-in-depth
    /// for the JSON wire path; stderr path is escape-handled at the
    /// caller (`failureLine(for:)` is the escape-on-write helper).
    ///
    /// The single stderr line printed when `--self-update` fails.
    ///
    /// `SelfUpdateError` is intentionally not `TrustedErrorMessage`, so
    /// `ErrorSanitizer.sanitizeForResponse(_:).code` collapses to
    /// `error_unknown`; the authored message lives in `rawLog`. stderr is the
    /// operator channel, so the raw text is the intended payload — escaped
    /// on write against CWE-117 control-character injection.
    public static func failureLine(for error: Error) -> String {
        let rawLog = ErrorSanitizer.sanitizeForResponse(error).rawLog
        return "self-update failed: \(ErrorSanitizer.escapeForStderr(rawLog))"
    }

    /// Cases whose message names the binary or the signing team carry that value, so the
    /// message is complete without any global configuration.
    public enum SelfUpdateError: LocalizedError {
        case networkUnavailable(String)
        case parseError(String)
        case downloadFailed(String)
        case installFailed(String)
        case binaryPathUnresolvable(binaryName: String)
        case checksumUnavailable(String, teamID: String)
        case checksumMismatch(expected: String, actual: String)
        case signatureInvalid(String, teamID: String)
        case notNotarized(String)
        case verificationTimedOut(tool: String, seconds: Int)

        public var errorDescription: String? {
            switch self {
            case .networkUnavailable(let detail):
                return "Network error querying GitHub Releases: \(ErrorSanitizer.sanitizeForInterpolation(detail))"
            case .parseError(let detail):
                return "Could not parse GitHub release metadata: \(ErrorSanitizer.sanitizeForInterpolation(detail))"
            case .downloadFailed(let detail):
                return "Binary download failed: \(ErrorSanitizer.sanitizeForInterpolation(detail))"
            case .installFailed(let detail):
                return "Could not install new binary: \(ErrorSanitizer.sanitizeForInterpolation(detail))"
            case .binaryPathUnresolvable(let binaryName):
                return "Could not resolve current binary path. Run as `~/bin/\(binaryName) --self-update` so the binary path is unambiguous."
            case .checksumUnavailable(let detail, let teamID):
                return "Could not fetch SHA-256 checksum companion file: \(ErrorSanitizer.sanitizeForInterpolation(detail)). " +
                       "If this release predates SHA-256 publication, the asset may legitimately lack a .sha256 file. " +
                       "Falling back is unsafe — refusing install. To check a binary by hand: " +
                       "`codesign --verify --strict -R '=\(SystemSignatureVerifier.designatedRequirement(teamID: teamID))' <file>` and " +
                       "`spctl -a -vvv -t install <file>` (expect `\(SystemSignatureVerifier.notarizedSourceLine)`)."
            case .checksumMismatch(let expected, let actual):
                return "SHA-256 verification FAILED. Refusing to install. " +
                       "Expected: \(expected)  Actual: \(actual). " +
                       "This indicates the downloaded binary does not match the maintainer-published hash. Possible causes: in-flight tampering, " +
                       "corrupted download, or compromised mirror. Do NOT install. If reproducible against a fresh release, file an issue."
            case .signatureInvalid(let detail, let teamID):
                return "Signature check FAILED. Refusing to install. The downloaded binary is not signed with a Developer ID " +
                       "Application certificate for team \(teamID) (codesign: \(ErrorSanitizer.sanitizeForInterpolation(detail))). " +
                       "Either the release was built without `make release-signed`, or the file is not the maintainer's. Your installed binary was left unchanged."
            case .notNotarized(let detail):
                return "Notarization check FAILED. Refusing to install. Gatekeeper does not report the downloaded binary as " +
                       "'Notarized Developer ID' (spctl: \(ErrorSanitizer.sanitizeForInterpolation(detail))). Your installed binary was left unchanged."
            case .verificationTimedOut(let tool, let seconds):
                let hint = tool == "spctl"
                    ? "spctl could not reach Apple's servers. Retry when the network is stable, or set SPCTL_TIMEOUT_SECONDS=<n> (max \(SystemSignatureVerifier.maxTimeoutSeconds)) for slow links."
                    : "The local signature check did not finish; the machine may be under heavy load. Retry later."
                return "\(tool) timed out after \(seconds)s. Refusing to install — your installed binary was left unchanged. \(hint)"
            }
        }
    }

    /// Everything that differs between servers. The URLs and the User-Agent are derived from
    /// these values, so one repository never self-updates from another's releases.
    public struct Configuration {
        /// GitHub owner of the releases, e.g. `PsychQuant`.
        public let owner: String
        /// GitHub repository name, e.g. `che-ical-mcp`.
        public let repository: String
        /// Release asset holding the standalone binary; `<assetName>.sha256` is its checksum companion.
        public let assetName: String
        /// Product name shown in progress output and the User-Agent, normally the binary name.
        public let displayName: String
        /// Version of the running binary, without a leading `v`.
        public let currentVersion: String
        /// Decides whether a downloaded binary may be installed.
        public let verifier: SignatureVerifying

        public init(owner: String, repository: String, assetName: String, displayName: String,
                    currentVersion: String, verifier: SignatureVerifying) {
            self.owner = owner
            self.repository = repository
            self.assetName = assetName
            self.displayName = displayName
            self.currentVersion = currentVersion
            self.verifier = verifier
        }

        /// GitHub Releases API URL for the latest tag.
        public var latestReleaseURL: URL {
            URL(string: "https://api.github.com/repos/\(owner)/\(repository)/releases/latest")!
        }

        /// Download URL for `assetName` attached to release `tag`.
        public func assetDownloadURL(tag: String, assetName: String) -> URL {
            URL(string: "https://github.com/\(owner)/\(repository)/releases/download/\(tag)/\(assetName)")!
        }

        public var userAgent: String { "\(displayName)/\(currentVersion) (self-update)" }
    }

    /// Run the self-update flow. Prints user-facing progress to stdout.
    /// Throws on any failure mode (network, parse, download, install).
    /// Returns silently on success — caller exits 0.
    public static func run(_ configuration: Configuration) async throws {
        let current = configuration.currentVersion
        print("\(configuration.displayName) self-update")
        print("Current version: \(current)")
        print("Querying GitHub Releases for latest...")

        let latestTag = try await fetchLatestTag(configuration)
        let latestVersion = stripTagPrefix(latestTag)
        print("Latest version:  \(latestVersion)")

        if latestVersion == current {
            print("✓ Already on latest version. No update needed.")
            return
        }

        // Compare semver-ish to make sure we're not "downgrading".
        if !isNewer(candidate: latestVersion, than: current) {
            print("ℹ Latest tag (\(latestVersion)) is not newer than current (\(current)).")
            print("  No update needed. (If you intended to downgrade, do it manually via curl + rm -f.)")
            return
        }

        let currentBinaryPath = try resolveCurrentBinaryPath(binaryName: configuration.assetName)
        print("Will install to: \(currentBinaryPath)")

        let assetName = configuration.assetName
        let downloadURL = configuration.assetDownloadURL(tag: latestTag, assetName: assetName)
        let sha256URL = configuration.assetDownloadURL(tag: latestTag, assetName: assetName + ".sha256")
        print("Fetching SHA-256 companion: \(sha256URL.absoluteString)")
        let expectedHash = try await fetchExpectedSHA256(from: sha256URL, configuration: configuration)
        print("Expected SHA-256: \(expectedHash)")

        print("Downloading \(assetName) from \(downloadURL.absoluteString) ...")
        // Stage in a private 0700 directory inside the target's directory: same volume, so
        // rename(2) is atomic (che-ical-mcp#49 verify F2). See `verifyAndInstall` for which
        // accounts that keeps out (#1).
        try await withStagingDirectory(nextTo: currentBinaryPath) { stagingDirectory in
            let stagedPath = URL(fileURLWithPath: stagingDirectory)
                .appendingPathComponent(URL(fileURLWithPath: currentBinaryPath).lastPathComponent).path
            let tempPath = try await downloadBinary(from: downloadURL, to: stagedPath,
                                                    userAgent: configuration.userAgent)
            try verifyAndInstall(temp: tempPath, target: currentBinaryPath,
                                 expectedHash: expectedHash, verifier: configuration.verifier)
        }
        print("✓ Installed \(latestVersion) to \(currentBinaryPath)")
        print("ℹ If this binary is currently running as an MCP server, restart your")
        print("  MCP host (Claude Desktop / Claude Code) to pick up the new version.")
    }

    // MARK: - Internals

    /// Hash → signature → install, in that order (che-ical-mcp#98 for the hash). Any refusal leaves `target` untouched
    /// and removes `temp`; on success `temp` has become `target` via `rename(2)`.
    ///
    /// The staged file is opened once, before any check, without following symlinks and without
    /// blocking on a FIFO. Both hashes are computed from that descriptor, the exec bit is set with
    /// `fchmod`, and immediately before `rename(2)` the path must still name that same file (#1).
    /// The signature check itself reads the path; that it saw our file is guaranteed by the private
    /// staging directory, not by a check, for the accounts the threat model below covers.
    ///
    /// Threat model (#1): defended are accounts with no write access to the target's directory and
    /// accounts that can only *add* entries there because it is sticky (`+t`) — they cannot remove
    /// or rename the private staging directory `run` creates, cannot enter it, and cannot touch the
    /// staged file. Not defended, by design: the same user, and any account that can remove or rename
    /// entries in the target's directory; both can replace the installed binary without this
    /// function. The window between the final identity check and `rename(2)` is reachable only by them.
    public static func verifyAndInstall(temp: String, target: String, expectedHash: String,
                                        verifier: SignatureVerifying) throws {
        try verifyAndInstall(temp: temp, target: target, expectedHash: expectedHash,
                             verifier: verifier, beforeRename: nil)
    }

    /// `beforeRename` is a test seam: it runs after the final hash and `fchmod`, before the last
    /// identity check.
    static func verifyAndInstall(temp: String, target: String, expectedHash: String,
                                 verifier: SignatureVerifying,
                                 beforeRename: (() throws -> Void)?) throws {
        var installed = false
        defer { if !installed { try? FileManager.default.removeItem(atPath: temp) } }

        let notRegular = "downloaded file is no longer a regular file at \(temp) — refusing to install"
        let fd = openRetryingEINTR(temp, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw SelfUpdateError.installFailed(notRegular) }
        defer { close(fd) }
        var opened = stat()
        guard fstat(fd, &opened) == 0, (opened.st_mode & S_IFMT) == S_IFREG else {
            throw SelfUpdateError.installFailed(notRegular)
        }

        let actualHash = try sha256(ofDescriptor: fd, path: temp)
        print("Actual SHA-256:   \(actualHash)")
        guard actualHash.lowercased() == expectedHash.lowercased() else {
            throw SelfUpdateError.checksumMismatch(expected: expectedHash, actual: actualHash)
        }
        print("✓ SHA-256 verification passed")

        print("Checking Developer ID signature and notarization...")
        try verifier.verify(binaryAt: temp)
        print("✓ Signed by team \(verifier.expectedTeamID) and notarized")
        // codesign and spctl read the path, not our descriptor. That the path named our file while
        // they ran rests on the private staging directory; a check here would add nothing, since a
        // swap that is undone before it passes, and one that is not is caught before rename(2).

        // Content written into the same file during the check is caught here.
        let finalHash = try sha256(ofDescriptor: fd, path: temp)
        guard finalHash.lowercased() == expectedHash.lowercased() else {
            throw SelfUpdateError.checksumMismatch(expected: expectedHash, actual: finalHash)
        }
        // `write` does not set the exec bit. fchmod acts on the checked file; a path-based chmod
        // would follow a symlink swapped in meanwhile.
        guard fchmod(fd, 0o755) == 0 else {
            throw SelfUpdateError.installFailed("chmod +x on temp file: \(String(cString: strerror(errno)))")
        }

        try beforeRename?()
        try requireSameFile(at: temp, as: opened)
        try installBinary(from: temp, to: target)
        installed = true
    }

    /// Refuses unless `path` (not following a final symlink) is a regular file with the identity
    /// (`st_dev`, `st_ino`) recorded in `opened`.
    private static func requireSameFile(at path: String, as opened: stat) throws {
        var current = stat()
        var rc: Int32
        repeat { rc = lstat(path, &current) } while rc != 0 && errno == EINTR
        guard rc == 0, (current.st_mode & S_IFMT) == S_IFREG,
              current.st_dev == opened.st_dev, current.st_ino == opened.st_ino else {
            throw SelfUpdateError.installFailed(
                "downloaded file at \(path) was replaced after verification — refusing to install")
        }
    }

    private static func openRetryingEINTR(_ path: String, _ flags: Int32, _ mode: mode_t = 0) -> Int32 {
        var fd: Int32
        repeat { fd = open(path, flags, mode) } while fd < 0 && errno == EINTR
        return fd
    }

    /// Writes the download to `temp` as a NEW file (`O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600):
    /// an existing file, symlink or hard link at that name is refused, never written through.
    static func writeStaged(_ data: Data, to temp: String) throws {
        let fd = openRetryingEINTR(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            throw SelfUpdateError.downloadFailed("could not write temp file at \(temp): \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw SelfUpdateError.downloadFailed("could not write temp file at \(temp): \(String(cString: strerror(errno)))")
                }
                offset += n
            }
        }
    }

    /// Runs `body` with a private staging directory next to `target` and removes the directory
    /// afterwards, whether `body` returns or throws.
    static func withStagingDirectory<T>(nextTo target: String, _ body: (String) async throws -> T) async throws -> T {
        let staging = try makeStagingDirectory(nextTo: target)
        defer { try? FileManager.default.removeItem(atPath: staging) }
        return try await body(staging)
    }

    /// A private directory for the download: created with `mkdtemp` (mode 0700, inherited ACL
    /// entries removed) inside the target's directory, so the final rename(2) stays on one volume
    /// and no other account can enter it. Mode bits do not stop an account that can remove or
    /// rename entries in the target's directory from replacing the directory itself — that account
    /// is outside the threat model (see `verifyAndInstall`). The caller removes it.
    static func makeStagingDirectory(nextTo target: String) throws -> String {
        let targetURL = URL(fileURLWithPath: target)
        let template = targetURL.deletingLastPathComponent()
            .appendingPathComponent(".\(targetURL.lastPathComponent).update-XXXXXX").path
        var buffer = Array(template.utf8CString)
        guard let created = mkdtemp(&buffer) else {
            throw SelfUpdateError.installFailed(
                "could not create a private staging directory next to \(target): \(String(cString: strerror(errno)))")
        }
        let path = String(cString: created)
        // mkdtemp sets mode 0700, but on APFS/HFS+ the directory can still inherit ACL entries from
        // its parent that grant other accounts access. Replace them with an empty ACL.
        if let empty = acl_init(0) {
            let rc = acl_set_file(path, ACL_TYPE_EXTENDED, empty)
            let failure = errno
            acl_free(UnsafeMutableRawPointer(empty))
            if rc != 0 && failure != ENOTSUP {
                try? FileManager.default.removeItem(atPath: path)
                throw SelfUpdateError.installFailed(
                    "could not clear inherited ACLs on the staging directory next to \(target): \(String(cString: strerror(failure)))")
            }
        }
        return path
    }

    /// Strip leading `v` from tags like `v1.7.1` → `1.7.1`.
    public static func stripTagPrefix(_ tag: String) -> String {
        if tag.hasPrefix("v") {
            return String(tag.dropFirst())
        }
        return tag
    }

    /// SemVer precedence (§11), tolerant of non-SemVer tags. Returns true iff `candidate` is strictly
    /// newer than `current`. Build metadata (`+…`) is ignored; the core `major.minor.patch` compares
    /// numerically (missing components count as 0); for equal cores a version without a prerelease
    /// outranks one with (`1.0.0 > 1.0.0-beta`), and prerelease identifiers compare numerically
    /// when numeric, in ASCII order otherwise, numeric < alphanumeric, longer list wins on a tie.
    /// A non-numeric core component falls back to string comparison so odd tags never crash.
    public static func isNewer(candidate: String, than current: String) -> Bool {
        compareVersions(candidate, current) > 0
    }

    /// -1 / 0 / 1 in SemVer precedence order.
    public static func compareVersions(_ lhs: String, _ rhs: String) -> Int {
        func split(_ v: String) -> (core: [String], pre: [String]) {
            let noBuild = v.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            let parts = noBuild.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let core = parts[0].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            let pre = parts.count > 1 ? parts[1].split(separator: ".", omittingEmptySubsequences: false).map(String.init) : []
            return (core, pre)
        }
        func cmp<T: Comparable>(_ a: T, _ b: T) -> Int { a < b ? -1 : (a > b ? 1 : 0) }

        let (a, b) = (split(lhs), split(rhs))
        for i in 0..<max(a.core.count, b.core.count) {
            let x = i < a.core.count ? a.core[i] : "0"
            let y = i < b.core.count ? b.core[i] : "0"
            let c = (Int(x).flatMap { xi in Int(y).map { cmp(xi, $0) } }) ?? cmp(x, y)
            if c != 0 { return c }
        }
        switch (a.pre.isEmpty, b.pre.isEmpty) {
        case (true, true): return 0
        case (true, false): return 1
        case (false, true): return -1
        case (false, false): break
        }
        for i in 0..<min(a.pre.count, b.pre.count) {
            let (x, y) = (a.pre[i], b.pre[i])
            let c: Int
            switch (Int(x), Int(y)) {
            case let (xi?, yi?): c = cmp(xi, yi)
            case (.some, .none): c = -1
            case (.none, .some): c = 1
            case (.none, .none): c = cmp(x, y)
            }
            if c != 0 { return c }
        }
        return cmp(a.pre.count, b.pre.count)
    }

    /// Resolve the current binary's path on disk via `BinaryPathResolver` (che-ical-mcp#129) —
    /// multi-hop realpath, with the additional `$PATH` walk needed for bare argv[0] invocations
    /// (`<Binary> --self-update` shell-resolved; che-ical-mcp#49 verify Finding 3).
    private static func resolveCurrentBinaryPath(binaryName: String) throws -> String {
        guard let argv0 = CommandLine.arguments.first else {
            throw SelfUpdateError.binaryPathUnresolvable(binaryName: binaryName)
        }
        do {
            return try BinaryPathResolver.resolveWithPATHFallback(argv0)
        } catch {
            throw SelfUpdateError.binaryPathUnresolvable(binaryName: binaryName)
        }
    }

    /// Fetch the SHA-256 companion file from a release asset URL (che-ical-mcp#98).
    /// Companion file format: single-line lowercase hex digest (matching
    /// `shasum -a 256` / `sha256sum` standard output, first column).
    /// Returns the parsed hex string. Throws `checksumUnavailable` on
    /// network failure or file-format issues.
    private static func fetchExpectedSHA256(from url: URL, configuration: Configuration) async throws -> String {
        let teamID = configuration.verifier.expectedTeamID
        var request = URLRequest(url: url)
        request.setValue(configuration.userAgent, forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 30

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw SelfUpdateError.checksumUnavailable("network: \(error.localizedDescription)", teamID: teamID)
        }
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
        return try expectedHash(fromCompanionBody: data, statusCode: statusCode, url: url, teamID: teamID)
    }

    /// The step after the companion download: anything but a 200 response holding a
    /// 64-character hex digest refuses the install with `checksumUnavailable` (`statusCode` is
    /// `-1` for a non-HTTP response). Split from the network call so every refusal is testable.
    static func expectedHash(fromCompanionBody data: Data, statusCode: Int, url: URL,
                             teamID: String) throws -> String {
        guard statusCode == 200 else {
            throw SelfUpdateError.checksumUnavailable("HTTP \(statusCode) from \(url.absoluteString)", teamID: teamID)
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw SelfUpdateError.checksumUnavailable("companion file is not UTF-8 text", teamID: teamID)
        }
        guard let hash = parseSHA256CompanionFile(text) else {
            throw SelfUpdateError.checksumUnavailable(
                "no 64-char hex SHA-256 token found in companion file content", teamID: teamID)
        }
        return hash
    }

    /// Parse the SHA-256 companion file content. Accepts:
    /// - bare hex hash on its own line: `abc123...`
    /// - `shasum -a 256` style with filename: `abc123  binary-path`
    /// First valid 64-char hex token wins; trims whitespace; returns lowercase, or `nil` when the
    /// content holds no such token. Public so tests can pin the parser without network mocking.
    public static func parseSHA256CompanionFile(_ raw: String) -> String? {
        // Strip BOM + whitespace; split into tokens.
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\u{FEFF}", with: "")
        for line in normalized.split(separator: "\n") {
            for token in line.split(whereSeparator: { $0.isWhitespace }) {
                let lower = token.lowercased()
                if lower.count == 64 && lower.allSatisfy({ "0123456789abcdef".contains($0) }) {
                    return lower
                }
            }
        }
        return nil
    }

    /// Compute SHA-256 of a file on disk. Uses CommonCrypto via a manual
    /// streamed hash so we don't pull CryptoKit into the test target's
    /// transitive surface.
    public static func sha256OfFile(at path: String) throws -> String {
        guard FileManager.default.fileExists(atPath: path) else {
            throw SelfUpdateError.installFailed("file does not exist at \(path) — cannot hash")
        }
        let fd = open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            throw SelfUpdateError.installFailed("could not open \(path) for hashing: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        return try sha256(ofDescriptor: fd, path: path)
    }

    /// SHA-256 of the whole file behind `fd` (read with `pread` from offset 0, so repeated calls
    /// hash the same bytes); `path` is only for messages.
    static func sha256(ofDescriptor fd: Int32, path: String) throws -> String {
        var ctx = CC_SHA256_CTX()
        CC_SHA256_Init(&ctx)

        let bufferSize = 65536
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var offset: off_t = 0
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, bufferSize, offset) }
            if bytesRead < 0 {
                if errno == EINTR { continue }
                throw SelfUpdateError.installFailed("error reading \(path) for hashing: \(String(cString: strerror(errno)))")
            }
            if bytesRead == 0 { break }
            offset += off_t(bytesRead)
            _ = buffer.withUnsafeBufferPointer { CC_SHA256_Update(&ctx, $0.baseAddress, CC_LONG(bytesRead)) }
        }

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        digest.withUnsafeMutableBufferPointer { _ = CC_SHA256_Final($0.baseAddress, &ctx) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Fetch the `tag_name` field from GitHub Releases API.
    private static func fetchLatestTag(_ configuration: Configuration) async throws -> String {
        var request = URLRequest(url: configuration.latestReleaseURL)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue(configuration.userAgent, forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 30

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw SelfUpdateError.networkUnavailable(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw SelfUpdateError.networkUnavailable("non-HTTP response")
        }
        guard http.statusCode == 200 else {
            throw SelfUpdateError.networkUnavailable("HTTP \(http.statusCode) from GitHub Releases API")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SelfUpdateError.parseError("response is not a JSON object")
        }
        guard let tag = json["tag_name"] as? String, !tag.isEmpty else {
            throw SelfUpdateError.parseError("response missing 'tag_name' field")
        }
        return tag
    }

    /// Download the binary asset to `temp`, a path inside the private staging directory
    /// `run` created next to the target. Returns `temp`; the caller removes the directory.
    ///
    /// **che-ical-mcp#49 verify Finding 2**: the staging directory is inside the target's
    /// directory (not `NSTemporaryDirectory()`) so that the
    /// final `rename(2)` is guaranteed same-filesystem and atomic. This
    /// means the upgrade is either complete or unchanged — no window
    /// where the target path doesn't exist.
    private static func downloadBinary(from url: URL, to temp: String, userAgent: String) async throws -> String {
        var request = URLRequest(url: url)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 120

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw SelfUpdateError.downloadFailed(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw SelfUpdateError.downloadFailed("HTTP \(code) from release download URL")
        }
        guard data.count > 0 else {
            throw SelfUpdateError.downloadFailed("downloaded asset is empty (0 bytes)")
        }

        // `temp` is inside the private staging directory next to the target (see `run`).
        try writeStaged(data, to: temp)
        return temp
    }

    /// Install the downloaded binary at `targetPath` using POSIX
    /// `rename(2)` for true atomic replacement.
    ///
    /// **che-ical-mcp#49 verify Finding 2 (atomic-replace correctness)**: previous
    /// implementation did `rm -f` THEN `mv`, leaving a window where
    /// the target path didn't exist. If `mv` failed mid-install, the
    /// system was bricked. Fixed by POSIX `rename(2)`, which atomically replaces the target
    /// when both are on one volume — guaranteed because the staging directory is inside the
    /// target's directory. (The exec bit is set earlier with `fchmod` on the verified
    /// descriptor, #1.)
    /// `rename(2)` semantics: target either points at the new file or
    /// the old file at all times — never absent. Stale inode caches
    /// (che-ical-mcp#62 trap) are irrelevant here because rename swaps the directory
    /// entry, not the inode the running process holds.
    private static func installBinary(from tempPath: String, to targetPath: String) throws {
        // POSIX rename(2): atomic same-filesystem replacement. Either
        // succeeds (target points at new) or fails leaving target alone.
        // The exec bit was already set through the verified descriptor (#1).
        let result = rename(tempPath, targetPath)
        if result != 0 {
            let errnoCode = errno
            // Best-effort cleanup of the staged temp on failure.
            try? FileManager.default.removeItem(atPath: tempPath)
            let errString = String(cString: strerror(errnoCode))
            throw SelfUpdateError.installFailed(
                "rename(2) \(tempPath) → \(targetPath) failed: \(errString) (errno=\(errnoCode)). " +
                "If permission denied, re-run with sudo or install to a user-writable location first."
            )
        }
    }
}
