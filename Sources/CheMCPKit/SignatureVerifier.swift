import Foundation

/// Decides whether a downloaded binary may replace the installed one.
public protocol SignatureVerifying {
    /// The Developer ID team the binary must be signed by (shown in progress output).
    var expectedTeamID: String { get }
    /// Returns normally only when `path` is acceptable; otherwise throws a `SelfUpdateError`.
    func verify(binaryAt path: String) throws
}

/// Checks identity and notarization with the same two tools the release pipeline uses:
///
/// 1. `codesign --verify --strict -R <requirement>` — the signature is intact **and** chains to a
///    Developer ID Application certificate issued to `expectedTeamID`. `--strict` alone accepts ad-hoc
///    signatures (measured 2026-09-23), so the requirement is what pins identity.
/// 2. `spctl -a -vvv -t install` must exit 0 and print `source=Notarized Developer ID` — the form
///    a notarizing release script gates releases on. `-t execute` is deliberately not used:
///    it rejects every bare Mach-O, notarized or not.
///
/// A raw Mach-O cannot be stapled, so spctl consults Apple's servers. That call can hang, so it runs
/// under a timeout and a timeout is a refusal (fail closed).
public struct SystemSignatureVerifier: SignatureVerifying {
    public let expectedTeamID: String

    /// Developer ID CA intermediate + Developer ID Application leaf + `teamID`.
    public static func designatedRequirement(teamID: String) -> String {
        "anchor apple generic" +
        " and certificate 1[field.1.2.840.113635.100.6.2.6] exists" +
        " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" +
        " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    public var designatedRequirement: String { Self.designatedRequirement(teamID: expectedTeamID) }

    public static let notarizedSourceLine = "source=Notarized Developer ID"
    public static let defaultTimeoutSeconds = 60
    /// Ceiling for `SPCTL_TIMEOUT_SECONDS`, so a stray huge value cannot turn a network hiccup
    /// into an effectively unbounded wait.
    public static let maxTimeoutSeconds = 600
    /// codesign is local and offline; it gets its own fixed budget instead of the spctl one.
    public static let defaultCodesignTimeoutSeconds = 30

    public let codesignPath: String
    public let spctlPath: String
    public let spctlTimeoutSeconds: Int
    public let codesignTimeoutSeconds: Int

    public init(expectedTeamID: String,
                codesignPath: String = "/usr/bin/codesign",
                spctlPath: String = "/usr/sbin/spctl",
                spctlTimeoutSeconds: Int = SystemSignatureVerifier.timeoutSeconds(from: ProcessInfo.processInfo.environment),
                codesignTimeoutSeconds: Int = SystemSignatureVerifier.defaultCodesignTimeoutSeconds) {
        self.expectedTeamID = expectedTeamID
        self.codesignPath = codesignPath
        self.spctlPath = spctlPath
        self.spctlTimeoutSeconds = spctlTimeoutSeconds
        self.codesignTimeoutSeconds = codesignTimeoutSeconds
    }

    /// `SPCTL_TIMEOUT_SECONDS` as a positive integer (capped at `maxTimeoutSeconds`), else the default.
    /// Anything else would disable or distort the timeout, so it is ignored rather than honoured.
    public static func timeoutSeconds(from environment: [String: String]) -> Int {
        guard let raw = environment["SPCTL_TIMEOUT_SECONDS"],
              !raw.isEmpty, raw.allSatisfy({ ("0"..."9").contains($0) }),
              let value = Int(raw), value > 0 else {
            return defaultTimeoutSeconds
        }
        return min(value, maxTimeoutSeconds)
    }

    public func verify(binaryAt path: String) throws {
        // `-R` reads a requirement FILE unless the argument starts with `=` (literal requirement text).
        // Without the prefix codesign exits 1 for every input — which would refuse genuine releases too.
        let identity = try Self.execute(codesignPath,
                                        ["--verify", "--strict", "-R", "=" + designatedRequirement, path],
                                        timeoutSeconds: codesignTimeoutSeconds)
        switch identity {
        case .timedOut:
            throw SelfUpdate.SelfUpdateError.verificationTimedOut(tool: "codesign", seconds: codesignTimeoutSeconds)
        case .exited(0, _):
            break
        case .exited:
            throw SelfUpdate.SelfUpdateError.signatureInvalid(identity.summary, teamID: expectedTeamID)
        }

        let notarization = try Self.execute(spctlPath, ["-a", "-vvv", "-t", "install", path],
                                            timeoutSeconds: spctlTimeoutSeconds)
        switch notarization {
        case .timedOut:
            throw SelfUpdate.SelfUpdateError.verificationTimedOut(tool: "spctl", seconds: spctlTimeoutSeconds)
        case .exited(let status, let output):
            let lines = output.split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard status == 0, lines.contains(Self.notarizedSourceLine) else {
                throw SelfUpdate.SelfUpdateError.notNotarized(notarization.summary)
            }
        }
    }

    // MARK: - process runner

    enum Outcome {
        case exited(Int32, String)
        case timedOut

        var summary: String {
            switch self {
            case .timedOut: return "timed out"
            case .exited(let status, let output):
                let text = output.trimmingCharacters(in: .whitespacesAndNewlines)
                return "exit \(status)" + (text.isEmpty ? "" : ": \(text.prefix(500))")
            }
        }
    }

    /// Runs `tool` with `arguments` (no shell), stdout and stderr merged. On timeout the child is
    /// terminated and its output is not read (a lingering grandchild could hold the pipe open).
    static func execute(_ tool: String, _ arguments: [String], timeoutSeconds: Int) throws -> Outcome {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        process.standardInput = FileHandle.nullDevice

        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do {
            try process.run()
        } catch {
            throw SelfUpdate.SelfUpdateError.installFailed(
                "could not run \(tool): \(error.localizedDescription)")
        }

        // Drain the pipe concurrently so a chatty child cannot block on a full buffer.
        let collected = OutputBox()
        let readDone = DispatchSemaphore(value: 0)
        DispatchQueue(label: "SystemSignatureVerifier.reader").async {
            collected.set(pipe.fileHandleForReading.readDataToEndOfFile())
            readDone.signal()
        }

        if done.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
            process.terminate()
            if done.wait(timeout: .now() + .seconds(2)) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + .seconds(2))   // let the runtime reap it
            }
            return .timedOut
        }
        // A child that exited normally closes the pipe; if something still holds it, report no output
        // rather than wait forever (the exit status alone still decides).
        let output = readDone.wait(timeout: .now() + .seconds(5)) == .success
            ? String(decoding: collected.get(), as: UTF8.self) : ""
        return .exited(process.terminationStatus, output)
    }

    private final class OutputBox: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        func set(_ value: Data) { lock.lock(); data = value; lock.unlock() }
        func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
    }
}
