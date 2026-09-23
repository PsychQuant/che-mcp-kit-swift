import Foundation

/// Single exit path for the process.
///
/// Termination can start on several threads at once: a signal handler (SIGTERM / SIGINT / SIGHUP,
/// possibly more than one), the main thread when the stdio server returns on stdin EOF, and the
/// `--cli` path when a call finishes or fails. `exit` is not safe to enter twice — the second call
/// ended the process while the first was still running `atexit` cleanup. The first caller
/// here exits; every later caller parks forever, so exactly one thread ever runs `exit`.
public enum Shutdown {
    private static let gate = ExitGate()

    /// True once termination has begun on any thread.
    public static var inProgress: Bool { gate.isClaimed }

    private static let installLock = NSLock()
    nonisolated(unsafe) private static var signalSources: [DispatchSourceSignal] = []

    /// Turns SIGTERM / SIGINT / SIGHUP into `terminate(policy.status(for:))`. Call it from the executable's `main.swift`
    /// as early as possible, so a signal during start-up is not handled by the default action
    /// (exit 128+signo, bypassing cleanup and the server's exit-0 contract). Idempotent.
    public static func installSignalHandlers(policy: SignalExitPolicy) {
        installLock.lock(); defer { installLock.unlock() }
        guard signalSources.isEmpty else { return }
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
            source.setEventHandler { terminate(policy.status(for: sig)) }
            source.resume()
            signalSources.append(source)
        }
    }

    public static func terminate(_ status: Int32) -> Never {
        if gate.claim() { exit(status) }
        while true { pause() }   // the winning thread is exiting; never return into a second exit
    }
}

/// A one-shot latch: `claim()` returns true exactly once across all threads.
public final class ExitGate: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    /// True once any caller has claimed the gate.
    public var isClaimed: Bool { lock.lock(); defer { lock.unlock() }; return claimed }

    public init() {}

    public func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}

/// Exit status for a signal-triggered shutdown.
public enum SignalExitPolicy {
    /// stdio MCP server: the client stopped it on purpose.
    case server
    /// one-shot `--cli` call: report the interruption the way shells expect (128 + signal number).
    case cli

    public func status(for signal: Int32) -> Int32 {
        switch self {
        case .server: return 0
        case .cli: return 128 + signal
        }
    }
}
