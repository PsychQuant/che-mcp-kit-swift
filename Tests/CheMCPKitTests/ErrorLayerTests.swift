import Foundation
import Testing
@testable import CheMCPKit

/// An author-controlled coded error standing in for a server's own error type.
private enum SampleCodedError: Error, LocalizedError, TrustedErrorMessage, CodedError {
    case notFound(id: String)
    var code: String { "item_not_found" }
    var errorDescription: String? {
        switch self {
        case .notFound(let id): return "item_not_found: no item with id \(ErrorSanitizer.sanitizeForInterpolation(id))"
        }
    }
}

private struct TrustedOnlyError: Error, LocalizedError, TrustedErrorMessage {
    var errorDescription: String? { "authored\nmessage" }
}

struct ErrorSanitizerTests {
    @Test func `Control characters are escaped for stderr`() {
        #expect(ErrorSanitizer.escapeForStderr("a\nb\u{1b}[2J\\") == "a\\nb\\x1b[2J\\\\")
    }

    @Test func `C1 controls are hex-escaped for stderr`() {
        #expect(ErrorSanitizer.escapeForStderr("a\u{9b}b\r") == "a\\x9bb\\r")
    }

    @Test func `Control characters are stripped for interpolation`() {
        #expect(ErrorSanitizer.sanitizeForInterpolation("x\u{00}y\u{1f}z\u{7f}") == "xyz")
    }

    @Test func `Trusted errors pass through and framework errors become codes`() {
        let trusted = ErrorSanitizer.sanitizeForResponse(SampleCodedError.notFound(id: "1"))
        #expect(trusted.code == "item_not_found: no item with id 1")
        let framework = ErrorSanitizer.sanitizeForResponse(NSError(domain: "NSCocoaErrorDomain", code: 260))
        #expect(framework.code == "error_nscocoaerrordomain_260")
    }

    @Test func `Swift errors without the trusted marker collapse to error_unknown`() {
        struct Plain: Error {}
        #expect(ErrorSanitizer.sanitize(Plain()).code == "error_unknown")
    }

    @Test func `Negative NSError codes are encoded by magnitude`() {
        #expect(ErrorSanitizer.sanitize(NSError(domain: "NSURLErrorDomain", code: -1009)).code
                == "error_nsurlerrordomain_1009")
    }

    @Test func `The stderr raw-log cap is 1024 characters`() {
        #expect(ErrorSanitizer.maxRawLogChars == 1024)
    }
}

struct ErrorEnvelopeTests {
    private func fields(_ env: [String: Any]) -> (code: String?, message: String?) {
        let inner = env["error"] as? [String: Any]
        return (inner?["code"] as? String, inner?["message"] as? String)
    }

    @Test func `A coded error supplies the code and its sanitized description`() {
        let f = fields(ErrorEnvelope.make(for: SampleCodedError.notFound(id: "a\nb"), sanitizedCode: "ignored"))
        #expect(f.code == "item_not_found")
        #expect(f.message == "item_not_found: no item with id ab")
    }

    @Test func `A trusted error without a code is internal_error with a control-free message`() {
        let f = fields(ErrorEnvelope.make(for: TrustedOnlyError(), sanitizedCode: "ignored"))
        #expect(f.code == "internal_error")
        #expect(f.message == "authoredmessage")
    }

    @Test func `A framework error reports only the sanitized code`() {
        let f = fields(ErrorEnvelope.make(for: NSError(domain: "NSCocoaErrorDomain", code: 260),
                                          sanitizedCode: "error_nscocoaerrordomain_260"))
        #expect(f.code == "error_nscocoaerrordomain_260")
        #expect(f.message == "error_nscocoaerrordomain_260")
    }
}

struct ResponseFormattingTests {
    @Test func `Payloads serialize with sorted keys`() throws {
        #expect(try formatJSON(["b": 1, "a": "x"]) == "{\n  \"a\" : \"x\",\n  \"b\" : 1\n}")
    }

    @Test func `A non-serializable payload throws a coded error instead of crashing`() {
        #expect(throws: ResponseFormattingError.nonSerializableValue) { try formatJSON(["x": Double.nan]) }
        let error = ResponseFormattingError.nonSerializableValue
        #expect(error.code == "invalid_argument")
        // Same text the servers emitted before the extraction (their `ToolError.invalidParameter`).
        #expect(error.localizedDescription
                == "Invalid parameter: response payload contains non-JSON-serializable value (developer bug)")
    }
}
struct TrustedErrorMessageConformerTests {
    /// Pins the canonical conformer list documented in ErrorSanitizer.swift.
    @Test func `Every documented conformer conforms and undocumented types do not`() {
        #expect(CLIRunner.CLIError.missingToolName(usageName: "X") is TrustedErrorMessage)
        #expect(CLIRunner.CLIError.missingToolName(usageName: "X") is CodedError)
        #expect(ResponseFormattingError.invalidUTF8 is TrustedErrorMessage)
        #expect(ResponseFormattingError.invalidUTF8 is CodedError)
        #expect(!(NSError(domain: "x", code: 1) is TrustedErrorMessage))
        #expect(!(BinaryPathResolverError.unresolvable is TrustedErrorMessage))
    }
}

