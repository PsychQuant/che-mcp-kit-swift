import Foundation

/// An error that carries a stable machine-readable code for the wire envelope
/// `{ "error": { "code", "message" } }`.
public protocol CodedError: Error {
    var code: String { get }
}

/// The one error shape both the MCP wire (`isError` text) and `--cli` stdout use:
/// `{ "error": { "code": String, "message": String } }`. `code` comes from `CodedError`
/// conformers; every other error is reported under the sanitizer's stable code.
public enum ErrorEnvelope {
    public static func make(for error: Error, sanitizedCode: String) -> [String: Any] {
        let code: String
        let message: String
        if let coded = error as? CodedError {
            code = coded.code
            message = ErrorSanitizer.sanitizeForInterpolation(error.localizedDescription)
        } else if error is TrustedErrorMessage {
            code = "internal_error"
            message = ErrorSanitizer.sanitizeForInterpolation(error.localizedDescription)
        } else {
            code = sanitizedCode
            message = sanitizedCode
        }
        return ["error": ["code": code, "message": message] as [String: Any]]
    }
}
