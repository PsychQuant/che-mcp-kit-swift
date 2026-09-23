import Foundation

// MARK: - Response Formatting Utilities

/// Thrown by `formatJSON` when a handler builds a payload that cannot be serialized.
/// Both cases are developer bugs; the descriptions are author-controlled literals.
public enum ResponseFormattingError: LocalizedError, TrustedErrorMessage, CodedError, Equatable {
    case nonSerializableValue
    case invalidUTF8

    public var code: String { "invalid_argument" }

    public var errorDescription: String? {
        switch self {
        case .nonSerializableValue:
            return "Invalid parameter: response payload contains non-JSON-serializable value (developer bug)"
        case .invalidUTF8:
            return "Invalid parameter: response payload contained invalid UTF-8 (developer bug)"
        }
    }
}

/// Serialize a tool response payload to JSON.
///
/// Throws on any internal failure (unsupported type, non-finite number,
/// UTF-8 conversion failure) instead of returning a placeholder that would
/// be indistinguishable from a legitimate empty result. The server's tool-call
/// catch-all converts thrown errors into MCP `isError: true` responses.
///
/// Note: `JSONSerialization.data(withJSONObject:)` raises an Objective-C
/// `NSInvalidArgumentException` on unsupported types (raw `Date`, NaN,
/// Infinity, non-string dict keys, etc.) — an ObjC exception which Swift's
/// `try/catch` cannot capture, crashing the process. We pre-check with
/// `isValidJSONObject(_:)` to convert that into a catchable Swift error.
public func formatJSON(_ value: Any) throws -> String {
    guard JSONSerialization.isValidJSONObject(value) else {
        throw ResponseFormattingError.nonSerializableValue
    }
    let data = try JSONSerialization.data(
        withJSONObject: value,
        options: [.prettyPrinted, .sortedKeys]
    )
    guard let string = String(data: data, encoding: .utf8) else {
        throw ResponseFormattingError.invalidUTF8
    }
    return string
}

/// Wrap a mutation result in a JSON envelope for consistent `--cli` output.
public func actionResult(_ fields: [String: Any]) throws -> String {
    return try formatJSON(fields)
}
