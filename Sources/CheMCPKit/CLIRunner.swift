import Foundation
import MCP

/// Runs one tool call for `--cli`. A server conforms with the same method its MCP
/// `CallTool` handler uses, so both paths share validation and output.
public protocol CLIToolExecutor {
    func executeToolCall(name: String, arguments: [String: Value]) async throws -> String
}

/// Handles --cli mode: parse CLI args or stdin JSON, dispatch to tool handler, print result.
public enum CLIRunner {

    public enum CLIError: LocalizedError, TrustedErrorMessage, CodedError, Equatable {
        /// Every CLI usage error is a caller mistake, never an internal failure.
        public var code: String { "invalid_argument" }

        /// `usageName` is the executable name shown in the usage line.
        case missingToolName(usageName: String)
        case danglingKey(String)
        case missingToolField
        case unexpectedPositional
        /// JSON parse failure detail. **MUST be an author-controlled literal**
        /// — do NOT interpolate framework error text (`error.localizedDescription`).
        /// Violating this routes the raw text through the `TrustedErrorMessage`
        /// carve-out unescaped (che-ical-mcp#41), which would re-open the CWE-117 window
        /// that che-ical-mcp#80 closed for the framework-error path. Today's call sites
        /// pass only static literals; future contributors please grep
        /// `CLIRunner.CLIError.invalidJSON\b` before adding a new caller (che-ical-mcp#85).
        case invalidJSON(String)

        public var errorDescription: String? {
            switch self {
            case .missingToolName(let usageName):
                return "Missing tool name. Usage: \(usageName) --cli <tool_name> [--key value ...]"
            case .danglingKey(let key):
                return "Argument '--\(key)' has no value. All arguments require a value."
            case .missingToolField:
                return "JSON input must contain a 'tool' field. Expected: {\"tool\":\"...\",\"arguments\":{...}}"
            case .unexpectedPositional:
                return "Unexpected positional argument. Use --key value pairs, or pass one JSON object: --cli <tool> '{\"key\": value}'"
            case .invalidJSON(let detail):
                return "Invalid JSON input: \(detail)"
            }
        }
    }

    // MARK: - Flag-based arg parsing

    /// Parse `--cli tool_name --key1 value1 --key2 value2` into (toolName, arguments).
    /// Returns string-keyed dictionary; values are always strings (handlers use .stringValue).
    public static func parseArgs(_ args: [String], usageName: String) throws -> (tool: String, arguments: [String: String]) {
        // Find --cli index, tool name is the next arg
        guard let cliIndex = args.firstIndex(of: "--cli"),
              cliIndex + 1 < args.count
        else {
            throw CLIError.missingToolName(usageName: usageName)
        }

        let toolName = args[cliIndex + 1]

        // Remaining args after tool name are --key value pairs. A positional argument is
        // an error: silently skipping one hid `--cli <tool> '{"limit": 3}'`
        // running with the default limit; the JSON form is handled
        // by `parsePositionalJSON` before this parser is reached.
        var arguments: [String: String] = [:]
        var i = cliIndex + 2
        while i < args.count {
            let arg = args[i]
            guard arg.hasPrefix("--") else {
                throw CLIError.unexpectedPositional
            }
            let key = String(arg.dropFirst(2))
            guard i + 1 < args.count else {
                throw CLIError.danglingKey(key)
            }
            arguments[key] = args[i + 1]
            i += 2
        }

        return (toolName, arguments)
    }

    /// `--cli <tool> '{"key": value, ...}'` — a single JSON object as the only argument after
    /// the tool name. Returns `nil` when that shape is not present.
    public static func parsePositionalJSON(_ args: [String]) throws -> (tool: String, arguments: [String: Value])? {
        guard let cliIndex = args.firstIndex(of: "--cli"), cliIndex + 2 < args.count else { return nil }
        let candidate = args[cliIndex + 2].trimmingCharacters(in: .whitespacesAndNewlines)
        guard candidate.hasPrefix("{") else { return nil }
        guard cliIndex + 3 == args.count else {
            throw CLIError.invalidJSON("a JSON argument object must be the only argument after the tool name")
        }
        guard let data = candidate.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw CLIError.invalidJSON("could not parse the positional argument as a JSON object")
        }
        var arguments: [String: Value] = [:]
        for (key, value) in object {
            arguments[key] = jsonToValue(value)
        }
        return (args[cliIndex + 1], arguments)
    }

    // MARK: - JSON stdin parsing

    /// Parse `{"tool":"...","arguments":{...}}` JSON string into (toolName, arguments).
    public static func parseJSONInput(_ input: String) throws -> (tool: String, arguments: [String: String]) {
        guard let data = input.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw CLIError.invalidJSON("could not parse as JSON object")
        }

        guard let toolName = json["tool"] as? String else {
            throw CLIError.missingToolField
        }

        var arguments: [String: String] = [:]
        if let args = json["arguments"] as? [String: Any] {
            for (key, value) in args {
                // Convert all values to strings for consistency with CLI arg parsing
                if let str = value as? String {
                    arguments[key] = str
                } else if let num = value as? NSNumber {
                    // Distinguish bool from number
                    if CFGetTypeID(num) == CFBooleanGetTypeID() {
                        arguments[key] = num.boolValue ? "true" : "false"
                    } else {
                        arguments[key] = "\(num)"
                    }
                } else if value is NSNull {
                    // Skip null values
                } else {
                    // Arrays, objects → serialize back to JSON string
                    if let jsonData = try? JSONSerialization.data(withJSONObject: value),
                       let jsonStr = String(data: jsonData, encoding: .utf8)
                    {
                        arguments[key] = jsonStr
                    }
                }
            }
        }

        return (toolName, arguments)
    }

    // MARK: - Convert to MCP Value

    /// Convert string values to MCP Value with smart type inference.
    /// Handlers use strict .boolValue/.intValue/.doubleValue, so we must
    /// produce the correct Value variant — not just .string for everything.
    public static func inferValue(_ str: String) -> Value {
        // Boolean
        if str == "true" { return .bool(true) }
        if str == "false" { return .bool(false) }
        // Integer
        if let intVal = Int(str) { return .int(intVal) }
        // Double (only if contains dot to avoid int→double)
        if str.contains("."), let dblVal = Double(str) { return .double(dblVal) }
        // JSON array or object (starts with [ or {)
        if (str.hasPrefix("[") || str.hasPrefix("{")),
           let data = str.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: data)
        {
            return jsonToValue(parsed)
        }
        // Default: string
        return .string(str)
    }

    /// Convert string dictionary to MCP Value dictionary for flag-based args.
    /// Flag values for `tool`: parameters its input schema in `tools` declares as `"type": "string"`
    /// are kept verbatim; the rest go through `inferValue` so integers and booleans still get their
    /// `Value` variant. Without this, `--query 007` reached the handler as `"7"`. Unknown tools fall
    /// back to inference for every key.
    public static func toMCPArguments(_ args: [String: String], tool: String, tools: [Tool]) -> [String: Value] {
        let stringKeys = stringTypedParameters(for: tool, in: tools)
        var result: [String: Value] = [:]
        for (key, value) in args {
            result[key] = stringKeys.contains(key) ? .string(value) : inferValue(value)
        }
        return result
    }

    /// Names of the properties `tool` declares with `"type": "string"`, read from `tools` — pass the
    /// same list the MCP path advertises so both paths agree.
    public static func stringTypedParameters(for tool: String, in tools: [Tool]) -> Set<String> {
        guard let definition = tools.first(where: { $0.name == tool }),
              case .object(let schema) = definition.inputSchema,
              case .object(let properties)? = schema["properties"] else { return [] }
        return Set(properties.compactMap { name, spec in
            if case .object(let fields) = spec, fields["type"] == .string("string") { return name }
            return nil
        })
    }

    /// Convert raw JSON (from stdin) directly to MCP Value, preserving native types.
    public static func jsonToValue(_ obj: Any) -> Value {
        switch obj {
        case let str as String:
            return .string(str)
        case let num as NSNumber:
            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                return .bool(num.boolValue)
            }
            if num.doubleValue == Double(num.intValue) && !"\(num)".contains(".") {
                return .int(num.intValue)
            }
            return .double(num.doubleValue)
        case let arr as [Any]:
            return .array(arr.map { jsonToValue($0) })
        case let dict as [String: Any]:
            return .object(dict.mapValues { jsonToValue($0) })
        case is NSNull:
            return .null   // "omitted" everywhere; "" would be a rejected string for boolean arguments (che-ical-mcp#205)
        default:
            return .string("\(obj)")
        }
    }

    /// Parse raw JSON stdin directly into MCP Value arguments (preserving types).
    public static func parseJSONInputToValues(_ input: String) throws -> (tool: String, arguments: [String: Value]) {
        guard let data = input.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw CLIError.invalidJSON("could not parse as JSON object")
        }

        guard let toolName = json["tool"] as? String else {
            throw CLIError.missingToolField
        }

        var arguments: [String: Value] = [:]
        if let args = json["arguments"] as? [String: Any] {
            for (key, value) in args {
                arguments[key] = jsonToValue(value)
            }
        }

        return (toolName, arguments)
    }

    // MARK: - Run

    /// Check if argv has a tool name after --cli (i.e., flag-based mode).
    private static func hasToolNameInArgs(_ args: [String]) -> Bool {
        guard let cliIndex = args.firstIndex(of: "--cli"),
              cliIndex + 1 < args.count
        else { return false }
        // Tool name should not start with -- (that would be another flag)
        return !args[cliIndex + 1].hasPrefix("--")
    }

    /// Formats a failed `--cli` call as the single stdout line. The default is the shared
    /// `{ "error": { "code", "message" } }` envelope (`formatErrorForCLI`).
    public typealias ErrorFormatter = (Error) -> String

    public static let defaultErrorFormatter: ErrorFormatter = { formatErrorForCLI($0).jsonMessage }

    /// Run CLI mode: detect input source, parse, dispatch, print result. `tools` is the list the
    /// MCP path advertises; `usageName` is the executable name shown in usage errors. A failure
    /// prints `errorFormatter`'s line (a server with an established output format passes its
    /// own) and terminates through `Shutdown.terminate(1)`.
    public static func run(executor: some CLIToolExecutor, tools: [Tool], usageName: String, args: [String],
                           errorFormatter: ErrorFormatter = defaultErrorFormatter) async {
        // Hoisted so the catch block can pass it as the writeFailureLog identifier.
        // `nil` covers the case where parsing throws before tool name is known
        // (e.g. CLIError.missingToolName); falls back to "<no-tool>" in handleRunError.
        var toolName: String? = nil
        do {
            let mcpArgs: [String: Value]

            // Priority: if argv has a tool name, always use flag parsing.
            // This avoids isatty issues in non-interactive environments (launchd, CI)
            // where stdin may be a pipe but no JSON is being sent.
            if let positional = try parsePositionalJSON(args) {
                toolName = positional.tool
                mcpArgs = positional.arguments
            } else if hasToolNameInArgs(args) {
                let (tool, strArgs) = try parseArgs(args, usageName: usageName)
                toolName = tool
                mcpArgs = toMCPArguments(strArgs, tool: tool, tools: tools)
            } else if isatty(fileno(stdin)) == 0 {
                // No tool name in argv — try reading JSON from stdin
                let inputData = FileHandle.standardInput.readDataToEndOfFile()
                guard let input = String(data: inputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !input.isEmpty
                else {
                    throw CLIError.missingToolName(usageName: usageName)
                }
                let (tool, parsedArgs) = try parseJSONInputToValues(input)
                toolName = tool
                mcpArgs = parsedArgs
            } else {
                throw CLIError.missingToolName(usageName: usageName)
            }

            // Statically unreachable: every branch above either assigns toolName
            // or throws. The guard keeps the unwrap type-safe.
            guard let unwrappedToolName = toolName else {
                throw CLIError.missingToolName(usageName: usageName)
            }
            let result = try await executor.executeToolCall(name: unwrappedToolName, arguments: mcpArgs)
            print(result)
        } catch {
            handleRunError(error, toolName: toolName, formatter: errorFormatter)
            Shutdown.terminate(1)   // same single exit path as signals
        }
    }

    /// Internal-for-test helper extracted from `run()`'s catch (che-ical-mcp#80).
    /// Writes the sanitized JSON to stdout and (if `error` is not a
    /// `TrustedErrorMessage`) the raw log to stderr via `writeFailureLog`,
    /// inheriting the trusted-branch carve-out (che-ical-mcp#41) and `escapeForStderr`
    /// (che-ical-mcp#37 F2) that the MCP path already enforces (che-ical-mcp spec R3/R7/R8).
    /// Does NOT call `exit()`; the caller is responsible for that so this
    /// helper stays unit-testable without subprocess invocation.
    /// Returns the line it printed.
    @discardableResult
    public static func handleRunError(_ error: Error, toolName: String?,
                                      formatter: ErrorFormatter = defaultErrorFormatter) -> String {
        let jsonMessage = formatter(error)
        print(jsonMessage)
        _ = ErrorSanitizer.writeFailureLog(
            handler: "CLIRunner",
            identifier: toolName ?? "<no-tool>",
            error: error
        )
        return jsonMessage
    }

    /// che-ical-mcp#37 verify (Codex medium finding): route CLI errors through the same
    /// sanitizer as the MCP wire path so a framework-thrown NSError doesn't echo
    /// `localizedDescription` (potentially containing titles or paths) to stdout for CLI users and automation pipelines.
    /// Returns `(jsonMessage, rawLog)` — the JSON goes to stdout (sanitized),
    /// the raw log goes to stderr (operator debug).
    public static func formatErrorForCLI(_ error: Error) -> (jsonMessage: String, rawLog: String) {
        let sanitized = ErrorSanitizer.sanitizeForResponse(error)
        let envelope = ErrorEnvelope.make(for: error, sanitizedCode: sanitized.code)
        if let data = try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]),
           let str = String(data: data, encoding: .utf8)
        {
            return (str, sanitized.rawLog)
        }
        let escaped = sanitized.code
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return ("{\"error\":{\"code\":\"internal_error\",\"message\":\"\(escaped)\"}}", sanitized.rawLog)
    }
}
