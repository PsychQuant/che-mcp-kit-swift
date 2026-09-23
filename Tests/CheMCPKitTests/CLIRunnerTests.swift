import Foundation
import MCP
import Testing
@testable import CheMCPKit

/// A two-tool schema standing in for a server's `defineTools()`.
enum SampleTools {
    static let all: [Tool] = [
        Tool(name: "search", description: "search",
             inputSchema: .object([
                "type": .string("object"),
                "properties": .object([
                    "query": .object(["type": .string("string")]),
                    "folder": .object(["type": .string("string")]),
                    "limit": .object(["type": .string("integer")]),
                    "include_deleted": .object(["type": .string("boolean")]),
                ]),
             ])),
        Tool(name: "read", description: "read",
             inputSchema: .object([
                "type": .string("object"),
                "properties": .object([
                    "id": .object(["type": .string("string")]),
                    "include_audio_info": .object(["type": .string("boolean")]),
                ]),
             ])),
    ]
}

/// Flag values bound for string-typed schema properties must reach the handler verbatim.
struct CLIArgumentTypingTests {
    @Test func `String-typed parameters keep numeric-looking values verbatim`() throws {
        let (tool, raw) = try CLIRunner.parseArgs(["Server", "--cli", "search", "--query", "007",
                                                  "--folder", "1.50", "--limit", "3"], usageName: "Server")
        let args = CLIRunner.toMCPArguments(raw, tool: tool, tools: SampleTools.all)
        #expect(args["query"] == .string("007"))
        #expect(args["folder"] == .string("1.50"))
        #expect(args["limit"] == .int(3))
    }

    @Test func `Booleans and integers are still inferred`() {
        let args = CLIRunner.toMCPArguments(["include_audio_info": "true", "id": "42"], tool: "read", tools: SampleTools.all)
        #expect(args["include_audio_info"] == .bool(true))
        #expect(args["id"] == .string("42"))
    }

    @Test func `Every string property of a tool is recognised`() {
        #expect(CLIRunner.stringTypedParameters(for: "search", in: SampleTools.all) == ["query", "folder"])
        #expect(CLIRunner.stringTypedParameters(for: "read", in: SampleTools.all) == ["id"])
    }

    @Test func `Unknown tools fall back to inference`() {
        #expect(CLIRunner.toMCPArguments(["x": "007"], tool: "no_such_tool", tools: SampleTools.all)["x"] == .int(7))
        #expect(CLIRunner.inferValue("1.5") == .double(1.5))
        #expect(CLIRunner.inferValue("[1,2]") == .array([.int(1), .int(2)]))
        #expect(CLIRunner.inferValue("abc") == .string("abc"))
    }
}

struct CLIRunnerParsingTests {
    @Test func `Flag arguments parse into a tool name and string values`() throws {
        let (tool, args) = try CLIRunner.parseArgs(["Server", "--cli", "search", "--limit", "3", "--query", "lab"], usageName: "Server")
        #expect(tool == "search")
        #expect(args == ["limit": "3", "query": "lab"])
    }

    @Test func `Positional JSON object after the tool name is honored, stray positionals are rejected`() throws {
        let positional = try #require(try CLIRunner.parsePositionalJSON(["Server", "--cli", "search", "{\"limit\": 2}"]))
        #expect(positional.tool == "search")
        #expect(positional.arguments["limit"] == .int(2))
        #expect(throws: CLIRunner.CLIError.unexpectedPositional) {
            try CLIRunner.parseArgs(["Server", "--cli", "read", "someid"], usageName: "Server")
        }
        #expect(throws: CLIRunner.CLIError.danglingKey("id")) {
            try CLIRunner.parseArgs(["Server", "--cli", "read", "--id"], usageName: "Server")
        }
        #expect(try CLIRunner.parsePositionalJSON(["Server", "--cli", "list"]) == nil)
    }

    @Test func `A missing tool name reports the usage line for the given executable`() {
        #expect(throws: CLIRunner.CLIError.missingToolName(usageName: "CheICalMCP")) {
            try CLIRunner.parseArgs(["CheICalMCP", "--cli"], usageName: "CheICalMCP")
        }
        // The text che-ical-mcp hard-coded before this package existed.
        #expect(CLIRunner.CLIError.missingToolName(usageName: "CheICalMCP").localizedDescription
                == "Missing tool name. Usage: CheICalMCP --cli <tool_name> [--key value ...]")
    }

    @Test func `JSON stdin form parses tool and typed arguments`() throws {
        let (tool, args) = try CLIRunner.parseJSONInputToValues(#"{"tool":"read","arguments":{"id":"1","include_audio_info":true,"x":null}}"#)
        #expect(tool == "read")
        #expect(args["include_audio_info"] == .bool(true))
        #expect(args["id"] == .string("1"))
        #expect(args["x"] == .null)
        #expect(throws: CLIRunner.CLIError.missingToolField) { try CLIRunner.parseJSONInputToValues(#"{"arguments":{}}"#) }
    }

    @Test func `CLI usage errors carry the invalid_argument code in the envelope`() {
        #expect(CLIRunner.CLIError.unexpectedPositional.code == "invalid_argument")
        let (envelope, _) = CLIRunner.formatErrorForCLI(CLIRunner.CLIError.missingToolName(usageName: "Server"))
        #expect(envelope == #"{"error":{"code":"invalid_argument","message":"Missing tool name. Usage: Server --cli <tool_name> [--key value ...]"}}"#)
    }

    @Test func `A framework error in the CLI envelope reports only the sanitized code`() {
        let (envelope, raw) = CLIRunner.formatErrorForCLI(NSError(domain: "NSCocoaErrorDomain", code: 260,
                                                                  userInfo: [NSLocalizedDescriptionKey: "secret title"]))
        #expect(envelope == #"{"error":{"code":"error_nscocoaerrordomain_260","message":"error_nscocoaerrordomain_260"}}"#)
        #expect(raw == "secret title")
    }
}
