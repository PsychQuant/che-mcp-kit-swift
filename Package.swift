// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CheMCPKit",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "CheMCPKit", targets: ["CheMCPKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", .upToNextMinor(from: "0.12.0"))
    ],
    targets: [
        .target(
            name: "CheMCPKit",
            dependencies: [
                .product(name: "MCP", package: "swift-sdk")
            ]
        ),
        .testTarget(
            name: "CheMCPKitTests",
            dependencies: ["CheMCPKit"]
        )
    ]
)
