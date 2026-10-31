// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RemoteExecutionCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "RemoteExecutionCore", targets: ["RemoteExecutionCore"])],
    targets: [
        .systemLibrary(name: "CSQLite"),
        .target(name: "RemoteExecutionCore", dependencies: ["CSQLite"]),
        .testTarget(name: "RemoteExecutionCoreTests", dependencies: ["RemoteExecutionCore"])
    ],
    swiftLanguageModes: [.v6]
)
