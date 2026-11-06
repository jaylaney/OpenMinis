// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RemoteExecutionCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "RemoteExecutionCore", targets: ["RemoteExecutionCore"]),
               .library(name: "RemotePrototypeWire", targets: ["RemotePrototypeWire"]),
               .library(name: "RemotePrototypeTransport", targets: ["RemotePrototypeTransport"]),
               .library(name: "RemotePrototypeCertificates", targets: ["RemotePrototypeCertificates"]),
               .library(name: "RemotePrototypeHost", targets: ["RemotePrototypeHost"]),
               .library(name: "RemoteHostPrototypeModel", targets: ["RemoteHostPrototypeModel"]),
               .library(name: "RemoteControllerProbeModel", targets: ["RemoteControllerProbeModel"])],
    dependencies: [.package(url: "https://github.com/apple/swift-certificates.git", exact: "1.17.0")],
    targets: [
        .systemLibrary(name: "CSQLite"),
        .target(name: "RemoteHostPrototypeModel", dependencies: ["RemotePrototypeHost"]),
        .testTarget(name: "RemoteHostPrototypeModelTests", dependencies: ["RemoteHostPrototypeModel", "RemotePrototypeHost", "RemoteExecutionCore", "RemotePrototypeWire"]),
        .target(name: "RemoteControllerProbeModel", dependencies: ["RemotePrototypeWire", "RemotePrototypeTransport"]),
        .testTarget(name: "RemoteControllerProbeModelTests", dependencies: ["RemoteControllerProbeModel", "RemotePrototypeWire", "RemotePrototypeTransport"]),
        .target(name: "RemotePrototypeWire"),
        .target(name: "RemotePrototypeHost", dependencies: ["RemoteExecutionCore", "RemotePrototypeTransport", "RemotePrototypeWire", .target(name: "RemotePrototypeCertificates", condition: .when(platforms: [.macOS]))]),
        .testTarget(name: "RemotePrototypeHostTests", dependencies: ["RemotePrototypeHost", "RemoteExecutionCore", "RemotePrototypeTransport", "RemotePrototypeWire", "CSQLite"]),
        .target(name: "RemotePrototypeCertificates", dependencies: [
            .product(name: "X509", package: "swift-certificates", condition: .when(platforms: [.macOS]))
        ]),
        .testTarget(name: "RemotePrototypeCertificatesTests", dependencies: ["RemotePrototypeCertificates"]),
        .target(name: "RemotePrototypeTransport", dependencies: ["RemotePrototypeWire"]),
        .testTarget(name: "RemotePrototypeTransportTests", dependencies: ["RemotePrototypeTransport", "RemotePrototypeWire", .target(name: "RemotePrototypeCertificates", condition: .when(platforms: [.macOS]))]),
        .testTarget(name: "RemotePrototypeWireTests", dependencies: ["RemotePrototypeWire"]),
        .target(name: "RemoteExecutionCore", dependencies: ["CSQLite"]),
        .testTarget(name: "RemoteExecutionCoreTests", dependencies: ["RemoteExecutionCore"]),
        .testTarget(name: "RemoteExecutionCorePublicAPITests", dependencies: ["RemoteExecutionCore"])
    ],
    swiftLanguageModes: [.v6]
)
