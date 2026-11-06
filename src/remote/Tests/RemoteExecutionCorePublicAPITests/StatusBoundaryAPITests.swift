import CryptoKit
import Foundation
import XCTest
import RemoteExecutionCore

@MainActor
final class StatusBoundaryAPITests: XCTestCase {
    // Public clients can enable, inspect and explicitly close the status owner.
    func testPublicAsyncFactoryAndLocalStatus() async throws {
        let leaf = FileManager.default.temporaryDirectory.appendingPathComponent("status-public-\(UUID())")
        defer { try? FileManager.default.removeItem(at: leaf) }
        let key = P256.Signing.PrivateKey().publicKey.derRepresentation
        let configuration = StatusOnlyHostConfiguration(directory: leaf, clock: PublicStatusClock(), random: PublicStatusRandom(),
                                                        identityResolver: { _ in
            XCTAssertFalse(Thread.isMainThread)
            return key
        }, onUnavailable: {})
        let handles: StatusOnlyHostHandles = try await StatusOnlyHost.open(configuration: configuration)
        let local = try await handles.host.localStatus()
        XCTAssertEqual(local.controllerState, .unenrolled)
        XCTAssertEqual(local.snapshot.executionCapability, .unsupported)
        await handles.host.close()
        do { _ = try await handles.host.localStatus(); XCTFail("closed owner must refuse") }
        catch { XCTAssertEqual(error as? StatusHostError, .closed) }
    }

    // Compiler fixtures exercise the exported module rather than inspect source.
    // Exposing a lease constructor, Codable, or host/legacy method on controller
    // turns a required diagnostic into a successful compilation.
    func testControllerAuthorityIsOpaqueAndStatusOnly() throws {
        let valid = """
        import RemoteExecutionCore
        func read(_ handle: StatusControllerHandle, _ lease: StatusControllerLease) async throws -> StatusOnlySnapshot {
            try await handle.status(over: lease)
        }
        """
        let positive = try typecheck(valid)
        XCTAssertEqual(positive.status, 0, positive.diagnostic)
        for source in [
            "import Foundation\nimport RemoteExecutionCore\nlet lease = StatusControllerLease(incarnation: UUID(), connectionToken: UUID(), connectionID: UUID(), storageEpoch: UUID(), controllerGeneration: 1)",
            "import RemoteExecutionCore\nfunc encode<T: Encodable>(_: T.Type) {}\nfunc check() { encode(StatusControllerLease.self) }",
            "import RemoteExecutionCore\nfunc decode<T: Decodable>(_: T.Type) {}\nfunc check() { decode(StatusControllerLease.self) }",
            "import RemoteExecutionCore\nfunc check(_ h: StatusControllerHandle) async { await h.close() }",
            "import RemoteExecutionCore\nfunc check(_ h: StatusControllerHandle) async throws { _ = try await h.localStatus() }",
            "import RemoteExecutionCore\nfunc check(_ h: StatusControllerHandle) async throws { try await h.revokeController() }",
            "import RemoteExecutionCore\nfunc check(_ h: StatusControllerHandle) async throws { _ = try await h.openEnrollment() }",
            "import RemoteExecutionCore\nfunc check(_ h: StatusControllerHandle) async throws { _ = try await h.submit() }"
        ] {
            let result = try typecheck(source)
            XCTAssertNotEqual(result.status, 0, "authority escaped public boundary: \(source)")
            XCTAssertTrue(result.diagnostic.contains("error:"))
        }
    }

    private func typecheck(_ source: String) throws -> (status: Int32, diagnostic: String) {
        let fixture = FileManager.default.temporaryDirectory.appendingPathComponent("status-compile-\(UUID()).swift")
        defer { try? FileManager.default.removeItem(at: fixture) }
        try source.write(to: fixture, atomically: false, encoding: .utf8)
        let sourceRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        // SwiftPM places the xctest bundle next to its Modules directory.
        var build = Bundle(for: StatusBoundaryAPITests.self).bundleURL.deletingLastPathComponent()
        while !FileManager.default.fileExists(atPath: build.appendingPathComponent("RemoteExecutionCore.swiftmodule").path),
              !FileManager.default.fileExists(atPath: build.appendingPathComponent("Modules/RemoteExecutionCore.swiftmodule").path), build.path != "/" {
            build.deleteLastPathComponent()
        }
        let modules = FileManager.default.fileExists(atPath: build.appendingPathComponent("Modules").path) ? build.appendingPathComponent("Modules") : build
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["swiftc", "-typecheck", "-I", modules.path,
                             "-I", sourceRoot.appendingPathComponent("Sources/CSQLite").path, fixture.path]
        let output = Pipe()
        process.standardError = output
        process.standardOutput = output
        try process.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: bytes, as: UTF8.self))
    }
}
private struct PublicStatusClock: StatusClock { func nowNanoseconds() -> UInt64 { 1 } }
private struct PublicStatusRandom: StatusRandomSource { func bytes(count: Int) throws -> Data { Data(repeating: 5, count: count) } }
