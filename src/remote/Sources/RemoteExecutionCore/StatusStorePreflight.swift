import CryptoKit
import Darwin
import Foundation

/// Snapshot taken under the caller's retained JournalDirectoryLock. Finder metadata
/// is deliberately absent: only its type, ownership and link count are authoritative.
struct StatusStoreProbe {
    let directory: URL
    let isFresh: Bool
    fileprivate let directoryIdentity: StatusFileIdentity
    fileprivate let inventory: [String: StatusFileSnapshot]
}

fileprivate struct StatusFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
    let mode: mode_t
    let owner: uid_t
    let group: gid_t
    let links: nlink_t
    let size: off_t

    init(_ info: stat) {
        device = info.st_dev
        inode = info.st_ino
        mode = info.st_mode
        owner = info.st_uid
        group = info.st_gid
        links = info.st_nlink
        size = info.st_size
    }
}

fileprivate struct StatusFileSnapshot: Equatable {
    let identity: StatusFileIdentity
    let digest: Data
}

/// No SQLite connection, recovery or permission repair occurs in this preflight.
/// The host must prepare the private leaf, acquire its stable lock, and retain that
/// ownership throughout inspection, read-only validation and recheck.
enum StatusStorePreflight {
    private static let mainName = "admission.sqlite3"
    private static let lockName = "admission.lock"
    private static let metadataName = ".DS_Store"
    private static let applicationID: UInt32 = 0x4f4d5354

    static func inspectOwned(directory: URL) throws -> StatusStoreProbe {
        let directoryInfo = try inspectDirectory(directory)
        // Recheck privacy/ACL and known artifacts after lock acquisition. The
        // existing leaf check above prevents absent state from being recreated.
        _ = try JournalStateDirectory.prepare(directory)
        let names = try checkedInventory(directory)
        guard names.contains(lockName) else { throw refusal("Status inspection requires the stable ownership lock") }
        var files: [String: StatusFileSnapshot] = [:]
        var fresh = true
        for name in names where name != metadataName {
            let url = directory.appendingPathComponent(name)
            let descriptor = try openArtifact(url)
            defer { close(descriptor) }
            let before = try identity(descriptor)
            if name == mainName, before.size != 0 {
                try validateHeader(try readHeader(descriptor))
                fresh = false
            }
            var hasher = SHA256()
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw failure("Cannot read status artifact", code: errno)
                }
                if count == 0 { break }
                hasher.update(data: Data(buffer.prefix(count)))
            }
            guard try identity(descriptor) == before,
                  try pathIdentity(url) == before else {
                throw refusal("Status artifact changed during inspection")
            }
            files[name] = StatusFileSnapshot(identity: before, digest: Data(hasher.finalize()))
        }
        // Detect companions appearing while bytes were being hashed; metadata is
        // revalidated but its appearance, disappearance and contents are immaterial.
        guard try checkedInventory(directory).subtracting([metadataName]) == names.subtracting([metadataName]),
              try inspectDirectory(directory) == directoryInfo else {
            throw refusal("Status directory changed during inspection")
        }
        return StatusStoreProbe(directory: directory, isFresh: fresh,
                                directoryIdentity: directoryInfo, inventory: files)
    }

    static func recheck(_ probe: StatusStoreProbe) throws {
        let current = try inspectOwned(directory: probe.directory)
        guard current.directoryIdentity == probe.directoryIdentity,
              current.isFresh == probe.isFresh, current.inventory == probe.inventory else {
            throw refusal("Status store changed after read-only validation")
        }
    }

    /// Called by legacy only after acquiring the same stable lock, before any
    /// writable SQLite open. Reserve OMST even when its version/format is unsupported.
    static func refuseStatusNamespaceForLegacy(directory: URL) throws {
        let url = directory.appendingPathComponent(mainName)
        var info = stat()
        if lstat(url.path, &info) != 0 {
            let code = errno
            if code == ENOENT { return }
            throw failure("Cannot inspect legacy journal header", code: code)
        }
        let descriptor = try openArtifact(url)
        defer { close(descriptor) }
        let header = try readHeader(descriptor)
        if header.count >= 72, bigEndianUInt32(header, at: 68) == applicationID {
            throw refusal("Status-only OMST namespace cannot be opened by the legacy journal")
        }
    }

    private static func checkedInventory(_ directory: URL) throws -> Set<String> {
        let names = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
        for name in names {
            guard name == lockName || name == mainName || name == metadataName else {
                throw refusal("Status store contains an unsupported entry")
            }
            // lstat only: never open Finder metadata or traverse any referenced path.
            var info = stat()
            guard lstat(directory.appendingPathComponent(name).path, &info) == 0 else {
                if name == metadataName, errno == ENOENT { continue }
                throw failure("Cannot inspect status entry", code: errno)
            }
            try JournalStateDirectory.validateArtifact(info)
        }
        return names
    }

    private static func inspectDirectory(_ directory: URL) throws -> StatusFileIdentity {
        var info = stat()
        guard lstat(directory.path, &info) == 0 else {
            throw failure("Cannot inspect owned status directory", code: errno)
        }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o700 == 0o700, info.st_mode & 0o077 == 0 else {
            throw refusal("Status store requires a private effective-user-owned directory")
        }
        // Directory size and link count can change when valid Finder metadata comes
        // and goes; they do not identify the authoritative store.
        info.st_size = 0
        info.st_nlink = 0
        return StatusFileIdentity(info)
    }

    private static func openArtifact(_ url: URL) throws -> Int32 {
        let expected = try pathIdentity(url)
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw failure("Cannot open status artifact without following links", code: errno) }
        do {
            guard try identity(descriptor) == expected else { throw refusal("Status artifact changed before open") }
        } catch {
            close(descriptor)
            throw error
        }
        return descriptor
    }

    private static func pathIdentity(_ url: URL) throws -> StatusFileIdentity {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw failure("Cannot inspect status artifact", code: errno) }
        try JournalStateDirectory.validateArtifact(info)
        return StatusFileIdentity(info)
    }

    private static func identity(_ descriptor: Int32) throws -> StatusFileIdentity {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw failure("Cannot inspect opened status artifact", code: errno) }
        try JournalStateDirectory.validateArtifact(info)
        return StatusFileIdentity(info)
    }

    private static func readHeader(_ descriptor: Int32) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 100)
        var total = 0
        while total < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                pread(descriptor, $0.baseAddress!.advanced(by: total), $0.count - total, off_t(total))
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw failure("Cannot read SQLite header", code: errno)
            }
            if count == 0 { break }
            total += count
        }
        return Data(bytes.prefix(total))
    }

    private static func validateHeader(_ header: Data) throws {
        guard header.count == 100,
              header.prefix(16) == Data("SQLite format 3\0".utf8),
              header[18] == 1, header[19] == 1,
              bigEndianUInt32(header, at: 68) == applicationID,
              bigEndianUInt32(header, at: 60) == 1 else {
            throw refusal("Status store requires the OMST v1 rollback-format SQLite header")
        }
    }

    private static func bigEndianUInt32(_ bytes: Data, at offset: Int) -> UInt32 {
        bytes[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func refusal(_ message: String) -> JournalStorageError {
        JournalStorageError(kind: .filesystem, message: message)
    }

    private static func failure(_ message: String, code: Int32) -> JournalStorageError {
        JournalStorageError(kind: .filesystem, message: message, posixCode: code)
    }
}
