import Darwin
import Foundation

/// Cooperative process-wide ownership of a stable file. Never unlink it: replacing
/// its inode could allow two owners to hold locks for the same journal directory.
final class JournalDirectoryLock {
    private let descriptor: Int32

    init(directory: URL) throws {
        let path = directory.appendingPathComponent("admission.lock").path
        let created = try JournalFileCreation.createIfMissing(path: path, description: "journal ownership lock")
        let opened = created ?? open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        guard opened >= 0 else {
            let code = errno
            throw JournalStorageError(kind: .filesystem, message: "Cannot open journal ownership lock: \(String(cString: strerror(code)))", posixCode: code)
        }
        do {
            var info = stat()
            guard fstat(opened, &info) == 0 else {
                let code = errno
                throw JournalStorageError(kind: .filesystem, message: "Cannot inspect opened journal ownership lock", posixCode: code)
            }
            try JournalStateDirectory.validateArtifact(info)
        } catch {
            close(opened)
            throw error
        }
        guard flock(opened, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(opened)
            if code == EWOULDBLOCK {
                throw JournalStorageError(kind: .alreadyOwned, message: "Journal directory already owned", posixCode: code)
            }
            throw JournalStorageError(kind: .filesystem, message: "Cannot acquire journal ownership lock: \(String(cString: strerror(code)))", posixCode: code)
        }
        descriptor = opened
    }

    deinit { close(descriptor) }
}
