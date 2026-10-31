import Darwin
import Foundation

/// Cooperative process-wide ownership of a stable file. Never unlink it: replacing
/// its inode could allow two owners to hold locks for the same journal directory.
final class JournalDirectoryLock {
    private let descriptor: Int32

    init(directory: URL) throws {
        let path = directory.appendingPathComponent("admission.lock").path
        let opened = open(path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard opened >= 0 else {
            throw JournalStorageError(message: "Cannot open journal ownership lock: \(String(cString: strerror(errno)))")
        }
        guard flock(opened, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(opened)
            if code == EWOULDBLOCK {
                throw JournalStorageError(message: "Journal directory already owned")
            }
            throw JournalStorageError(message: "Cannot acquire journal ownership lock: \(String(cString: strerror(code)))")
        }
        descriptor = opened
    }

    deinit { close(descriptor) }
}
