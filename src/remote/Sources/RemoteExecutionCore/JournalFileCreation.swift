import Darwin

/// Returns a descriptor only for a file created by this call. Existing paths are
/// left untouched so each caller retains its ordinary existing-file open checks.
enum JournalFileCreation {
    static func createIfMissing(path: String, description: String) throws -> Int32? {
        let descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            let code = errno
            if code == EEXIST { return nil }
            throw JournalStorageError(kind: .filesystem,
                message: "Cannot create \(description): \(String(cString: strerror(code)))", posixCode: code)
        }
        do {
            var info = stat()
            guard fstat(descriptor, &info) == 0 else {
                let code = errno
                throw JournalStorageError(kind: .filesystem,
                    message: "Cannot inspect created \(description)", posixCode: code)
            }
            try JournalStateDirectory.validateArtifact(info)
            // umask may remove owner read/write. Only an O_EXCL success gives this
            // call authority to restore them, through that same descriptor.
            guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
                let code = errno
                throw JournalStorageError(kind: .filesystem,
                    message: "Cannot set created \(description) mode", posixCode: code)
            }
            return descriptor
        } catch {
            close(descriptor)
            // Never unlink: a failed creation/normalization remains for inspection.
            throw error
        }
    }
}
