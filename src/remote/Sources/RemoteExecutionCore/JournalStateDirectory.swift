import Darwin
import Foundation

/// Requires a dedicated state leaf below a stable, host-trusted parent. This is
/// ordinary POSIX/ACL privacy, not isolation from hostile code running as this user.
/// Existing directories and inherited ACLs are never silently repaired.
enum JournalStateDirectory {
    static func prepare(_ requestedDirectory: URL, createIfMissing: Bool = true) throws -> URL {
        // Reject ambiguous spelling before resolving anything. In particular, link/.
        // must not make lstat inspect the symlink target instead of the leaf itself.
        let components = requestedDirectory.path.split(separator: "/")
        guard requestedDirectory.isFileURL,
              !components.contains("."), !components.contains(".."),
              let leaf = components.last else {
            throw invalid("Journal state directory requires an unambiguous named leaf")
        }
        // Host-trusted parent aliases (including macOS /var and /tmp) are valid.
        // Resolve only that parent and retain the caller's original leaf name.
        let parentPath = requestedDirectory.deletingLastPathComponent().path
        guard let canonicalParent = realpath(parentPath, nil) else {
            let code = errno
            throw JournalStorageError(kind: .filesystem,
                message: "Cannot resolve trusted journal state parent: \(String(cString: strerror(code)))", posixCode: code)
        }
        defer { free(canonicalParent) }
        // Foundation's resolvingSymlinksInPath may reintroduce /var or /tmp aliases
        // on Darwin. POSIX realpath preserves the canonical spelling SQLite requires.
        let parent = URL(fileURLWithPath: String(cString: canonicalParent), isDirectory: true)
        let directory = parent.appendingPathComponent(String(leaf), isDirectory: true)
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            let code = errno
            guard code == ENOENT else { throw invalid("Cannot inspect journal state directory", code: code) }
            guard createIfMissing else { throw invalid("Journal state directory does not exist", code: code) }
            // Do not create or change parents. The host must provision a trusted parent.
            if mkdir(directory.path, mode_t(0o700)) != 0 {
                let creationCode = errno
                guard creationCode == EEXIST else {
                    throw JournalStorageError(kind: .filesystem,
                        message: "Cannot create journal state directory: \(String(cString: strerror(creationCode)))",
                        posixCode: creationCode)
                }
            } else if chmod(directory.path, mode_t(0o700)) != 0 {
                // Normalize only the leaf this call created. A restrictive umask
                // can remove every owner bit, preventing a descriptor open first.
                // The parent is host-trusted; this is not hostile same-user isolation.
                let code = errno
                throw JournalStorageError(kind: .filesystem,
                    message: "Cannot set created journal state directory mode: \(String(cString: strerror(code)))",
                    posixCode: code)
            }
            guard lstat(directory.path, &info) == 0 else {
                throw invalid("Cannot inspect created journal state directory", code: errno)
            }
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw invalid("Journal state leaf must be a directory, not a symbolic link or other file")
        }
        guard info.st_uid == geteuid() else { throw invalid("Journal state directory must be owned by the effective user") }
        guard info.st_mode & 0o700 == 0o700, info.st_mode & 0o077 == 0 else {
            throw invalid("Journal state directory requires owner rwx mode bits and no group or other permissions (0700)")
        }
        try inspectACL(directory, expected: info)
        try inspectArtifacts(in: directory)
        return directory
    }

    private static func inspectArtifacts(in directory: URL) throws {
        for name in ["admission.lock", "admission.sqlite3", "admission.sqlite3-journal",
                     "admission.sqlite3-wal", "admission.sqlite3-shm"] {
            var info = stat()
            if lstat(directory.appendingPathComponent(name).path, &info) != 0 {
                let code = errno
                guard code == ENOENT else {
                    throw JournalStorageError(kind: .filesystem, message: "Cannot inspect journal state artifact",
                                              posixCode: code)
                }
                continue
            }
            try validateArtifact(info)
        }
    }

    static func validateArtifact(_ info: stat) throws {
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1 else {
            throw JournalStorageError(kind: .filesystem,
                message: "Journal state artifacts must be regular, effective-user-owned files with one hard link")
        }
    }

    private static func inspectACL(_ directory: URL, expected: stat) throws {
        guard let security = filesec_init() else {
            throw invalid("Cannot allocate journal state directory security inspection", code: errno)
        }
        defer { filesec_free(security) }
        var inspected = stat()
        guard lstatx_np(directory.path, &inspected, security) == 0 else {
            throw invalid("Cannot inspect journal state directory security", code: errno)
        }
        guard inspected.st_dev == expected.st_dev, inspected.st_ino == expected.st_ino,
              inspected.st_mode == expected.st_mode, inspected.st_uid == expected.st_uid,
              inspected.st_gid == expected.st_gid else {
            throw invalid("Journal state directory changed during inspection")
        }
        // Darwin statx can return success with an unpopulated filesec on an
        // internal allocation failure. Require its basic properties as evidence
        // of complete inspection before accepting an absent ACL property.
        var owner = uid_t(0)
        var group = gid_t(0)
        var mode = mode_t(0)
        guard filesec_get_property(security, FILESEC_OWNER, &owner) == 0,
              filesec_get_property(security, FILESEC_GROUP, &group) == 0,
              filesec_get_property(security, FILESEC_MODE, &mode) == 0 else {
            throw invalid("Incomplete journal state directory security inspection", code: errno)
        }
        guard owner == inspected.st_uid, group == inspected.st_gid, mode == inspected.st_mode else {
            throw invalid("Inconsistent journal state directory security inspection")
        }
        var present: Int32 = 0
        guard filesec_query_property(security, FILESEC_ACL, &present) == 0 else {
            throw invalid("Cannot query journal state directory ACL", code: errno)
        }
        // acl_get_file returns nil/ENOENT for a missing FILESEC_ACL property as
        // well as for missing paths. Query after successful lstatx instead, so
        // an inspection failure cannot be mistaken for an absent ACL.
        guard present != 0 else { return }
        var decoded: acl_t?
        guard filesec_get_property(security, FILESEC_ACL, &decoded) == 0, let acl = decoded else {
            throw invalid("Cannot decode journal state directory ACL", code: errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw invalid("Invalid journal state directory ACL", code: errno) }
        var entry: acl_entry_t?
        var entryID = ACL_FIRST_ENTRY.rawValue
        while true {
            if acl_get_entry(acl, entryID, &entry) != 0 {
                let code = errno
                // Darwin returns -1/EINVAL when a valid ACL has no further entries.
                // acl_valid above distinguishes a malformed ACL from normal exhaustion.
                guard code == EINVAL else { throw invalid("Cannot enumerate journal state directory ACL", code: code) }
                return
            }
            guard let entry else { throw invalid("Missing journal state directory ACL entry") }
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(entry, &tag) == 0 else {
                throw invalid("Cannot inspect journal state directory ACL entry", code: errno)
            }
            // Reject all allow entries, including inherited grants and owner grants;
            // do not attempt principal membership or permission-set interpretation.
            guard tag == ACL_EXTENDED_DENY else {
                throw invalid("Journal state directory ACL must not contain extended allow grants")
            }
            entryID = ACL_NEXT_ENTRY.rawValue
        }
    }

    private static func invalid(_ message: String, code: Int32? = nil) -> JournalStorageError {
        let detail = code.map { ": \(String(cString: strerror($0)))" } ?? ""
        return JournalStorageError(kind: .invalidDirectory, message: message + detail, posixCode: code)
    }
}
