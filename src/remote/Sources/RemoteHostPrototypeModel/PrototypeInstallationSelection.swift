import Foundation

public enum PrototypeInstallationSelection {
    public enum SelectionError: Error { case invalidArguments }

    /// Arguments exclude the executable. This is a local launch selection only.
    public static func parse(arguments: [String]) throws -> UUID? {
        var selected: UUID?
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--prototype-installation" {
                guard selected == nil, index + 1 < arguments.count,
                      let id = UUID(uuidString: arguments[index + 1]),
                      id.uuidString.lowercased() == arguments[index + 1],
                      id.uuidString != "00000000-0000-0000-0000-000000000000" else { throw SelectionError.invalidArguments }
                selected = id; index += 2
            } else {
                guard !argument.hasPrefix("--prototype-installation") else { throw SelectionError.invalidArguments }
                index += 1 // Unrelated system launch arguments are not path selectors.
            }
        }
        return selected
    }
    public static func resolve(applicationSupport: URL, installationID: UUID?) -> URL {
        applicationSupport.appendingPathComponent("OpenMinisPrototype", isDirectory: true)
            .appendingPathComponent("installations", isDirectory: true)
            .appendingPathComponent(installationID?.uuidString.lowercased() ?? "default", isDirectory: true)
    }

    /// Only fixed trusted parents are provisioned, and only at explicit enable.
    /// Core creates/validates the private installation leaf under its own rules.
    static func provisionParents(of directory: URL) throws {
        let parents = directory.deletingLastPathComponent()
        let prototype = parents.deletingLastPathComponent()
        guard parents.lastPathComponent == "installations", prototype.lastPathComponent == "OpenMinisPrototype" else { throw SelectionError.invalidArguments }
        for url in [prototype, parents] {
            var info = stat()
            if lstat(url.path, &info) == 0 {
                guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw SelectionError.invalidArguments }
            } else {
                guard errno == ENOENT, mkdir(url.path, 0o700) == 0 else { throw SelectionError.invalidArguments }
            }
        }
    }
}
