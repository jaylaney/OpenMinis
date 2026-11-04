#if os(macOS)
import Foundation

/// Cancellation only. Each explicit enable allocates a fresh instance; there is
/// deliberately no reset or authority-producing operation.
public final class ServiceFence: @unchecked Sendable {
    private let lock = NSLock()
    private var disabled = false
    private var cancellations: [@Sendable () -> Void] = []
    public init() {}
    public var isDisabled: Bool { lock.withLock { disabled } }
    public func disable() {
        let actions = lock.withLock { () -> [@Sendable () -> Void] in
            disabled = true
            // Repeat idempotent cancellation for racing callers: each caller
            // must finish cancellation, even if another already latched the bit.
            return cancellations
        }
        for action in actions { action() }
    }
    func onDisable(_ action: @escaping @Sendable () -> Void) {
        let run = lock.withLock { if disabled { return true }; cancellations.append(action); return false }
        if run { action() }
    }
    func whileEnabled<T>(_ body: () throws -> T) throws -> T {
        try lock.withLock { guard !disabled else { throw HostBridgeError.disabled }; return try body() }
    }
}
public enum HostBridgeError: Error, Equatable, Sendable { case disabled, refused, unavailable }
#endif
