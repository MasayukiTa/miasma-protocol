/// BackupExclusion.swift — exclude the data directory from iCloud/device backups.
///
/// The data directory holds locally re-derivable and sensitive state that must
/// not leave the device through iCloud or encrypted device backups. We mark it
/// with `URLResourceValues.isExcludedFromBackup = true` right after the
/// directory is created, and again on every launch so the setting is idempotent
/// for directories that already exist.

import Foundation

/// Why setting the backup-exclusion flag failed.
///
/// The error kind is returned without any path or attribute value so callers can
/// log the category without leaking file-system details.
public enum BackupExclusionError: Error, Equatable {
    /// The URL did not point at an existing item on disk.
    case notFound
    /// The file system rejected the resource-value write.
    case setFailed
    /// Any other failure kind.
    case other
}

/// Mark the item at `url` as excluded from iCloud and device backups.
///
/// This is idempotent: calling it on a directory that is already excluded is a
/// no-op that still returns success. It never throws; failures are reported as a
/// `BackupExclusionError` kind so the caller can keep the app running and log
/// only the category.
///
/// - Parameter url: File URL of the directory (or file) to exclude.
/// - Returns: `nil` on success, or the failure kind.
@discardableResult
public func excludeFromBackup(at url: URL) -> BackupExclusionError? {
    guard FileManager.default.fileExists(atPath: url.path) else {
        return .notFound
    }
    var target = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    do {
        try target.setResourceValues(&values)
        return nil
    } catch let error as CocoaError where error.code == .fileNoSuchFile {
        return .notFound
    } catch is CocoaError {
        return .setFailed
    } catch {
        return .other
    }
}

/// Convenience overload that takes a directory path string.
///
/// - Parameter path: File-system path of the directory (or file) to exclude.
/// - Returns: `nil` on success, or the failure kind.
@discardableResult
public func excludeFromBackup(atPath path: String) -> BackupExclusionError? {
    excludeFromBackup(at: URL(fileURLWithPath: path))
}
