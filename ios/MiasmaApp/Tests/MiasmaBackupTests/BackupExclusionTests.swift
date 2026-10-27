import XCTest
@testable import MiasmaBackup

final class BackupExclusionTests: XCTestCase {

    /// Create a fresh temporary directory and remove it after the test.
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("miasma-backup-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: dir)
        }
        return dir
    }

    /// Read back the exclusion flag for a URL.
    private func isExcluded(_ url: URL) throws -> Bool {
        let values = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        return values.isExcludedFromBackup ?? false
    }

    /// After calling the helper, the directory is flagged as excluded.
    func testExcludeSetsFlagOnExistingDirectory() throws {
        let dir = try makeTempDir()
        XCTAssertFalse(try isExcluded(dir), "precondition: not excluded yet")

        let result = excludeFromBackup(at: dir)

        XCTAssertNil(result, "excludeFromBackup should succeed")
        XCTAssertTrue(try isExcluded(dir), "directory should be excluded from backup")
    }

    /// Calling the helper twice leaves the directory excluded and returns success
    /// both times (idempotent).
    func testExcludeIsIdempotent() throws {
        let dir = try makeTempDir()

        XCTAssertNil(excludeFromBackup(at: dir))
        XCTAssertNil(excludeFromBackup(at: dir))
        XCTAssertTrue(try isExcluded(dir))
    }

    /// The path-string overload sets the flag on an existing directory.
    func testExcludeByPathSetsFlag() throws {
        let dir = try makeTempDir()

        let result = excludeFromBackup(atPath: dir.path)

        XCTAssertNil(result)
        XCTAssertTrue(try isExcluded(dir))
    }

    /// A URL that does not exist on disk reports the notFound kind.
    func testExcludeMissingDirectoryReturnsNotFound() throws {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("miasma-backup-missing-" + UUID().uuidString, isDirectory: true)

        let result = excludeFromBackup(at: missing)

        XCTAssertEqual(result, .notFound)
    }
}
