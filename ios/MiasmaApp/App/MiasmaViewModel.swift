/// MiasmaViewModel.swift — ObservableObject ViewModel for iOS (Phase 2, Task 13).
import Foundation
import Combine
import MiasmaFFI

@MainActor
class MiasmaViewModel: ObservableObject {

    @Published var nodeStatus: NodeStatusFfi?
    @Published var lastMid: String?
    @Published var retrievedData: Data?
    @Published var isLoading = false
    @Published var errorMessage: String?

    private var dataDir: String {
        (FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?
            .appendingPathComponent("miasma")
            .path) ?? NSTemporaryDirectory()
    }

    // MARK: - Status

    func refreshStatus() {
        Task {
            isLoading = true
            errorMessage = nil
            do {
                nodeStatus = try await Task.detached(priority: .userInitiated) {
                    try getNodeStatus(dataDir: self.dataDir)
                }.value
            } catch MiasmaFfiError.notInitialized {
                nodeStatus = nil
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }

    // MARK: - Dissolve

    func dissolve(data: Data) {
        Task {
            isLoading = true
            errorMessage = nil
            lastMid = nil
            do {
                lastMid = try await Task.detached(priority: .userInitiated) {
                    try dissolveBytes(dataDir: self.dataDir, data: data)
                }.value
                refreshStatus()
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }

    // MARK: - Retrieve

    func retrieve(mid: String) {
        Task {
            isLoading = true
            errorMessage = nil
            retrievedData = nil
            do {
                retrievedData = try await Task.detached(priority: .userInitiated) {
                    try retrieveBytes(dataDir: self.dataDir, midStr: mid)
                }.value
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }

    // MARK: - Distress wipe

    func distressWipe() {
        Task {
            isLoading = true
            errorMessage = nil
            do {
                try await Task.detached(priority: .userInitiated) {
                    try MiasmaFFI.distressWipe(dataDir: self.dataDir)
                }.value
                // Reset all state.
                nodeStatus = nil
                lastMid = nil
                retrievedData = nil
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}
