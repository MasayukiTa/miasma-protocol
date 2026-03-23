/// MiasmaViewModel.swift — ObservableObject ViewModel for iOS.
///
/// Manages node state, directed sharing inbox, and daemon lifecycle.
/// iOS is retrieval-first: inbox, confirm, retrieve, delete are supported.
/// Sending directed shares is not supported in this milestone.
import Foundation
import Combine
import MiasmaFFI

/// Envelope item for the inbox list.
struct DirectedInboxItem: Identifiable {
    let envelopeId: String
    let senderKey: String
    let state: String
    let challengeCode: String?
    let createdAt: UInt64
    let expiresAt: UInt64

    var id: String { envelopeId }
}

@MainActor
class MiasmaViewModel: ObservableObject {

    @Published var nodeStatus: NodeStatusFfi?
    @Published var lastMid: String?
    @Published var retrievedData: Data?
    @Published var isLoading = false
    @Published var errorMessage: String?

    // ── Daemon state ────────────────────────────────────────────────────
    @Published var isDaemonRunning = false
    @Published var daemonHttpPort: UInt16 = 0
    @Published var sharingContact: String = ""

    // ── Directed sharing ────────────────────────────────────────────────
    @Published var inboxItems: [DirectedInboxItem] = []

    private var dataDir: String {
        (FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?
            .appendingPathComponent("miasma")
            .path) ?? NSTemporaryDirectory()
    }

    // MARK: - Daemon lifecycle

    func startDaemon() {
        Task {
            isLoading = true
            errorMessage = nil
            do {
                let status = try await Task.detached(priority: .userInitiated) {
                    // Ensure data directory exists.
                    let dir = self.dataDir
                    try FileManager.default.createDirectory(
                        atPath: dir,
                        withIntermediateDirectories: true
                    )
                    return try startEmbeddedDaemon(
                        dataDir: dir,
                        storageMb: 512,
                        bandwidthMbDay: 100
                    )
                }.value
                isDaemonRunning = true
                daemonHttpPort = status.httpPort
                sharingContact = status.sharingContact
                refreshStatus()
                refreshInbox()
            } catch {
                errorMessage = "Daemon: \(error.localizedDescription)"
                // Fall back to local-only init.
                do {
                    try await Task.detached(priority: .userInitiated) {
                        try initializeNode(dataDir: self.dataDir, storageMb: 512, bandwidthMbDay: 100)
                    }.value
                } catch { /* best effort */ }
            }
            isLoading = false
        }
    }

    func stopDaemon() {
        stopEmbeddedDaemon()
        isDaemonRunning = false
        daemonHttpPort = 0
        sharingContact = ""
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
                stopDaemon()
                nodeStatus = nil
                lastMid = nil
                retrievedData = nil
                inboxItems = []
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }

    // MARK: - Directed sharing (retrieval-first)

    func refreshInbox() {
        guard isDaemonRunning, daemonHttpPort > 0 else { return }
        Task {
            do {
                let port = daemonHttpPort
                let items = try await Task.detached(priority: .userInitiated) {
                    try self.httpGetInbox(port: port)
                }.value
                inboxItems = items
            } catch {
                // Silent failure — inbox will show empty
            }
        }
    }

    func retrieveDirected(envelopeId: String, password: String, completion: @escaping (String?) -> Void) {
        guard isDaemonRunning, daemonHttpPort > 0 else {
            completion("Daemon not running")
            return
        }
        let port = daemonHttpPort
        Task {
            do {
                let _ = try await Task.detached(priority: .userInitiated) {
                    try self.httpDirectedRetrieve(port: port, envelopeId: envelopeId, password: password)
                }.value
                refreshInbox()
                completion(nil)
            } catch {
                completion(error.localizedDescription)
            }
        }
    }

    func deleteDirectedEnvelope(envelopeId: String, isInbox: Bool) {
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try deleteDirectedEnvelope(dataDir: self.dataDir, envelopeId: envelopeId)
                }.value
                refreshInbox()
            } catch {
                errorMessage = "Delete failed: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - HTTP bridge helpers (for directed sharing)

    private func httpGetInbox(port: UInt16) throws -> [DirectedInboxItem] {
        let url = URL(string: "http://127.0.0.1:\(port)/api/directed/inbox")!
        let (data, _) = try synchronousHTTPGet(url: url)
        guard let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return []
        }
        return arr.map { obj in
            DirectedInboxItem(
                envelopeId: obj["envelope_id"] as? String ?? "",
                senderKey: obj["sender_pubkey"] as? String ?? "",
                state: obj["state"] as? String ?? "Unknown",
                challengeCode: obj["challenge_code"] as? String,
                createdAt: (obj["created_at"] as? NSNumber)?.uint64Value ?? 0,
                expiresAt: (obj["expires_at"] as? NSNumber)?.uint64Value ?? 0
            )
        }
    }

    private func httpDirectedRetrieve(port: UInt16, envelopeId: String, password: String) throws -> Data {
        let url = URL(string: "http://127.0.0.1:\(port)/api/directed/retrieve")!
        let body: [String: Any] = ["envelope_id": envelopeId, "password": password]
        let jsonData = try JSONSerialization.data(withJSONObject: body)
        let (respData, _) = try synchronousHTTPPost(url: url, body: jsonData)
        guard let obj = try JSONSerialization.jsonObject(with: respData) as? [String: Any] else {
            throw MiasmaFfiError.other(msg: "invalid response")
        }
        if let error = obj["error"] as? String {
            throw MiasmaFfiError.other(msg: error)
        }
        guard let b64 = obj["data"] as? String, let decoded = Data(base64Encoded: b64) else {
            throw MiasmaFfiError.other(msg: "missing data in response")
        }
        return decoded
    }

    private func synchronousHTTPGet(url: URL) throws -> (Data, URLResponse) {
        var result: (Data, URLResponse)?
        var error: Error?
        let semaphore = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: url) { d, r, e in
            if let d = d, let r = r { result = (d, r) }
            error = e
            semaphore.signal()
        }.resume()
        semaphore.wait()
        if let e = error { throw e }
        guard let r = result else { throw MiasmaFfiError.other(msg: "no response") }
        return r
    }

    private func synchronousHTTPPost(url: URL, body: Data) throws -> (Data, URLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        var result: (Data, URLResponse)?
        var error: Error?
        let semaphore = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { d, r, e in
            if let d = d, let r = r { result = (d, r) }
            error = e
            semaphore.signal()
        }.resume()
        semaphore.wait()
        if let e = error { throw e }
        guard let r = result else { throw MiasmaFfiError.other(msg: "no response") }
        return r
    }
}
