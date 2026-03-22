/// WebBridgeView.swift — WKWebView-hosted Miasma web UI with native FFI bridge.
///
/// Loads the web app from the app bundle and injects `window.miasma` via a
/// WKUserScript + WKScriptMessageHandler.  JS calls dispatch to UniFFI
/// functions and return results via evaluateJavaScript callbacks.
///
/// Usage: Add `WebBridgeView()` as a tab or push destination.

import SwiftUI
import WebKit

// MARK: - SwiftUI Wrapper

struct WebBridgeView: View {
    var body: some View {
        WebBridgeRepresentable()
            .ignoresSafeArea()
            .navigationTitle("Web")
            .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - UIViewRepresentable

struct WebBridgeRepresentable: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()

        // Install message handler for JS → Swift bridge
        let handler = MiasmaBridgeHandler()
        config.userContentController.add(handler, name: "miasma")

        // Inject window.miasma bridge object
        let bridgeJS = """
        window.miasma = {
          _pending: {},
          _nextId: 1,
          _callback: function(id, result) {
            if (this._pending[id]) {
              this._pending[id](result);
              delete this._pending[id];
            }
          },
          _call: function(action, params) {
            return new Promise(function(resolve) {
              var id = window.miasma._nextId++;
              window.miasma._pending[id] = resolve;
              var msg = Object.assign({action: action, id: id}, params || {});
              window.webkit.messageHandlers.miasma.postMessage(msg);
            });
          },
          ping: function() { return this._call('ping'); },
          status: function() { return this._call('status'); },
          dissolve: function(data, k, n) { return this._call('dissolve', {data: data, k: k, n: n}); },
          retrieve: function(mid, k, n) { return this._call('retrieve', {mid: mid, k: k, n: n}); },
          wipe: function() { return this._call('wipe'); }
        };
        """
        let script = WKUserScript(
            source: bridgeJS,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(script)

        let webView = WKWebView(frame: .zero, configuration: config)
        handler.webView = webView

        // Load web assets from app bundle
        if let htmlURL = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "web") {
            let baseDir = htmlURL.deletingLastPathComponent()
            webView.loadFileURL(htmlURL, allowingReadAccessTo: baseDir)
        }

        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

// MARK: - Message Handler

class MiasmaBridgeHandler: NSObject, WKScriptMessageHandler {
    weak var webView: WKWebView?

    private var dataDir: String {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = support.appendingPathComponent("miasma")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.path
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard let body = message.body as? [String: Any],
              let action = body["action"] as? String,
              let id = body["id"] as? Int else { return }

        // Dispatch on background thread to avoid blocking main
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = self?.handleAction(action, body: body) ?? "{\"error\":\"handler deallocated\"}"
            DispatchQueue.main.async {
                self?.webView?.evaluateJavaScript(
                    "window.miasma._callback(\(id), \(result))"
                )
            }
        }
    }

    private func handleAction(_ action: String, body: [String: Any]) -> String {
        switch action {
        case "ping":
            return "{\"ok\":true}"

        case "status":
            do {
                let status = try getNodeStatus(dataDir: dataDir)
                return """
                {"peer_count":0,"share_count":\(status.shareCount),"storage_used_bytes":\(Int(status.usedMb * 1024 * 1024)),"listen_addrs":[],"peer_id":""}
                """
            } catch {
                return "{\"error\":\"\(escapeJSON(error.localizedDescription))\"}"
            }

        case "dissolve":
            guard let dataB64 = body["data"] as? String,
                  let data = Data(base64Encoded: dataB64) else {
                return "{\"error\":\"missing or invalid data\"}"
            }
            do {
                let mid = try dissolveBytes(dataDir: dataDir, data: [UInt8](data))
                return "{\"mid\":\"\(escapeJSON(mid))\"}"
            } catch {
                return "{\"error\":\"\(escapeJSON(error.localizedDescription))\"}"
            }

        case "retrieve":
            guard let mid = body["mid"] as? String else {
                return "{\"error\":\"missing mid\"}"
            }
            do {
                let bytes = try retrieveBytes(dataDir: dataDir, midStr: mid)
                let b64 = Data(bytes).base64EncodedString()
                return "{\"data\":\"\(b64)\"}"
            } catch {
                return "{\"error\":\"\(escapeJSON(error.localizedDescription))\"}"
            }

        case "wipe":
            do {
                try distressWipe(dataDir: dataDir)
                return "{\"ok\":true}"
            } catch {
                return "{\"error\":\"\(escapeJSON(error.localizedDescription))\"}"
            }

        default:
            return "{\"error\":\"unknown action: \(escapeJSON(action))\"}"
        }
    }

    private func escapeJSON(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
         .replacingOccurrences(of: "\n", with: "\\n")
    }
}
