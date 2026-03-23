/// InboxView.swift — Retrieval-first directed sharing inbox for iOS.
///
/// Shows incoming directed shares with challenge display, password-gated
/// retrieval, and delete. Sending is not supported on iOS in this milestone.

import SwiftUI

struct InboxView: View {
    @EnvironmentObject var vm: MiasmaViewModel

    var body: some View {
        NavigationStack {
            Group {
                if !vm.isDaemonRunning {
                    ContentUnavailableView(
                        "Daemon Not Running",
                        systemImage: "network.slash",
                        description: Text("Start the daemon to view directed shares")
                    )
                } else if vm.inboxItems.isEmpty {
                    ContentUnavailableView(
                        "No Incoming Shares",
                        systemImage: "tray",
                        description: Text("Directed shares sent to you will appear here")
                    )
                } else {
                    List(vm.inboxItems, id: \.envelopeId) { item in
                        InboxItemRow(item: item, vm: vm)
                    }
                }
            }
            .navigationTitle("Inbox")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Refresh") { vm.refreshInbox() }
                }
            }
            .onAppear { vm.refreshInbox() }
        }
    }
}

struct InboxItemRow: View {
    let item: DirectedInboxItem
    @ObservedObject var vm: MiasmaViewModel
    @State private var password = ""
    @State private var isRetrieving = false
    @State private var retrieveError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // State badge + envelope ID
            HStack {
                Text(badgeLabel)
                    .font(.caption2.bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(badgeColor, in: Capsule())

                Text(String(item.envelopeId.prefix(16)) + "…")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            // Sender
            Text("From: \(String(item.senderKey.prefix(20)))…")
                .font(.caption)

            // Expiry
            Text(expiryText)
                .font(.caption)
                .foregroundStyle(isExpired ? .red : .secondary)

            // Challenge code (for recipient to share with sender)
            if let code = item.challengeCode, item.state == "ChallengeIssued" {
                GroupBox("Challenge code (share with sender)") {
                    Text(code)
                        .font(.title3.monospaced().bold())
                        .textSelection(.enabled)
                }
            }

            // Password-gated retrieval
            if item.state == "Confirmed" {
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)

                Button {
                    isRetrieving = true
                    retrieveError = nil
                    vm.retrieveDirected(envelopeId: item.envelopeId, password: password) { error in
                        isRetrieving = false
                        retrieveError = error
                    }
                } label: {
                    if isRetrieving {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text("Retrieve")
                }
                .disabled(password.isEmpty || isRetrieving)
                .buttonStyle(.borderedProminent)

                if let err = retrieveError {
                    Text(err).font(.caption).foregroundStyle(.red)
                }
            }

            // Terminal state messages
            switch item.state {
            case "Retrieved":
                Label("Content retrieved", systemImage: "checkmark.circle.fill")
                    .font(.caption).foregroundStyle(.green)
            case "Expired":
                Label("Expired", systemImage: "clock.badge.exclamationmark")
                    .font(.caption).foregroundStyle(.orange)
            case "SenderRevoked":
                Label("Revoked by sender", systemImage: "xmark.circle")
                    .font(.caption).foregroundStyle(.red)
            case "ChallengeFailed":
                Label("Challenge failed", systemImage: "xmark.circle")
                    .font(.caption).foregroundStyle(.red)
            case "PasswordFailed":
                Label("Password attempts exhausted", systemImage: "xmark.circle")
                    .font(.caption).foregroundStyle(.red)
            default:
                EmptyView()
            }

            // Delete (non-terminal only)
            if !isTerminal(item.state) {
                Button("Delete", role: .destructive) {
                    vm.deleteDirectedEnvelope(envelopeId: item.envelopeId, isInbox: true)
                }
                .font(.caption)
            }
        }
        .padding(.vertical, 4)
    }

    private var badgeColor: Color {
        switch item.state {
        case "Pending", "ChallengeIssued": return .orange
        case "Confirmed", "Retrieved": return .green
        case "SenderRevoked", "ChallengeFailed", "PasswordFailed": return .red
        default: return .gray
        }
    }

    private var badgeLabel: String {
        switch item.state {
        case "ChallengeIssued": return "Challenge"
        default: return item.state
        }
    }

    private var isExpired: Bool {
        guard item.expiresAt > 0 else { return false }
        return Date().timeIntervalSince1970 >= Double(item.expiresAt)
    }

    private var expiryText: String {
        guard item.expiresAt > 0 else { return "" }
        let now = Date().timeIntervalSince1970
        let remaining = Double(item.expiresAt) - now
        if remaining <= 0 { return "Expired" }
        let totalMinutes = Int(remaining) / 60
        let hours = totalMinutes / 60
        let minutes = totalMinutes % 60
        if hours > 0 {
            return "Expires in \(hours)h \(minutes)m"
        } else {
            return "Expires in \(minutes)m"
        }
    }

    private func isTerminal(_ state: String) -> Bool {
        ["Retrieved", "Expired", "SenderRevoked", "RecipientDeleted", "ChallengeFailed", "PasswordFailed"].contains(state)
    }
}
