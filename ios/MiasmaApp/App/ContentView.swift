/// ContentView.swift — Tab-based root UI for iOS (Phase 2, Task 13).
import SwiftUI
import WebKit

struct ContentView: View {
    @EnvironmentObject var vm: MiasmaViewModel

    var body: some View {
        TabView {
            HomeView()
                .tabItem {
                    Label("Home", systemImage: "cloud")
                }
            DissolveView()
                .tabItem {
                    Label("Dissolve", systemImage: "cloud.fill")
                }
            RetrieveView()
                .tabItem {
                    Label("Retrieve", systemImage: "arrow.down.circle")
                }
            StatusView()
                .tabItem {
                    Label("Status", systemImage: "info.circle")
                }
            WebBridgeView()
                .tabItem {
                    Label("Web", systemImage: "globe")
                }
        }
    }
}

// MARK: - Home

struct HomeView: View {
    @EnvironmentObject var vm: MiasmaViewModel

    var body: some View {
        VStack(spacing: 12) {
            Text("Miasma")
                .font(.largeTitle.bold())
                // Long-press for emergency wipe (iOS gesture).
                .onLongPressGesture(minimumDuration: 3.0) {
                    vm.distressWipe()
                }
            Text("Plausibly-deniable distributed storage")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text("Long-press title for emergency wipe")
                .font(.caption2)
                .foregroundStyle(.tertiary)

            if let s = vm.nodeStatus {
                Text("\(s.shareCount) shares · \(s.usedMb, format: .number.precision(.fractionLength(1))) / \(s.quotaMb) MiB")
                    .font(.caption)
                    .foregroundStyle(.accentColor)
            }
            if let err = vm.errorMessage {
                Text(err).font(.caption).foregroundStyle(.red)
            }
        }
        .padding()
    }
}

// MARK: - Dissolve

struct DissolveView: View {
    @EnvironmentObject var vm: MiasmaViewModel
    @State private var inputText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Text") {
                    TextEditor(text: $inputText)
                        .frame(height: 120)
                    Button("Dissolve text") {
                        if let data = inputText.data(using: .utf8) {
                            vm.dissolve(data: data)
                        }
                    }
                    .disabled(inputText.isEmpty || vm.isLoading)
                }
                if vm.isLoading {
                    Section { ProgressView() }
                }
                if let mid = vm.lastMid {
                    Section("MID") {
                        Text(mid).font(.caption.monospaced())
                    }
                }
            }
            .navigationTitle("Dissolve")
        }
    }
}

// MARK: - Retrieve

struct RetrieveView: View {
    @EnvironmentObject var vm: MiasmaViewModel
    @State private var midInput = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("MID") {
                    TextField("miasma:<base58>", text: $midInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Button("Retrieve") {
                    vm.retrieve(mid: midInput.trimmingCharacters(in: .whitespaces))
                }
                .disabled(midInput.isEmpty || vm.isLoading)

                if vm.isLoading {
                    Section { ProgressView() }
                }
                if let data = vm.retrievedData {
                    Section("Result") {
                        Text("\(data.count) bytes retrieved")
                        if let text = String(data: data, encoding: .utf8) {
                            ShareLink("Share as text", item: text)
                        }
                    }
                }
                if let err = vm.errorMessage {
                    Section { Text(err).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Retrieve")
        }
    }
}

// MARK: - Status

struct StatusView: View {
    @EnvironmentObject var vm: MiasmaViewModel
    @State private var showWipeAlert = false

    var body: some View {
        NavigationStack {
            Form {
                if let s = vm.nodeStatus {
                    Section("Node") {
                        LabeledContent("Shares", value: "\(s.shareCount)")
                        LabeledContent("Used", value: String(format: "%.1f / %llu MiB", s.usedMb, s.quotaMb))
                        LabeledContent("Listen", value: s.listenAddr)
                        LabeledContent("Bootstrap peers", value: "\(s.bootstrapCount)")
                    }
                } else {
                    Section { Text("Node not initialised — tap Dissolve to start.") }
                }

                Section {
                    Button("Refresh") { vm.refreshStatus() }
                }

                Section {
                    Button("Emergency Wipe", role: .destructive) {
                        showWipeAlert = true
                    }
                }
            }
            .navigationTitle("Status")
            .onAppear { vm.refreshStatus() }
            .alert("Emergency Wipe", isPresented: $showWipeAlert) {
                Button("WIPE NOW", role: .destructive) { vm.distressWipe() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Destroy the master key? All stored shares become permanently unreadable. This CANNOT be undone.")
            }
        }
    }
}
