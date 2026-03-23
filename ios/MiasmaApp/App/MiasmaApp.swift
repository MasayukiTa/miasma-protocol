/// MiasmaApp.swift — SwiftUI entry point for iOS (Phase 2, Task 13).
import SwiftUI
import BackgroundTasks   // BGProcessingTask

@main
struct MiasmaApp: App {

    @StateObject private var vm = MiasmaViewModel()

    init() {
        registerBackgroundTasks()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vm)
                .onReceive(NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)) { _ in
                    vm.refreshStatus()
                    vm.refreshInbox()
                }
        }
    }

    // MARK: - Background tasks

    /// Register BGProcessingTask identifiers declared in Info.plist.
    ///
    /// iOS restricts background execution to short windows granted by the OS.
    /// The BGProcessingTask is used to:
    ///   1. Keep the local share store warm (refresh LRU, handle eviction).
    ///   2. Perform low-priority share rotation.
    ///   3. Update the node status notification (if permitted).
    private func registerBackgroundTasks() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "dev.miasma.share-maintenance",
            using: nil
        ) { task in
            self.handleShareMaintenance(task: task as! BGProcessingTask)
        }
    }

    private func handleShareMaintenance(task: BGProcessingTask) {
        // Schedule the next run immediately after this one ends.
        scheduleShareMaintenance()

        task.expirationHandler = {
            task.setTaskCompleted(success: false)
        }

        // Phase 2: call into miasma-core FFI for share maintenance.
        // For now, complete immediately.
        task.setTaskCompleted(success: true)
    }

    private func scheduleShareMaintenance() {
        let request = BGProcessingTaskRequest(identifier: "dev.miasma.share-maintenance")
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        request.earliestBeginDate = Date(timeIntervalSinceNow: 4 * 3600) // 4 hours
        try? BGTaskScheduler.shared.submit(request)
    }
}
