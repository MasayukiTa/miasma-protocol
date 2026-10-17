package dev.miasma

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Analytics
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.miasma.ui.DissolveScreen
import dev.miasma.ui.FilesScreen
import dev.miasma.ui.HomeScreen
import dev.miasma.ui.InboxScreen
import dev.miasma.ui.OutboxScreen
import dev.miasma.ui.RetrieveScreen
import dev.miasma.ui.SendScreen
import dev.miasma.ui.SettingsScreen
import dev.miasma.ui.StatusScreen
import dev.miasma.ui.theme.MiasmaTheme

class MainActivity : ComponentActivity() {

    private val vm: MiasmaViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Start the background daemon with persisted settings.
        MiasmaService.startNode(
            this,
            filesDir.absolutePath,
            Prefs.storageMb(this),
            Prefs.bandwidthMbDay(this),
        )

        // Poll for daemon status to update ViewModel once daemon is ready.
        lifecycleScope.launch {
            while (true) {
                val ds = MiasmaService.lastDaemonStatus
                if (ds != null) {
                    val newPort = ds.httpPort.toInt()
                    if (newPort != vm.daemonHttpPort.value) {
                        vm.onDaemonStarted(newPort, ds.sharingContact)
                    }
                } else if (vm.daemonHttpPort.value != 0) {
                    // Daemon died or hasn't started — reset port.
                    vm.onDaemonStarted(0, "")
                }
                // Propagate daemon startup errors.
                val err = MiasmaService.lastDaemonError
                if (err != null && vm.daemonHttpPort.value == 0) {
                    vm.onDaemonError(err)
                }
                kotlinx.coroutines.delay(1_000)
            }
        }

        setContent {
            MiasmaTheme {
                val navController = rememberNavController()
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NAV_ITEMS.forEach { item ->
                                val label = stringResource(item.labelRes)
                                NavigationBarItem(
                                    icon = { Icon(item.icon, contentDescription = label) },
                                    label = { Text(label) },
                                    selected = currentDestination?.hierarchy?.any { it.route == item.route } == true,
                                    onClick = {
                                        navController.navigate(item.route) {
                                            popUpTo(navController.graph.findStartDestination().id) {
                                                saveState = true
                                            }
                                            launchSingleTop = true
                                            restoreState = true
                                        }
                                    },
                                )
                            }
                        }
                    },
                ) { innerPadding ->
                    NavHost(
                        navController,
                        startDestination = "home",
                        modifier = Modifier.padding(innerPadding),
                    ) {
                        composable("home") {
                            HomeScreen(
                                vm = vm,
                                onSend = { navController.navigate("send") },
                                onReceive = { navController.navigate("inbox") },
                                onSave = { navController.navigate("dissolve") },
                            )
                        }
                        composable("files") {
                            FilesScreen(
                                onSend = { navController.navigate("send") },
                                onInbox = { navController.navigate("inbox") },
                                onOutbox = { navController.navigate("outbox") },
                                onSave = { navController.navigate("dissolve") },
                                onRetrieve = { navController.navigate("retrieve") },
                            )
                        }
                        composable("send")     { SendScreen(vm) }
                        composable("inbox")    { InboxScreen(vm) }
                        composable("outbox")   { OutboxScreen(vm) }
                        composable("dissolve") { DissolveScreen(vm) }
                        composable("retrieve") { RetrieveScreen(vm) }
                        composable("status")   { StatusScreen(vm) }
                        composable("settings") { SettingsScreen() }
                    }
                }
            }
        }
    }
}

private data class NavItem(
    val route: String,
    val labelRes: Int,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
)

private val NAV_ITEMS = listOf(
    NavItem("home", R.string.nav_home, Icons.Outlined.Home),
    NavItem("files", R.string.nav_files, Icons.Outlined.Folder),
    NavItem("status", R.string.nav_status, Icons.Outlined.Analytics),
    NavItem("settings", R.string.nav_settings, Icons.Outlined.Settings),
)
