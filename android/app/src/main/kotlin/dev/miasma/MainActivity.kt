package dev.miasma

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.miasma.ui.DissolveScreen
import dev.miasma.ui.HomeScreen
import dev.miasma.ui.RetrieveScreen
import dev.miasma.ui.SettingsScreen
import dev.miasma.ui.StatusScreen
import dev.miasma.ui.theme.MiasmaTheme

class MainActivity : ComponentActivity() {

    private val vm: MiasmaViewModel by viewModels()

    private val requestCameraPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* handled in screen */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Start the background daemon with persisted settings.
        MiasmaService.startNode(
            this,
            filesDir.absolutePath,
            Prefs.storageMb(this),
            Prefs.bandwidthMbDay(this),
        )

        // Pre-request camera permission (QR scanner).
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            requestCameraPermission.launch(Manifest.permission.CAMERA)
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
                                NavigationBarItem(
                                    icon = { Icon(item.icon, contentDescription = item.label) },
                                    label = { Text(item.label) },
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
                        composable("home")     { HomeScreen(vm) }
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

private data class NavItem(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val NAV_ITEMS = listOf(
    NavItem("home",     "Home",     Icons.Default.Cloud),
    NavItem("dissolve", "Dissolve", Icons.Default.CloudUpload),
    NavItem("retrieve", "Retrieve", Icons.Default.CloudDownload),
    NavItem("status",   "Status",   Icons.Default.Info),
    NavItem("settings", "Settings", Icons.Default.Settings),
)
