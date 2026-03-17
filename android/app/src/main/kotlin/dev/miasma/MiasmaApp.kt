package dev.miasma

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class MiasmaApp : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        val channel = NotificationChannel(
            CHANNEL_DAEMON,
            "Miasma Daemon",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Persistent notification while the Miasma node is running"
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    companion object {
        const val CHANNEL_DAEMON = "miasma_daemon"
    }
}
