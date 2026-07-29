package org.matrix.teesimulator.physicalharness

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import java.time.Instant
import java.util.concurrent.Executors

class DonorService : Service() {
    private lateinit var controller: DonorServiceController
    private lateinit var startDispatcher: DonorServiceStartDispatcher

    override fun onCreate() {
        super.onCreate()
        val runtime = ProductionDonorRuntimeHolder.get(applicationContext)
        controller =
            DonorServiceController(
                runtime,
                Executors.newSingleThreadExecutor { task ->
                    Thread(task, "donor-service-runtime").apply { isDaemon = true }
                },
                mainExecutor,
                Instant::now,
                object : DonorServiceController.Host {
                    override fun startForegroundNow() = startDonorForeground()

                    override fun stopSelfIfLatest(startId: Int): Boolean = stopSelfResult(startId)

                    override fun removeForeground() = stopForeground(STOP_FOREGROUND_REMOVE)

                    override fun terminateDonorProcess(): Nothing {
                        android.os.Process.killProcess(android.os.Process.myPid())
                        kotlin.system.exitProcess(1)
                    }
                },
            )
        startDispatcher = DonorServiceStartDispatcher(controller)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        val profileId =
            if (action == ACTION_START) intent.getStringExtra(EXTRA_PROFILE_ID) else null
        try {
            DonorStartupGates.runWhenAuthorized(
                intent?.getStringArrayListExtra(EXTRA_ACTIVE_ROLES).orEmpty().toSet()
            ) {
                startDispatcher.dispatch(action, profileId, startId)
            }
        } catch (_: RuntimeException) {
            stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (::controller.isInitialized) controller.closeOrTerminate()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun startDonorForeground() {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                getString(R.string.donor_notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
        )
        val notification =
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(getString(R.string.donor_notification_title))
                .build()

        startForeground(
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
    }

    companion object {
        const val ACTION_START = "org.matrix.teesimulator.physicalharness.action.START"
        const val ACTION_STOP = "org.matrix.teesimulator.physicalharness.action.STOP"
        const val EXTRA_PROFILE_ID = "org.matrix.teesimulator.physicalharness.extra.PROFILE_ID"
        const val EXTRA_ACTIVE_ROLES = "org.matrix.teesimulator.physicalharness.extra.ACTIVE_ROLES"

        private const val NOTIFICATION_CHANNEL_ID = "donor_service"
        private const val NOTIFICATION_ID = 1
    }
}
