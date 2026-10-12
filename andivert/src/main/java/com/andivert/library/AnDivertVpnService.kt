package com.andivert.library

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Base [VpnService] that owns the TUN interface AnDivert diverts from.
 *
 * Developers normally subclass this and override [onDivertStarting] /
 * [onPacket]. The base class handles the tedious parts:
 *
 *  - building the TUN with sane addresses, MTU and DNS
 *  - optional per-app allow/deny lists (`addAllowedApplication` etc.)
 *  - giving the native engine the TUN descriptor
 *  - registering this service so upstream sockets can be `protect()`ed
 *    (without that, the forwarder's own traffic would loop into the TUN)
 *  - running a foreground notification so Android does not kill the VPN
 *
 * ### Minimal subclass
 *
 * ```kotlin
 * class MyGate : AnDivertVpnService() {
 *     override fun divertFilter() = "outbound and udp.DstPort == 53"
 *
 *     override fun onPacket(packet: AnDivert.DivertedPacket, divert: AnDivert) {
 *         Log.i(TAG, "dns -> ${packet.meta.dstAddressString()}")
 *         divert.send(packet.bytes)   // release it unchanged
 *     }
 * }
 * ```
 *
 * Start it with [start], stop it with [stop].
 */
abstract class AnDivertVpnService : VpnService() {

    companion object {
        private const val TAG = "AnDivertVpnService"
        private const val CHANNEL_ID = "andivert_vpn"
        private const val NOTIFICATION_ID = 0xAD10

        /** Actions understood by [onStartCommand]. */
        const val ACTION_START = "com.andivert.library.START"
        const val ACTION_STOP = "com.andivert.library.STOP"

        /** Virtual interface configuration; override via the open methods. */
        const val DEFAULT_ADDRESS = "10.111.222.1"
        const val DEFAULT_PREFIX_LENGTH = 32
        const val DEFAULT_MTU = 1500
        const val DEFAULT_DNS = "1.1.1.1"
    }

    /** The live diversion handle; null while the VPN is not running. */
    @Volatile
    var divert: AnDivert? = null
        private set

    private var tunInterface: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    @Volatile private var running = false

    // ------------------------------------------------------------------
    // Hooks for subclasses
    // ------------------------------------------------------------------

    /** Filter expression passed to `AnDivert.open`. */
    protected open fun divertFilter(): String = "true"

    /** Flags passed to `AnDivert.open`; see `AnDivert.FLAG_*`. */
    protected open fun divertFlags(): Int = 0

    /**
     * Called once per diverted packet on the worker thread. Implementations
     * must either call `divert.send(packet.bytes)` to release the packet or
     * intentionally drop it. Blocking here stalls the diversion loop.
     */
    protected abstract fun onPacket(packet: AnDivert.DivertedPacket, divert: AnDivert)

    /** Called after the TUN is up and the engine attached. */
    protected open fun onDivertStarting(stats: AnDivert) {}

    /** Called after the engine stopped and the TUN was closed. */
    protected open fun onDivertStopped() {}

    /** Virtual interface address, e.g. "10.111.222.1". */
    protected open fun vpnAddress(): String = DEFAULT_ADDRESS

    protected open fun vpnPrefixLength(): Int = DEFAULT_PREFIX_LENGTH

    protected open fun vpnMtu(): Int = DEFAULT_MTU

    protected open fun vpnDns(): String = DEFAULT_DNS

    /**
     * Apps whose traffic is routed into the TUN. Empty means "all apps".
     * Adding package names here is how NetGuard-style per-app firewalls work.
     */
    protected open fun allowedPackages(): List<String> = emptyList()

    /** Apps explicitly excluded from the TUN. Empty means "none excluded". */
    protected open fun disallowedPackages(): List<String> = emptyList()

    // ------------------------------------------------------------------
    // VpnService lifecycle
    // ------------------------------------------------------------------

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    /** Requests a VPN permission intent from an Activity. */
    fun prepareVpnPermission(context: android.content.Context): Intent? =
        VpnService.prepare(context)

    private fun startVpn() {
        if (running) {
            Log.i(TAG, "already running")
            return
        }

        val builder = Builder()
            .setSession("AnDivert")
            .addAddress(vpnAddress(), vpnPrefixLength())
            .addRoute("0.0.0.0", 0)
            .setMtu(vpnMtu())

        vpnDns().takeIf { it.isNotBlank() }?.let {
            builder.addDnsServer(it)
            // keep the DNS server out of the tunnel so lookups work
            builder.addRoute(it, 32)
        }

        // Modern Android wants the app to declare it is not a full VPN unless
        // it really is; we are a transparent pipeline, so allow bypass where
        // the platform supports it.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        allowedPackages().forEach { builder.addAllowedApplication(it) }
        disallowedPackages().forEach { builder.addDisallowedApplication(it) }

        val tun = try {
            builder.establish()
        } catch (t: Throwable) {
            Log.e(TAG, "establish() failed", t)
            null
        }
        if (tun == null) {
            Log.e(TAG, "VPN permission denied or TUN unavailable")
            stopSelf()
            return
        }
        tunInterface = tun

        // Let the native forwarder protect its own sockets via VpnService.protect.
        AnDivertNative.nativeSetVpnService(this)

        val handle = try {
            AnDivert.open(tun.fd, divertFilter(), divertFlags())
        } catch (t: Throwable) {
            Log.e(TAG, "AnDivert.open failed", t)
            closeTun()
            stopSelf()
            return
        }
        divert = handle
        running = true

        startForegroundNotification()
        onDivertStarting(handle)

        worker = Thread({ divertLoop(handle) }, "andivert-worker").also {
            it.start()
        }
    }

    private fun divertLoop(handle: AnDivert) {
        Log.i(TAG, "divert loop started (filter=${handle.filter})")
        while (running) {
            val packet = try {
                handle.recv(timeoutMs = 500)
            } catch (t: Throwable) {
                Log.e(TAG, "recv failed", t)
                null
            }
            if (packet == null) continue
            try {
                onPacket(packet, handle)
            } catch (t: Throwable) {
                // A broken handler must not kill the pipeline; release the
                // packet so traffic keeps flowing.
                Log.e(TAG, "onPacket threw, releasing packet", t)
                runCatching { handle.send(packet.bytes) }
            }
        }
        Log.i(TAG, "divert loop stopped")
    }

    private fun stopVpn() {
        if (!running && divert == null) {
            stopSelf()
            return
        }
        running = false
        worker?.join(2000)
        worker = null

        divert?.let {
            try {
                it.close()
            } catch (t: Throwable) {
                Log.w(TAG, "close failed", t)
            }
        }
        divert = null

        closeTun()
        AnDivertNative.nativeSetVpnService(null)
        stopForegroundCompat()
        onDivertStopped()
        stopSelf()
    }

    private fun closeTun() {
        try {
            tunInterface?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "TUN close failed", t)
        }
        tunInterface = null
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Another VPN app took over, or the user revoked permission.
        Log.w(TAG, "VPN revoked by the system")
        stopVpn()
        super.onRevoke()
    }

    // ------------------------------------------------------------------
    // Foreground notification
    // ------------------------------------------------------------------

    private fun startForegroundNotification() {
        val nm = getSystemService(NotificationManager::class.java)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        "AnDivert",
                        NotificationManager.IMPORTANCE_LOW
                    )
                )
            }
        }

        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("AnDivert active")
            .setContentText("Diverting packets: ${divertFilter()}")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .apply { pending?.let { setContentIntent(it) } }
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }
}
