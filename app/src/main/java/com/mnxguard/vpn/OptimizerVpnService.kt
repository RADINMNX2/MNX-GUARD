package com.mnxguard.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The local DNS optimizer.
 *
 * It is a [VpnService] because that is the only way an app can see another
 * app's DNS traffic without root, but it is deliberately NOT a VPN: there is no
 * remote gateway, no encryption and no route for general traffic. The only
 * route installed is a single /32 for the virtual resolver address below, so
 * ordinary TCP/UDP keeps using the physical link at full speed. Queries aimed
 * at the carrier's resolver instead land here and are answered through the
 * fastest public resolver — which is the real, measurable win available to a
 * non-root app.
 *
 * Jitter of an existing flow cannot be reduced locally (that is an upstream
 * path property); the quality meter in the UI reports it honestly rather than
 * pretending to fix it.
 */
class OptimizerVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.mnxguard.vpn.optimizer.START"
        const val ACTION_STOP = "com.mnxguard.vpn.optimizer.STOP"
        const val EXTRA_RESOLVER = "optimizer_resolver"

        const val PREFS = "mnx_settings"
        const val PREF_RESOLVER = "optimizer_resolver"

        const val CHANNEL_ID = "mnx_optimizer"
        const val NOTIF_ID = 0x4D58

        /** Set while the TUN is up, so the UI can reflect the real state. */
        @Volatile
        var active: Boolean = false
            private set

        private const val TAG = "OptimizerVpn"
        private const val VIRT_DNS = "10.111.222.1"
        private const val VIRT_CLIENT = "10.111.222.2"
        private const val DEFAULT_RESOLVER = "1.1.1.1"
        private const val MAX_PACKET = 32767
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val stopping = AtomicBoolean(false)

    @Volatile
    private var upstream: InetAddress = InetAddress.getByName(DEFAULT_RESOLVER)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val requested = intent.getStringExtra(EXTRA_RESOLVER)
                upstream = resolveUpstream(requested)
                startForegroundCompat()
                startRelay()
            }
        }
        return START_STICKY
    }

    private fun resolveUpstream(requested: String?): InetAddress {
        val host = requested?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_RESOLVER
        return runCatching { InetAddress.getByName(host) }.getOrNull()
            ?: InetAddress.getByName(DEFAULT_RESOLVER)
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        "Optimizer",
                        NotificationManager.IMPORTANCE_LOW,
                    ),
                )
            }
        }
    }

    private fun startForegroundCompat() {
        ensureChannel()
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MNX Optimizer")
            .setContentText("DNS optimizer is active")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun startRelay() {
        stopRelay()
        stopping.set(false)
        val established = runCatching {
            Builder()
                .setSession("MNX OPTIMIZER")
                .addAddress(VIRT_CLIENT, 32)
                .addDnsServer(VIRT_DNS)
                .addRoute(VIRT_DNS, 32)
                .establish()
        }.getOrNull()
        if (established == null) {
            Log.w(TAG, "could not establish the optimizer interface")
            active = false
            stopSelf()
            return
        }
        tun = established
        active = true
        worker = thread(name = "mnx-optimizer", isDaemon = true) { pump(established) }
    }

    private fun stopRelay() {
        stopping.set(true)
        active = false
        worker?.interrupt()
        worker = null
        runCatching { tun?.close() }
        tun = null
    }

    private fun pump(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET)
        try {
            while (!stopping.get()) {
                val length = input.read(buffer)
                if (length <= 0) break
                val reply = handleQuery(buffer, length) ?: continue
                output.write(reply)
            }
        } catch (_: Exception) {
            // Closing the descriptor on stop surfaces as an IOException here.
        }
    }

    /**
     * Turns one IPv4/UDP packet aimed at [VIRT_DNS]:53 into a reply packet, or
     * returns null when the packet is anything else (which then simply is not
     * answered; the system resolver retries over the carrier path).
     */
    private fun handleQuery(packet: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        if ((packet[0].toInt() and 0xF0) ushr 4 != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) return null
        if ((packet[9].toInt() and 0xFF) != 17) return null

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        if (dstPort != 53) return null

        val payloadOffset = ihl + 8
        val payloadLength = length - payloadOffset
        if (payloadLength <= 0) return null

        val query = packet.copyOfRange(payloadOffset, length)
        val answer = exchange(query) ?: return null
        return buildReply(srcIp, dstIp, srcPort, answer)
    }

    /** Sends the DNS payload to the chosen upstream and returns the raw reply. */
    private fun exchange(query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        return try {
            protect(socket)
            socket.soTimeout = 4000
            socket.send(DatagramPacket(query, query.size, upstream, 53))
            val replyBuffer = ByteArray(4096)
            val reply = DatagramPacket(replyBuffer, replyBuffer.size)
            socket.receive(reply)
            replyBuffer.copyOfRange(0, reply.length)
        } catch (_: Exception) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    /**
     * Builds the IPv4/UDP packet that carries [answer] back to the app, with the
     * addresses and ports swapped relative to the query.
     */
    private fun buildReply(
        clientIp: ByteArray,
        serverIp: ByteArray,
        clientPort: Int,
        answer: ByteArray,
    ): ByteArray {
        val total = 20 + 8 + answer.size
        val out = ByteArray(total)

        out[0] = 0x45
        out[1] = 0
        out[2] = ((total shr 8) and 0xFF).toByte()
        out[3] = (total and 0xFF).toByte()
        out[4] = 0
        out[5] = 0
        out[6] = 0x40 // don't fragment
        out[7] = 0
        out[8] = 64 // TTL
        out[9] = 17 // UDP
        // bytes 10..11 checksum, filled below
        // Source is the virtual resolver, destination is the client.
        System.arraycopy(serverIp, 0, out, 12, 4)
        System.arraycopy(clientIp, 0, out, 16, 4)
        val headerChecksum = checksum(out, 0, 20)
        out[10] = ((headerChecksum shr 8) and 0xFF).toByte()
        out[11] = (headerChecksum and 0xFF).toByte()

        val udpLength = 8 + answer.size
        out[20] = ((53 shr 8) and 0xFF).toByte()
        out[21] = (53 and 0xFF).toByte()
        out[22] = ((clientPort shr 8) and 0xFF).toByte()
        out[23] = (clientPort and 0xFF).toByte()
        out[24] = ((udpLength shr 8) and 0xFF).toByte()
        out[25] = (udpLength and 0xFF).toByte()
        out[26] = 0
        out[27] = 0
        System.arraycopy(answer, 0, out, 28, answer.size)

        val udpChecksum = udpChecksum(out, 12, 16, 28, udpLength)
        out[26] = ((udpChecksum shr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()
        return out
    }

    /** Standard one's-complement checksum over a byte range. */
    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (data[index].toInt() and 0xFF) shl 8
        return fold(sum)
    }

    /** UDP checksum including the IPv4 pseudo-header. */
    private fun udpChecksum(
        packet: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((packet[srcOffset + i].toInt() and 0xFF) shl 8) or
                (packet[srcOffset + i + 1].toInt() and 0xFF)
            sum += ((packet[dstOffset + i].toInt() and 0xFF) shl 8) or
                (packet[dstOffset + i + 1].toInt() and 0xFF)
        }
        sum += 17
        sum += udpLength
        var index = udpOffset
        val end = udpOffset + udpLength
        while (index + 1 < end) {
            sum += ((packet[index].toInt() and 0xFF) shl 8) or (packet[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (packet[index].toInt() and 0xFF) shl 8
        val folded = fold(sum)
        return if (folded == 0) 0xFFFF else folded
    }

    private fun fold(sum: Int): Int {
        var value = sum
        while (value shr 16 != 0) value = (value and 0xFFFF) + (value shr 16)
        return value.inv() and 0xFFFF
    }

    override fun onRevoke() {
        stopSelf()
    }

    override fun onDestroy() {
        stopRelay()
        super.onDestroy()
    }
}
