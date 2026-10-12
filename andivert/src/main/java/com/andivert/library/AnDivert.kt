package com.andivert.library

/**
 * AnDivert — a WinDivert-style packet diversion library for Android.
 *
 * ## How it works
 *
 * WinDivert on Windows installs a kernel driver (WinDivert.sys) that intercepts
 * packets below the network stack. Android gives ordinary apps no such hook, so
 * AnDivert uses the platform-sanctioned equivalent: a TUN interface created by
 * [android.net.VpnService]. Every IP packet routed into the TUN is delivered to
 * user space, where this engine can inspect, filter, drop, modify or re-inject
 * it — the same conceptual model, no root required.
 *
 * ## Mental mapping from WinDivert
 *
 * | WinDivert                     | AnDivert                        |
 * |-------------------------------|---------------------------------|
 * | `WinDivertOpen(filter, ...)`  | [AnDivert.open]                 |
 * | `WinDivertRecv(...)`          | [AnDivert.recv]                 |
 * | `WinDivertSend(...)`          | [AnDivert.send]                 |
 * | `WinDivertClose(...)`         | [AnDivert.close]                |
 * | `WINDIVERT_IPHDR`             | field accessors on [PacketMeta] |
 *
 * ## Typical use
 *
 * ```kotlin
 * // inside your VpnService, once the TUN fd is available:
 * val divert = AnDivert.open(
 *     tunFd = tunInterface.fd,
 *     filter = "outbound and tcp.DstPort == 443"
 * )
 * while (running) {
 *     val packet = divert.recv(timeoutMs = 1000) ?: continue
 *     if (packet.meta.dstPort == 443) {
 *         divert.send(packet.bytes)   // or a modified copy
 *     }
 * }
 * divert.close()
 * ```
 *
 * ## Filter language
 *
 * A practical subset of the WinDivert filter language:
 *
 * ```
 * true | false
 * outbound | inbound
 * ip | ipv4 | ipv6 | tcp | udp | icmp | icmpv6
 * ip.SrcAddr == 10.0.0.1        ip.DstAddr != 8.8.8.8
 * ip.Protocol == 6              ip.TTL > 1
 * tcp.SrcPort == 443            tcp.DstPort >= 1024
 * udp.SrcPort == 53             udp.DstPort == 5353
 * tcp.Syn | tcp.Ack | tcp.Fin | tcp.Rst | tcp.Psh
 * icmp.Type == 8                icmp.Code == 0
 * ```
 * Combined with `and`, `or`, `not` and parentheses, e.g.
 * `outbound and udp and ip.DstAddr == 8.8.8.8`.
 */
class AnDivert private constructor(
    private val handle: Long,
    val filter: String,
    val flags: Int
) : AutoCloseable {

    /** Everything the engine knows about one diverted packet. */
    data class PacketMeta(
        /** true when the packet came from an app (leaving the device). */
        val outbound: Boolean,
        /** IANA protocol number: 6 = TCP, 17 = UDP, 1 = ICMP, 58 = ICMPv6. */
        val protocol: Int,
        /** Source port, or -1 when the protocol has none / packet unparsed. */
        val srcPort: Int,
        val dstPort: Int,
        /** IPv4 source address as a packed int, 0 for IPv6 traffic. */
        val srcAddr: Int,
        val dstAddr: Int
    ) {
        val isTcp get() = protocol == 6
        val isUdp get() = protocol == 17
        val isIcmp get() = protocol == 1
        val isIcmpV6 get() = protocol == 58

        /** Dotted-quad form of [dstAddr] (IPv4 only). */
        fun dstAddressString(): String =
            if (dstAddr == 0) "::" else "${(dstAddr ushr 24) and 0xFF}." +
                "${(dstAddr ushr 16) and 0xFF}." +
                "${(dstAddr ushr 8) and 0xFF}." +
                "${dstAddr and 0xFF}"
    }

    /** One diverted packet plus its metadata. */
    class DivertedPacket(val bytes: ByteArray, val meta: PacketMeta)

    /** Cumulative engine counters. */
    data class Stats(
        val packetsDivered: Long,
        val packetsPassed: Long,
        val packetsDropped: Long,
        val bytesIn: Long,
        val bytesOut: Long,
        val queueLength: Long,
        val queueCapacity: Long
    )

    @Volatile private var closed = false

    /**
     * Blocks up to [timeoutMs] for a packet matching the filter.
     *
     * @return the packet, or `null` if the timeout elapsed. This is the
     *   equivalent of `WinDivertRecv()` returning `ERROR_TIMEOUT`.
     */
    fun recv(timeoutMs: Int = 1000): DivertedPacket? {
        check(!closed) { "AnDivert handle is closed" }
        val meta = IntArray(6)
        val bytes = AnDivertNative.nativeRecv(handle, timeoutMs, meta) ?: return null
        return DivertedPacket(
            bytes,
            PacketMeta(
                outbound = (meta[0] and ADDRESS_FLAG_OUTBOUND) != 0,
                protocol = meta[1],
                srcPort = meta[2],
                dstPort = meta[3],
                srcAddr = meta[4],
                dstAddr = meta[5]
            )
        )
    }

    /**
     * Re-injects a packet into the network stack — the equivalent of
     * `WinDivertSend()`. Pass the original bytes to release a diverted packet,
     * or a modified copy (after fixing checksums) to rewrite it.
     *
     * @return true when the whole packet was written.
     */
    fun send(packet: ByteArray): Boolean {
        check(!closed) { "AnDivert handle is closed" }
        return AnDivertNative.nativeSend(handle, packet) == 0
    }

    fun stats(): Stats {
        val raw = AnDivertNative.nativeGetStats(handle) ?: LongArray(7)
        return Stats(raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6])
    }

    /** Last error code from the native engine; see [AnDivert.errorString]. */
    val lastError: Int get() = AnDivertNative.nativeLastError()

    override fun close() {
        if (!closed) {
            closed = true
            AnDivertNative.nativeClose(handle)
        }
    }

    companion object {
        /** Packet originated on this device. */
        const val ADDRESS_FLAG_OUTBOUND = 0x01

        /** Packet is destined to this device. */
        const val ADDRESS_FLAG_INBOUND = 0x02

        /** Layer constants, matching `AN_LAYER_*` in `andivert.h`. */
        const val LAYER_NETWORK = 0

        /**
         * Observe matching packets but let them continue unmodified
         * (mirrors `WINDIVERT_FLAG_SNIFF`).
         */
        const val FLAG_SNIFF = 0x0001

        /**
         * Drop every matching packet without delivering it
         * (mirrors `WINDIVERT_FLAG_DROP`).
         */
        const val FLAG_DROP = 0x0002

        /** Receive only; never re-inject. */
        const val FLAG_READONLY = 0x0004

        /**
         * Attaches the engine to an already-created TUN file descriptor.
         *
         * This is the `WinDivertOpen()` equivalent. The descriptor normally
         * comes from `VpnService.Builder.establish().fd`, which is why
         * [AnDivertVpnService] exists — it owns the VPN lifecycle for you.
         *
         * @param tunFd the TUN file descriptor to divert from.
         * @param filter AnDivert filter expression; `null` or `"true"` matches
         *   everything. A malformed filter fails here (never silently).
         * @param flags combination of [FLAG_SNIFF], [FLAG_DROP], [FLAG_READONLY].
         * @throws IllegalArgumentException when the filter does not compile.
         */
        fun open(
            tunFd: Int,
            filter: String? = null,
            flags: Int = 0,
            priority: Int = 0,
            layer: Int = LAYER_NETWORK
        ): AnDivert {
            val handle = AnDivertNative.nativeOpen(
                tunFd, filter, layer, priority, flags.toLong()
            )
            require(handle != 0L) {
                val err = AnDivertNative.nativeLastError()
                "AnDivert.open failed: ${AnDivertNative.nativeStrError(err)}" +
                    (if (AnDivertNative.nativeFilterError().isNotBlank())
                        " (${AnDivertNative.nativeFilterError()})" else "")
            }
            return AnDivert(handle, filter ?: "true", flags)
        }

        /**
         * Compiles [filter] without opening a handle. Useful for validating
         * user input in a settings screen.
         */
        fun isValidFilter(filter: String?): Boolean =
            AnDivertNative.nativeValidateFilter(filter)

        /** Human-readable reason the last filter failed to compile. */
        fun filterError(): String = AnDivertNative.nativeFilterError()

        fun errorString(err: Int): String = AnDivertNative.nativeStrError(err)

        fun version(): String = AnDivertNative.nativeVersion()
    }
}
