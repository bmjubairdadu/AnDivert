package com.andivert.library

/**
 * Native bindings for the AnDivert engine.
 *
 * This object mirrors the C API in [andivert.h]. Most developers should use
 * [AnDivert] or [AnDivertVpnService] instead of calling this directly.
 */
internal object AnDivertNative {

    init {
        System.loadLibrary("andivert")
    }

    /** Registers the VpnService instance used to protect upstream sockets. */
    external fun nativeSetVpnService(vpnService: android.net.VpnService?)

    external fun nativeOpen(tunFd: Int, filter: String?, layer: Int,
                            priority: Int, flags: Long): Long

    external fun nativeClose(handle: Long)

    /**
     * Blocks up to [timeoutMs] for one diverted packet.
     * Returns the raw IP packet, or null on timeout.
     * [meta] (int[6]) receives: flags, protocol, sport, dport, srcAddr, dstAddr.
     */
    external fun nativeRecv(handle: Long, timeoutMs: Int, meta: IntArray): ByteArray?

    external fun nativeSend(handle: Long, packet: ByteArray): Int

    /** long[7]: diverted, passed, dropped, bytesIn, bytesOut, queueLen, queueMax */
    external fun nativeGetStats(handle: Long): LongArray?

    external fun nativeLastError(): Int
    external fun nativeStrError(err: Int): String

    /** Compiles [filter] and returns whether it is syntactically valid. */
    external fun nativeValidateFilter(filter: String?): Boolean
    external fun nativeFilterError(): String

    external fun nativeVersion(): String
}
