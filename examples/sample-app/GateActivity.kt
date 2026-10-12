package com.example.andivertgate

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.andivert.library.AnDivert
import com.andivert.library.AnDivertVpnService

/**
 * A complete, minimal AnDivert consumer: a foreground service that logs every
 * DNS (UDP:53) query leaving the device — and could block or rewrite it.
 *
 * This file is the entire integration surface a developer needs to write.
 */
class GateActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "AndivertGate"
        private const val REQUEST_VPN = 1
    }

    /** The whole service: pick a filter, handle diverted packets. */
    class Gate : AnDivertVpnService() {
        override fun divertFilter(): String = "outbound and udp.DstPort == 53"

        override fun onPacket(packet: AnDivert.DivertedPacket, divert: AnDivert) {
            Log.i(TAG, "DNS query -> ${packet.meta.dstAddressString()}")
            // Release the packet unchanged so it reaches the network:
            divert.send(packet.bytes)
            // To BLOCK it, just do not call send().
            // To MODIFY it, edit packet.bytes (fix checksums!) then send.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(Button(this@GateActivity).apply {
                text = "Start DNS logger"
                setOnClickListener { startGate() }
            })
            addView(Button(this@GateActivity).apply {
                text = "Stop"
                setOnClickListener {
                    startService(
                        Intent(this@GateActivity, Gate::class.java)
                            .setAction(AnDivertVpnService.ACTION_STOP)
                    )
                }
            })
        })
    }

    private fun startGate() {
        // System VPN consent dialog (first time only).
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, REQUEST_VPN)
            return
        }
        actuallyStart()
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        if (req == REQUEST_VPN && res == RESULT_OK) actuallyStart()
    }

    private fun actuallyStart() {
        startForegroundService(
            Intent(this, Gate::class.java)
                .setAction(AnDivertVpnService.ACTION_START)
        )
        Toast.makeText(this, "Gate started", Toast.LENGTH_SHORT).show()
    }
}
