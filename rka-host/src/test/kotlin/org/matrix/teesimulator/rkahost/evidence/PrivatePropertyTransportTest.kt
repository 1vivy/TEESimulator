package org.matrix.teesimulator.rkahost.evidence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.matrix.teesimulator.rkahost.cli.RootPrivateInput

class PrivatePropertyTransportTest {
    @Test
    fun syntheticAllowlistDrivesCommandPolicyValidationAndPrivateInputOnce() {
        val allowlist = PropertyAllowlist.parse(listOf("synthetic.beta", "synthetic.alpha"))
        val calls = mutableListOf<List<String>>()
        val policy =
            AdbCommandPolicy(
                LiteralCommandRunner {
                    calls += it
                    CommandResult(0, "value")
                },
                allowlist,
            )

        policy.execute(listOf("adb", "-s", "serial", "shell", "getprop", "synthetic.alpha"))

        assertEquals(1, calls.size)
        assertEquals(
            RootPrivateInput.parse(listOf("synthetic.alpha", "synthetic.beta")),
            allowlist.privateInput(),
        )
    }

    @Test
    fun duplicateMalformedAndOversizedPrivateKeysAreRejectedAtTypedBoundary() {
        assertThrows(IllegalArgumentException::class.java) {
            PropertyAllowlist.parse(listOf("synthetic.alpha", "synthetic.alpha"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            PropertyAllowlist.parse(listOf("not a key"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            PropertyAllowlist.parse((1..17).map { "synthetic.$it" })
        }
    }
}
