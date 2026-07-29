package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertFailsWith
import org.matrix.teesimulator.twophone.SpkiPin

class PinnedJsseServerContextTest {
    @Test
    fun validatesConfiguredAliasAndExactDonorPin() {
        val pki = TlsTestPki()
        val root = pki.root("server-root")
        val selected = pki.leaf("selected", root, server = true)
        val decoy = pki.leaf("decoy", root, server = true)
        val keys = pki.keyStore("selected" to selected, "decoy" to decoy)
        val trust = pki.trustStore(pki.root("client-root"))

        PinnedJsseServerContext.create(
            keys,
            "selected",
            TlsTestPki.PASSWORD,
            SpkiPin.from(selected.certificate),
            trust,
        )
        assertFailsWith<PinnedJsseContextException.InvalidIdentity> {
            PinnedJsseServerContext.create(
                keys,
                "selected",
                TlsTestPki.PASSWORD,
                SpkiPin.from(decoy.certificate),
                trust,
            )
        }
        assertFailsWith<PinnedJsseContextException.InvalidIdentity> {
            PinnedJsseServerContext.create(
                keys,
                "missing",
                TlsTestPki.PASSWORD,
                SpkiPin.from(selected.certificate),
                trust,
            )
        }
    }
}
