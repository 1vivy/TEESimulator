package org.matrix.TEESimulator.rka.broker

import java.lang.reflect.Method
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ProvisioningSnapshotWriteGuardTest {
    @Test
    fun boundaryExposesNoWriteOrMutableProviderSurface() {
        val sourceMethods = ProvisioningObservationSource::class.java.methods.toList()
        val snapshotMethods = ProvisioningSnapshot::class.java.methods.toList()

        assertEquals(12, sourceMethods.count { it.isObservationGetter() })
        assertFalse(sourceMethods.any { it.isWriteSurface() })
        assertFalse(snapshotMethods.any { it.isWriteSurface() })
    }

    private fun Method.isObservationGetter() =
        parameterCount == 0 &&
            name.startsWith("get") &&
            declaringClass == ProvisioningObservationSource::class.java

    private fun Method.isWriteSurface() =
        name.startsWith("set") ||
            name.contains("write", ignoreCase = true) ||
            name.contains("provider", ignoreCase = true) ||
            name.contains("client", ignoreCase = true)
}
