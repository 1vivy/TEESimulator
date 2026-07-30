package org.matrix.teesimulator.rkahost

import org.junit.Assert.assertNotNull
import org.junit.Test

class AdapterRedContractTest {
    @Test
    fun adapterContractExists() {
        assertNotNull(Class.forName("org.matrix.teesimulator.rkahost.UsbHostRelayTransport"))
        assertNotNull(Class.forName("org.matrix.teesimulator.rkahost.DeviceSerial"))
    }
}
