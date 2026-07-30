package org.matrix.TEESimulator.interception.keystore

import android.os.IBinder
import android.system.keystore2.IKeystoreSecurityLevel

internal fun interface RegisteredSecurityLevel {
    fun loadPersistedKeys()
}

internal fun interface SecurityLevelRegistrar {
    fun register(
        backdoor: IBinder,
        securityLevel: IKeystoreSecurityLevel,
        level: Int,
    ): RegisteredSecurityLevel
}
