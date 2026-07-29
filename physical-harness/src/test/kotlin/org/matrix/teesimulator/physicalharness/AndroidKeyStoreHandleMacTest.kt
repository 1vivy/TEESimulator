package org.matrix.teesimulator.physicalharness

import java.security.Key
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidKeyStoreHandleMacTest {
    @Test
    fun existenceProbeOnlyChecksTheFixedAlias() {
        val missing = FakeHandleMacBackend(aliasPresent = false)
        val existing = FakeHandleMacBackend(aliasPresent = true)

        assertFalse(AndroidKeyStoreHandleMac.exists(missing))
        assertTrue(AndroidKeyStoreHandleMac.exists(existing))
        assertEquals(listOf("contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}"), missing.calls)
        assertEquals(listOf("contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}"), existing.calls)
    }

    @Test
    fun createAndOpenAreDistinctAndRejectAmbiguousBootstrapStates() {
        val existing = FakeHandleMacBackend(aliasPresent = true)
        assertFailsWith<AndroidKeyStoreHandleMacException.AliasAlreadyExists> {
            AndroidKeyStoreHandleMac.createNew(existing)
        }
        assertEquals(listOf("contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}"), existing.calls)

        val missing = FakeHandleMacBackend(aliasPresent = false)
        assertFailsWith<AndroidKeyStoreHandleMacException.KeyNotFound> {
            AndroidKeyStoreHandleMac.openExisting(missing)
        }
        assertEquals(listOf("contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}"), missing.calls)
    }

    @Test
    fun createGeneratesThenReloadsOnlyTheFixedNonExportableTeeHmacKey() {
        val backend = FakeHandleMacBackend(aliasPresent = false)

        val mac = AndroidKeyStoreHandleMac.createNew(backend)
        val output = mac.sign(byteArrayOf(1, 2, 3))

        assertEquals(
            listOf(
                "contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}",
                "generate:${AndroidKeyStoreHandleMac.KEY_ALIAS}",
                "load:${AndroidKeyStoreHandleMac.KEY_ALIAS}",
                "security",
                "sign",
            ),
            backend.calls,
        )
        assertContentEquals(
            MessageDigest.getInstance("SHA-256").digest(byteArrayOf(1, 2, 3)),
            output,
        )
        assertContentEquals(byteArrayOf(1, 2, 3), backend.signedInputs.single())
    }

    @Test
    fun openReloadsWithoutGenerating() {
        val backend = FakeHandleMacBackend(aliasPresent = true)

        AndroidKeyStoreHandleMac.openExisting(backend)

        assertEquals(
            listOf(
                "contains:${AndroidKeyStoreHandleMac.KEY_ALIAS}",
                "load:${AndroidKeyStoreHandleMac.KEY_ALIAS}",
                "security",
            ),
            backend.calls,
        )
    }

    @Test
    fun synchronizedCreateAllowsExactlyOneWinner() {
        val backend = FakeHandleMacBackend(aliasPresent = false)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val attempts =
                List(2) {
                    executor.submit<Throwable?> {
                        start.await()
                        runCatching { AndroidKeyStoreHandleMac.createNew(backend) }
                            .exceptionOrNull()
                    }
                }
            start.countDown()

            val failures = attempts.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, failures.count { it == null })
            assertEquals(
                1,
                failures.count { it is AndroidKeyStoreHandleMacException.AliasAlreadyExists },
            )
            assertEquals(1, backend.generateCount)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun rejectsMissingWrongTypeWrongAlgorithmAndExportableEntries() {
        assertFailsWith<AndroidKeyStoreHandleMacException.KeyNotFound> {
            AndroidKeyStoreHandleMac.openExisting(
                FakeHandleMacBackend(aliasPresent = true, key = null)
            )
        }
        assertFailsWith<AndroidKeyStoreHandleMacException.WrongKeyType> {
            AndroidKeyStoreHandleMac.openExisting(
                FakeHandleMacBackend(aliasPresent = true, key = NonSecretKey)
            )
        }
        assertFailsWith<AndroidKeyStoreHandleMacException.WrongKeyType> {
            AndroidKeyStoreHandleMac.openExisting(
                FakeHandleMacBackend(aliasPresent = true, key = NonExportableSecretKey("AES"))
            )
        }
        assertFailsWith<AndroidKeyStoreHandleMacException.ExportableKey> {
            AndroidKeyStoreHandleMac.openExisting(
                FakeHandleMacBackend(
                    aliasPresent = true,
                    key = SecretKeySpec(ByteArray(32), "HmacSHA256"),
                )
            )
        }
    }

    @Test
    fun acceptsOnlyTrustedEnvironmentSecurityLevel() {
        listOf(
                BackendSecurityLevel.SOFTWARE,
                BackendSecurityLevel.STRONGBOX,
                BackendSecurityLevel.UNKNOWN,
            )
            .forEach { rejectedLevel ->
                assertFailsWith<AndroidKeyStoreHandleMacException.UntrustedSecurityLevel> {
                    AndroidKeyStoreHandleMac.openExisting(
                        FakeHandleMacBackend(aliasPresent = true, securityLevel = rejectedLevel)
                    )
                }
            }

        AndroidKeyStoreHandleMac.openExisting(
            FakeHandleMacBackend(
                aliasPresent = true,
                securityLevel = BackendSecurityLevel.TRUSTED_ENVIRONMENT,
            )
        )
    }

    @Test
    fun failedCreationDeletesTheRejectedEntry() {
        val backend =
            FakeHandleMacBackend(
                aliasPresent = false,
                securityLevel = BackendSecurityLevel.SOFTWARE,
            )

        assertFailsWith<AndroidKeyStoreHandleMacException.UntrustedSecurityLevel> {
            AndroidKeyStoreHandleMac.createNew(backend)
        }

        assertFalse(backend.aliasPresent)
        assertEquals(1, backend.deleteCount)
    }

    @Test
    fun bootstrapRollbackDeletesOnlyThroughTheCreatedHandle() {
        val backend = FakeHandleMacBackend(aliasPresent = false)
        val created = AndroidKeyStoreHandleMac.createNew(backend)
        backend.calls.clear()

        created.deleteForBootstrapRollback()

        assertFalse(backend.aliasPresent)
        assertEquals(listOf("delete:${AndroidKeyStoreHandleMac.KEY_ALIAS}"), backend.calls)
    }

    @Test
    fun bootstrapRollbackCannotDeleteAPreExistingMac() {
        val backend = FakeHandleMacBackend(aliasPresent = true)
        val existing = AndroidKeyStoreHandleMac.openExisting(backend)
        backend.calls.clear()

        assertFailsWith<IllegalStateException> { existing.deleteForBootstrapRollback() }

        assertTrue(backend.aliasPresent)
        assertTrue(backend.calls.isEmpty())
    }

    @Test
    fun authenticatorExceptionMessagesContainNoKeyOrInputMaterial() {
        val backendFailure = IllegalStateException("synthetic")
        val exceptions =
            listOf(
                AndroidKeyStoreHandleMacException.AliasAlreadyExists(),
                AndroidKeyStoreHandleMacException.KeyNotFound(),
                AndroidKeyStoreHandleMacException.WrongKeyType(),
                AndroidKeyStoreHandleMacException.ExportableKey(),
                AndroidKeyStoreHandleMacException.UntrustedSecurityLevel(),
                AndroidKeyStoreHandleMacException.BackendFailure(backendFailure),
                HandleAuthenticatorException.InvalidSessionId(),
                HandleAuthenticatorException.InvalidMacOutput(),
            )

        exceptions.forEach { exception ->
            assertFalse(exception.message.orEmpty().contains("010203"))
            assertFalse(exception.message.orEmpty().contains("secret"))
        }
        assertIs<AndroidKeyStoreHandleMacException.BackendFailure>(exceptions[5])
        assertEquals(backendFailure, exceptions[5].cause)
        assertNull(exceptions[0].cause)
    }
}

private class FakeHandleMacBackend(
    @Volatile var aliasPresent: Boolean,
    var key: Key? = NonExportableSecretKey(),
    var securityLevel: BackendSecurityLevel = BackendSecurityLevel.TRUSTED_ENVIRONMENT,
) : AndroidKeyStoreHandleMacBackend {
    val calls = mutableListOf<String>()
    val signedInputs = mutableListOf<ByteArray>()
    var generateCount = 0
    var deleteCount = 0

    override fun containsAlias(alias: String): Boolean {
        calls += "contains:$alias"
        return aliasPresent
    }

    override fun generate(alias: String) {
        calls += "generate:$alias"
        generateCount += 1
        aliasPresent = true
    }

    override fun load(alias: String): Key? {
        calls += "load:$alias"
        return key
    }

    override fun securityLevel(secretKey: SecretKey): BackendSecurityLevel {
        calls += "security"
        return securityLevel
    }

    override fun sign(secretKey: SecretKey, input: ByteArray): ByteArray {
        calls += "sign"
        signedInputs += input.copyOf()
        return MessageDigest.getInstance("SHA-256").digest(input)
    }

    override fun delete(alias: String) {
        calls += "delete:$alias"
        deleteCount += 1
        aliasPresent = false
    }
}

private class NonExportableSecretKey(private val algorithm: String = "HmacSHA256") : SecretKey {
    override fun getAlgorithm(): String = algorithm

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null
}

private data object NonSecretKey : Key {
    override fun getAlgorithm() = "HmacSHA256"

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null
}
