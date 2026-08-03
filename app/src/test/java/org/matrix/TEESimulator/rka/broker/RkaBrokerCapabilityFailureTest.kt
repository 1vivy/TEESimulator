package org.matrix.TEESimulator.rka.broker

import android.os.ServiceSpecificException
import java.io.Serializable
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RkaBrokerCapabilityFailureTest {
    @Test
    fun versionThreeIgnoresTheDeprecatedEekCurveField() {
        val endpoint = FakeIrpcEndpoint(supportedEekCurve = 0)

        assertTrue(inspect(FakeResolver(irpc = endpoint)) is BrokerOutcome.Success)
        assertTrue(
            IrpcClient(FakeResolver(irpc = endpoint), DirectCallRunner)
                .resolveIdentity(BrokerDeadline.at(5_000), BrokerCancellation.active()) is
                BrokerOutcome.Success
        )
    }

    @Test
    fun missingServiceIsTypedAndNeverFallsBack() {
        val resolver = FakeResolver(irpcFailure = MissingBrokerService)
        val outcome = inspect(resolver)

        assertEquals(
            BrokerError.ServiceMissing(BrokerServiceKind.IRPC),
            (outcome as BrokerOutcome.Failure).error,
        )
        assertEquals(listOf(IrpcClient.DEFAULT_TEE_SERVICE), resolver.irpcNames)
        assertTrue(resolver.keyMintNames.isEmpty())
    }

    @Test
    fun accessDeniedIsTypedWithoutLeakingPlatformMessage() {
        val resolver = FakeResolver(irpcFailure = SecurityException("selinux secret path"))
        val failure = inspect(resolver) as BrokerOutcome.Failure

        assertEquals(BrokerError.AccessDenied(BrokerServiceKind.IRPC), failure.error)
        assertFalse(failure.toString().contains("secret"))
        assertEquals("AccessDenied(service=IRPC)", failure.error.toString())
    }

    @Test
    fun serviceSpecificCodesMapExhaustivelyAndRedactMessages() {
        val known =
            FakeResolver(irpcFailure = ServiceSpecificException(2, "opaque key blob 010203"))
        val oem = FakeResolver(irpcFailure = ServiceSpecificException(9_001, "vendor secret"))

        assertEquals(
            BrokerError.ServiceRejected(
                BrokerServiceKind.IRPC,
                BrokerServiceFailure.IrpcInvalidMac,
            ),
            (inspect(known) as BrokerOutcome.Failure).error,
        )
        val oemError = (inspect(oem) as BrokerOutcome.Failure).error
        assertEquals(
            BrokerError.ServiceRejected(BrokerServiceKind.IRPC, BrokerServiceFailure.Oem(9_001)),
            oemError,
        )
        assertFalse(oemError.toString().contains("vendor"))

        val removed = FakeResolver(irpcFailure = ServiceSpecificException(6, "removed detail"))
        assertEquals(
            BrokerError.ServiceRejected(BrokerServiceKind.IRPC, BrokerServiceFailure.IrpcRemoved),
            (inspect(removed) as BrokerOutcome.Failure).error,
        )
    }

    @Test
    fun keyMintFailuresUseTheKeyMintTypedDomain() {
        val denied = FakeResolver(keyMintFailure = SecurityException("selinux detail"))
        val rejected = FakeResolver(keyMintFailure = ServiceSpecificException(-38, "blob detail"))

        assertEquals(
            BrokerError.AccessDenied(BrokerServiceKind.KEYMINT),
            (inspect(denied) as BrokerOutcome.Failure).error,
        )
        assertEquals(
            BrokerError.ServiceRejected(BrokerServiceKind.KEYMINT, BrokerServiceFailure.Oem(-38)),
            (inspect(rejected) as BrokerOutcome.Failure).error,
        )
    }

    @Test
    fun cancellationDeadlineAndDeathAreDistinctTypedFailures() {
        val cancelled =
            BrokerCapability.forResolver(FakeResolver(), DirectCallRunner)
                .inspect(
                    BrokerCaller.external(10_042, 0),
                    BrokerDeadline.at(5_000),
                    BrokerCancellation.cancelled(),
                )
        val timeout =
            BrokerCapability.forResolver(FakeResolver(), DirectCallRunner)
                .inspect(
                    BrokerCaller.external(10_042, 0),
                    BrokerDeadline.at(0),
                    BrokerCancellation.active(),
                )
        val dead = inspect(FakeResolver(irpc = FakeIrpcEndpoint(alive = AtomicBoolean(false))))

        assertEquals(BrokerError.Cancelled, (cancelled as BrokerOutcome.Failure).error)
        assertEquals(BrokerError.DeadlineExceeded, (timeout as BrokerOutcome.Failure).error)
        assertEquals(
            BrokerError.ServiceDead(BrokerServiceKind.IRPC),
            (dead as BrokerOutcome.Failure).error,
        )
    }

    @Test
    fun inFlightCancellationInterruptsTheBoundedCall() {
        val entered = CountDownLatch(1)
        val blocked = CountDownLatch(1)
        val cancellation = BrokerCancellation.active()
        val canceller =
            Thread {
                    entered.await()
                    cancellation.cancel()
                }
                .apply { start() }

        val outcome =
            ExecutorBrokerCallRunner().run(
                BrokerServiceKind.IRPC,
                BrokerDeadline.at(5_000),
                cancellation,
            ) {
                entered.countDown()
                blocked.await()
            }

        canceller.join()
        assertEquals(BrokerError.Cancelled, (outcome as BrokerOutcome.Failure).error)
    }

    @Test
    fun deathDuringAnIrpcOperationDiscardsTheResult() {
        val alive = AtomicBoolean(true)
        val client =
            IrpcClient(
                FakeResolver(irpc = FakeIrpcEndpoint(alive = alive, dieOnGenerate = true)),
                DirectCallRunner,
            )

        val outcome =
            client.generateKeyBatch(
                RkpKeyCount.parse(1).success(),
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            )

        assertEquals(
            BrokerError.ServiceDead(BrokerServiceKind.IRPC),
            (outcome as BrokerOutcome.Failure).error,
        )
    }

    @Test
    fun saturatedCallRunnerFailsWithTypedCapacity() {
        val executor = Executors.newSingleThreadExecutor()
        executor.shutdown()

        val outcome =
            ExecutorBrokerCallRunner(executor).run(
                BrokerServiceKind.IRPC,
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            ) {}

        assertEquals(
            BrokerError.Capacity(BrokerServiceKind.IRPC),
            (outcome as BrokerOutcome.Failure).error,
        )
    }

    @Test
    fun publicSurfaceContainsNoBinderParcelBlobOrSerializableTypes() {
        val publicTypes =
            listOf(
                BrokerCapability::class.java,
                BrokerCapabilityReport::class.java,
                IrpcCapability::class.java,
                KeyMintCapability::class.java,
                AttestationChallenge::class.java,
                RkpKeyCount::class.java,
                IrpcKeyBatch::class.java,
                BrokerError::class.java,
            )
        val forbidden = Regex("(IBinder|Binder|Parcel|Parcelable|KeyBlob|ServiceEndpoint)")

        publicTypes.forEach { type ->
            assertFalse(
                "${type.name} is serializable",
                Serializable::class.java.isAssignableFrom(type),
            )
            type.methods
                .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) }
                .forEach { method ->
                    val signature =
                        buildList {
                                add(method.returnType.name)
                                method.parameterTypes.mapTo(this) { it.name }
                            }
                            .joinToString()
                    assertFalse(
                        "${type.name}.${method.name}: $signature",
                        forbidden.containsMatchIn(signature),
                    )
                }
        }
    }

    @Test
    fun brokerSourcesCannotActivateLegacyInterceptors() {
        val root = Path.of(System.getProperty("user.dir"))
        val brokerRoot = root.resolve("src/main/java/org/matrix/TEESimulator/rka/broker")
        val source =
            Files.walk(brokerRoot).use { paths ->
                paths
                    .filter { it.toString().endsWith(".kt") }
                    .map { path -> String(Files.readAllBytes(path), Charsets.UTF_8) }
                    .toList()
                    .joinToString("\n")
            }

        assertFalse(source.contains("interception."))
        assertFalse(source.contains("Keystore2Interceptor"))
        assertFalse(source.contains("KeystoreInterceptor"))
    }

    private fun inspect(resolver: FakeResolver): BrokerOutcome<BrokerCapabilityReport> =
        BrokerCapability.forResolver(resolver, DirectCallRunner)
            .inspect(
                BrokerCaller.external(10_042, 0),
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            )

    private fun <T> BrokerOutcome<T>.success(): T = (this as BrokerOutcome.Success).value
}
