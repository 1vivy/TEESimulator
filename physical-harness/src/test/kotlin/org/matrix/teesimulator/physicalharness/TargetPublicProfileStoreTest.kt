package org.matrix.teesimulator.physicalharness

import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.PublicProfileException
import org.matrix.teesimulator.twophone.PublicProfileField

class TargetPublicProfileStoreTest {
    private val directory = createTempDirectory("target-public-profile").toFile()
    private val facade = FakePublicProfileAtomicFileFacade(directory)
    private val fixture = PublicProfileStoreFixture()
    private val store = TargetPublicProfileStore(fixture.fixtureIdentity, facade)

    @AfterTest
    fun cleanUp() {
        directory.deleteRecursively()
    }

    @Test
    fun rootStoreUsesTheRequiredPathOwnerAndMode() {
        assertEquals(
            "/data/adb/tricky_store/two-phone-target-v1.bin",
            TargetPublicProfileStore.FILE_PATH,
        )
        assertEquals(0, TargetPublicProfileStore.REQUIRED_UID)
        assertEquals(0x180, TargetPublicProfileStore.REQUIRED_MODE)
    }

    @Test
    fun everyLengthMutationIsTypedAndRetainsThePriorProfile() {
        val previous = fixture.targetBytes()
        store.install(previous)

        previous.storedFields().forEach { field ->
            assertRetained<PublicProfileException.InvalidFieldLength>(
                previous.storeMutatingInt(field.lengthOffset, 0),
                previous,
            )
            assertRetained<PublicProfileException.OversizedField>(
                previous.storeMutatingInt(field.lengthOffset, Int.MAX_VALUE),
                previous,
            )
        }
    }

    @Test
    fun envelopePinCertificateAndSignerFailuresAreExactAndRetained() {
        val previous = fixture.targetBytes()
        store.install(previous)

        assertRetained<PublicProfileException.UnknownVersion>(
            previous.storeMutatingShort(4, 2),
            previous,
        )
        assertRetained<PublicProfileException.Truncated>(
            previous.copyOf(previous.size - 1),
            previous,
        )
        assertRetained<PublicProfileException.DuplicateField>(
            previous.storeDuplicateField(PublicProfileField.FIXTURE_PACKAGE),
            previous,
        )
        assertRetained<PublicProfileException.PinMismatch>(
            previous.storeFlippingField(PublicProfileField.DONOR_PIN),
            previous,
        )
        assertRetained<PublicProfileException.PinMismatch>(
            previous.storeFlippingField(PublicProfileField.TARGET_PIN),
            previous,
        )
        assertRetained<PublicProfileException.InvalidCertificate>(
            previous.storeFlippingField(PublicProfileField.TARGET_CERTIFICATE),
            previous,
        )
        assertRetained<PublicProfileException.IdentityMismatch>(
            previous.storeFlippingField(PublicProfileField.FIXTURE_SIGNER),
            previous,
        )
    }

    @Test
    fun interruptedAtomicWriteLeavesThePriorTargetProfileLoadable() {
        val previous = fixture.targetBytes()
        store.install(previous)
        facade.failWrite = true

        assertFailsWith<InterruptedProfileWrite> { store.install(fixture.targetBytes(42_322)) }

        facade.failWrite = false
        assertContentEquals(previous, PublicProfileCodec.encodeTarget(store.load()!!))
    }

    private inline fun <reified T : Throwable> assertRetained(
        candidate: ByteArray,
        previous: ByteArray,
    ) {
        assertFailsWith<T> { store.install(candidate) }
        assertContentEquals(previous, PublicProfileCodec.encodeTarget(store.load()!!))
    }
}
