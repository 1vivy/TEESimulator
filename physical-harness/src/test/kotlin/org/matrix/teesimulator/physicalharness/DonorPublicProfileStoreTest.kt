package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.PublicProfileException
import org.matrix.teesimulator.twophone.PublicProfileField

class DonorPublicProfileStoreTest {
    private val directory = createTempDirectory("donor-public-profile").toFile()
    private val facade = FakePublicProfileAtomicFileFacade(directory)
    private val store = DonorPublicProfileStore(facade)
    private val fixture = PublicProfileStoreFixture()

    @AfterTest
    fun cleanUp() {
        directory.deleteRecursively()
    }

    @Test
    fun appPrivateStoreRoundTripsTheCanonicalDonorProfile() {
        assertNull(store.load())
        val expected = fixture.donorBytes()

        store.install(expected)
        val loaded = store.load()!!

        assertContentEquals(expected, PublicProfileCodec.encodeDonor(loaded))
        assertEquals("two-phone-donor-v1.bin", DonorPublicProfileStore.FILE_NAME)
        assertEquals(1, facade.preparedWrites)
    }

    @Test
    fun invalidCandidateNeverReplacesTheLastKnownGoodProfile() {
        val previous = fixture.donorBytes()
        store.install(previous)
        val pairMutation = previous.storeFlippingField(PublicProfileField.PAIR_TARGET_PIN)

        assertFailsWith<PublicProfileException.IdentityMismatch> { store.install(pairMutation) }

        assertContentEquals(previous, PublicProfileCodec.encodeDonor(store.load()!!))
        assertEquals(1, facade.startedWrites)
    }

    @Test
    fun interruptedAtomicWriteLeavesThePriorDonorProfileLoadable() {
        val previous = fixture.donorBytes()
        store.install(previous)
        facade.failWrite = true

        assertFailsWith<InterruptedProfileWrite> { store.install(fixture.donorBytes(42_322)) }

        facade.failWrite = false
        assertContentEquals(previous, PublicProfileCodec.encodeDonor(store.load()!!))
    }

    @Test
    fun storedConfigSourceReplacesTheEmptyProductionStub() {
        store.install(fixture.donorBytes())
        val source = StoredDonorConfigSource(store)

        val profile = source.load("approved.profile", Instant.now())!!

        assertEquals("approved.profile", profile.profileId)
        assertEquals(fixture.donor().bindEndpoint.port, profile.port)
        assertEquals(fixture.donor().pairIdentity.targetPin, profile.expectedTargetPin.toString())
        assertEquals(fixture.donor().pairIdentity.donorPin, profile.expectedDonorPin.toString())
        assertFailsWith<DonorProfileException.InvalidProfileId> {
            source.load("../profile", Instant.now())
        }
    }
}
