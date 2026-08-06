package org.matrix.TEESimulator.config

import java.util.concurrent.ConcurrentHashMap
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class LegacyModeBaselineTest {
    private val uid = 10_042

    @Before
    fun setUp() {
        setField("packageModes", emptyMap<String, ConfigurationManager.Mode>())
        setField("packageKeyboxes", emptyMap<String, String>())
        uidCache().clear()
    }

    @After
    fun tearDown() {
        setField("packageModes", emptyMap<String, ConfigurationManager.Mode>())
        setField("packageKeyboxes", emptyMap<String, String>())
        uidCache().clear()
    }

    @Test
    fun explicitPatchRemainsPatch() {
        configure("fixture.patch", ConfigurationManager.Mode.PATCH)

        assertTrue(ConfigurationManager.shouldPatch(uid))
        assertFalse(ConfigurationManager.shouldGenerate(uid))
        assertFalse(ConfigurationManager.shouldSkipUid(uid))
        assertTrue(ConfigurationManager.shouldUseSyntheticLease(uid))
    }

    @Test
    fun explicitGenerateRemainsGenerate() {
        configure("fixture.generate", ConfigurationManager.Mode.GENERATE)

        assertFalse(ConfigurationManager.shouldPatch(uid))
        assertTrue(ConfigurationManager.shouldGenerate(uid))
        assertFalse(ConfigurationManager.shouldSkipUid(uid))
        assertFalse(ConfigurationManager.shouldUseSyntheticLease(uid))
    }

    @Test
    fun autoRemainsAutoBeforeHardwareResolution() {
        configure("fixture.auto", ConfigurationManager.Mode.AUTO)

        assertTrue(ConfigurationManager.isAutoMode(uid))
        assertTrue(ConfigurationManager.shouldGenerate(uid))
        assertFalse(ConfigurationManager.shouldPatch(uid))
        assertFalse(ConfigurationManager.shouldSkipUid(uid))
        assertFalse(ConfigurationManager.shouldUseSyntheticLease(uid))
    }

    @Test
    fun firstConfiguredPackageKeepsModePrecedence() {
        uidCache()[uid] = arrayOf("fixture.generate", "fixture.patch")
        setField(
            "packageModes",
            linkedMapOf(
                "fixture.generate" to ConfigurationManager.Mode.GENERATE,
                "fixture.patch" to ConfigurationManager.Mode.PATCH,
            ),
        )

        assertTrue(ConfigurationManager.shouldGenerate(uid))
        assertFalse(ConfigurationManager.shouldPatch(uid))
        assertTrue(ConfigurationManager.shouldUseSyntheticLease(uid))
    }

    @Test
    fun configuredKeyboxAndDefaultResolutionRemainStable() {
        uidCache()[uid] = arrayOf("fixture.unmapped", "fixture.mapped")
        setField("packageKeyboxes", mapOf("fixture.mapped" to "fixture-keybox.xml"))

        assertEquals("fixture-keybox.xml", ConfigurationManager.getKeyboxFileForUid(uid))

        uidCache()[uid] = arrayOf("fixture.unmapped")
        assertEquals("keybox.xml", ConfigurationManager.getKeyboxFileForUid(uid))
    }

    @Test
    fun unselectedUidRemainsPlatformPassThrough() {
        uidCache()[uid] = arrayOf("fixture.unselected")

        assertTrue(ConfigurationManager.shouldSkipUid(uid))
        assertFalse(ConfigurationManager.shouldPatch(uid))
        assertFalse(ConfigurationManager.shouldGenerate(uid))
        assertFalse(ConfigurationManager.isAutoMode(uid))
        assertFalse(ConfigurationManager.shouldUseSyntheticLease(uid))
    }

    @Test
    fun syntheticLeaseCandidateUidsIncludeOnlyExplicitPatchTargets() {
        // Given
        setField(
            "packageModes",
            linkedMapOf(
                "fixture.auto" to ConfigurationManager.Mode.AUTO,
                "fixture.generate" to ConfigurationManager.Mode.GENERATE,
                "fixture.patch" to ConfigurationManager.Mode.PATCH,
            ),
        )

        // When
        val selected =
            ConfigurationManager.configuredCandidateUids(
                linkedMapOf(
                    "fixture.auto" to uid,
                    "fixture.generate" to uid + 1,
                    "fixture.patch" to uid + 2,
                )
            )

        // Then
        assertEquals(listOf(uid + 2), selected)
    }

    private fun configure(packageName: String, mode: ConfigurationManager.Mode) {
        uidCache()[uid] = arrayOf(packageName)
        setField("packageModes", mapOf(packageName to mode))
    }

    @Suppress("UNCHECKED_CAST")
    private fun uidCache(): ConcurrentHashMap<Int, Array<String>> =
        field("uidToPackagesCache").get(ConfigurationManager)
            as ConcurrentHashMap<Int, Array<String>>

    private fun setField(name: String, value: Any) {
        field(name).set(ConfigurationManager, value)
    }

    private fun field(name: String) =
        ConfigurationManager::class.java.getDeclaredField(name).apply { isAccessible = true }
}
