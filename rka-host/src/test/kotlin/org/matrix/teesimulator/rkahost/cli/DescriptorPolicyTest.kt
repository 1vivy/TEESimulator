package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DescriptorPolicyTest {
    @Test
    fun rejectsCounterfeitNamedMemfdWithoutSeals() {
        val error =
            assertThrows(HostCliException::class.java) {
                DescriptorPolicy.validate(
                    DescriptorFacts(
                        name = "/memfd:rka-device-pair (deleted)",
                        seals = 0,
                        accessMode = 0,
                        regular = true,
                        size = 100,
                    )
                )
            }
        assertEquals("PAIR_FD_UNSEALED", error.message)
    }

    @Test
    fun rejectsWritableAndWrongTypeDescriptors() {
        val sealed = DescriptorFacts("/memfd:rka-device-pair (deleted)", 15, 2, true, 100)
        assertThrows(HostCliException::class.java) { DescriptorPolicy.validate(sealed) }
        assertThrows(HostCliException::class.java) {
            DescriptorPolicy.validate(sealed.copy(accessMode = 0, regular = false))
        }
    }
}
