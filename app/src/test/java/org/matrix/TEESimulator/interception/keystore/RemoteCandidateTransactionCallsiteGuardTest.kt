package org.matrix.TEESimulator.interception.keystore

import org.junit.Assert.assertEquals
import org.junit.Test
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

class RemoteCandidateTransactionCallsiteGuardTest {
    @Test
    fun compiledGenerateHandlerRetainsParcelParsingAndCandidateRoute() {
        val calls = mutableListOf<Pair<String, String>>()
        val resource =
            "/" + KeyMintSecurityLevelInterceptor::class.java.name.replace('.', '/') + ".class"
        val bytecode =
            checkNotNull(KeyMintSecurityLevelInterceptor::class.java.getResourceAsStream(resource))
                .use { it.readBytes() }

        ClassReader(bytecode)
            .accept(
                object : ClassVisitor(Opcodes.ASM9) {
                    override fun visitMethod(
                        access: Int,
                        name: String,
                        descriptor: String,
                        signature: String?,
                        exceptions: Array<out String>?,
                    ): MethodVisitor? {
                        if (name != "handleGenerateKey") return null
                        return object : MethodVisitor(Opcodes.ASM9) {
                            override fun visitMethodInsn(
                                opcode: Int,
                                owner: String,
                                name: String,
                                descriptor: String,
                                isInterface: Boolean,
                            ) {
                                calls += owner to name
                            }
                        }
                    }
                },
                ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES,
            )

        assertEquals(1, calls.count { it == "android/os/Parcel" to "enforceInterface" })
        assertEquals(2, calls.count { it == "android/os/Parcel" to "readTypedObject" })
        assertEquals(1, calls.count { it == "android/os/Parcel" to "createTypedArray" })
        assertEquals(
            1,
            calls.count {
                it ==
                    "org/matrix/TEESimulator/interception/keystore/shim/KeyMintSecurityLevelInterceptor" to
                        "routeCandidateGenerate"
            },
        )
    }
}
