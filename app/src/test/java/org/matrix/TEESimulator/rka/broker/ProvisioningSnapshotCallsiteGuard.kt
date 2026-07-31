package org.matrix.TEESimulator.rka.broker

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator

internal object ProvisioningSnapshotCallsiteGuard {
    val requiredCategories =
        setOf("system-property", "settings", "mutable-rkpd", "reflection", "exec")

    fun requireReadOnly(vararg classes: Class<*>) {
        val violations =
            classes.flatMap { type ->
                val resource = "/${type.name.replace('.', '/')}.class"
                val bytes =
                    type.getResourceAsStream(resource)?.use { it.readBytes() }
                        ?: error("missing production bytecode $resource")
                forbiddenCallsites(bytes)
            }
        require(violations.isEmpty()) {
            "ProvisioningSnapshot contains forbidden mutation callsites: ${violations.sorted()}"
        }
    }

    fun runMutationDriver(): Set<String> {
        val root = Files.createTempDirectory("provisioning-snapshot-mutations-")
        return try {
            val sources =
                mapOf(
                    "android/os/SystemProperties.java" to
                        """
                        package android.os;
                        public final class SystemProperties {
                          public static void set(String key, String value) {}
                        }
                        """,
                    "android/provider/Settings.java" to
                        """
                        package android.provider;
                        public final class Settings {
                          public static final class Global {
                            public static void putString(String key, String value) {}
                          }
                        }
                        """,
                    "com/android/rkpdapp/utils/Settings.java" to
                        """
                        package com.android.rkpdapp.utils;
                        public final class Settings {
                          public static void setUrl(String value) {}
                        }
                        """,
                    "android/hardware/security/keymint/IRemotelyProvisionedComponent.java" to
                        """
                        package android.hardware.security.keymint;
                        public interface IRemotelyProvisionedComponent {
                          void generateEcdsaP256KeyPair();
                        }
                        """,
                    "Mutant.java" to
                        """
                        public final class Mutant {
                          public static void mutate(
                              android.hardware.security.keymint.IRemotelyProvisionedComponent rkpd)
                              throws Exception {
                            android.os.SystemProperties.set("key", "value");
                            android.provider.Settings.Global.putString("key", "value");
                            com.android.rkpdapp.utils.Settings.setUrl("https://rkp.example");
                            rkpd.generateEcdsaP256KeyPair();
                            Class.forName("java.lang.String");
                            Runtime.getRuntime().exec("false");
                          }
                        }
                        """,
                )
            val files =
                sources.map { (relative, source) ->
                    root.resolve(relative).also {
                        Files.createDirectories(it.parent)
                        Files.write(it, source.trimIndent().toByteArray())
                    }
                }
            val output = root.resolve("classes")
            Files.createDirectories(output)
            val arguments = listOf("-d", output.toString()) + files.map(Path::toString)
            val compiler =
                ProcessBuilder(listOf("javac") + arguments).redirectErrorStream(true).start()
            val compilerOutput = compiler.inputStream.bufferedReader().use { it.readText() }
            check(compiler.waitFor() == 0) { compilerOutput }
            val bytecode = Files.readAllBytes(output.resolve("Mutant.class"))
            check(runCatching { requireReadOnlyBytecode(bytecode) }.isFailure)
            forbiddenCallsites(bytecode).toSet()
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun requireReadOnlyBytecode(bytecode: ByteArray) {
        val violations = forbiddenCallsites(bytecode)
        require(violations.isEmpty()) { "forbidden mutation callsites: ${violations.sorted()}" }
    }

    private fun forbiddenCallsites(bytecode: ByteArray): List<String> {
        val pool = ConstantPool.read(bytecode)
        return pool.methodReferences.mapNotNull { (owner, method) ->
            when {
                owner == "android/os/SystemProperties" && method == "set" -> "system-property"
                owner.startsWith("android/provider/Settings") && method.startsWith("put") ->
                    "settings"
                owner.endsWith("/Settings") &&
                    (method.startsWith("set") || method.startsWith("put")) -> "settings"
                owner.contains("IRemotelyProvisionedComponent") &&
                    (method.startsWith("generate") ||
                        method.startsWith("create") ||
                        method.startsWith("set")) -> "mutable-rkpd"
                owner.contains("rkpd", ignoreCase = true) &&
                    (method.startsWith("generate") ||
                        method.startsWith("create") ||
                        method.startsWith("set") ||
                        method.startsWith("put") ||
                        method.startsWith("write") ||
                        method.startsWith("update") ||
                        method.startsWith("delete")) -> "mutable-rkpd"
                owner.startsWith("java/lang/reflect/") ||
                    owner.startsWith("kotlin/reflect/") ||
                    (owner == "java/lang/Class" &&
                        (method == "forName" ||
                            method.startsWith("getDeclared") ||
                            method == "getMethod" ||
                            method == "getMethods" ||
                            method == "getField" ||
                            method == "getFields")) -> "reflection"
                (owner == "java/lang/Runtime" && method == "exec") ||
                    (owner == "java/lang/ProcessBuilder" &&
                        (method == "<init>" || method == "start")) -> "exec"
                else -> null
            }
        }
    }

    private class ConstantPool(val methodReferences: List<Pair<String, String>>) {
        companion object {
            fun read(bytecode: ByteArray): ConstantPool =
                DataInputStream(ByteArrayInputStream(bytecode)).use { input ->
                    require(input.readInt() == 0xCAFEBABE.toInt())
                    input.readUnsignedShort()
                    input.readUnsignedShort()
                    val count = input.readUnsignedShort()
                    val utf8 = arrayOfNulls<String>(count)
                    val classes = IntArray(count)
                    val names = IntArray(count)
                    val references = mutableListOf<Pair<Int, Int>>()
                    var index = 1
                    while (index < count) {
                        when (input.readUnsignedByte()) {
                            1 -> utf8[index] = input.readUTF()
                            3,
                            4 -> input.readInt()
                            5,
                            6 -> {
                                input.readLong()
                                index++
                            }
                            7 -> classes[index] = input.readUnsignedShort()
                            8,
                            16,
                            19,
                            20 -> input.readUnsignedShort()
                            9 -> {
                                input.readUnsignedShort()
                                input.readUnsignedShort()
                            }
                            10,
                            11 ->
                                references += input.readUnsignedShort() to input.readUnsignedShort()
                            12 -> {
                                names[index] = input.readUnsignedShort()
                                input.readUnsignedShort()
                            }
                            15 -> {
                                input.readUnsignedByte()
                                input.readUnsignedShort()
                            }
                            17,
                            18 -> {
                                input.readUnsignedShort()
                                input.readUnsignedShort()
                            }
                            else -> error("unsupported classfile constant")
                        }
                        index++
                    }
                    ConstantPool(
                        references.map { (classIndex, nameIndex) ->
                            requireNotNull(utf8[classes[classIndex]]) to
                                requireNotNull(utf8[names[nameIndex]])
                        }
                    )
                }
        }
    }
}
