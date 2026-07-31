package org.matrix.TEESimulator.interception.keystore

import android.system.keystore2.Domain
import android.system.keystore2.KeyDescriptor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.candidate.CandidateGenerateRequest
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry

class RemoteCandidateInterceptorHandlerTest {
    @After
    fun resetRegistry() {
        CandidateRuntimeRegistry.initializeLifecycle()
    }

    @Test
    fun keystoreHandlersRouteListGetGrantAndDelete() {
        val fixture = ProductionFixture()
        fixture.service
            .generate(CandidateGenerateRequest(fixture.id, fixture.identity, fixture.shape))
            .remoteSuccess()
        fixture.backend.calls.clear()
        publishRuntime(fixture.runtime)

        val list =
            privateMethod(
                "routeCandidateList",
                Long::class.java,
                Int::class.java,
                Boolean::class.java,
            )
        assertNull(list.invoke(Keystore2Interceptor, 91L, fixture.uid, false))
        val pending = ListEntriesHandler::class.java.getDeclaredField("pendingRemoteKeys")
        pending.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val cached = pending.get(ListEntriesHandler) as MutableMap<Long, *>
        assertTrue(cached.containsKey(91L))
        cached.remove(91L)

        fixture.backend.failureStage = "get"
        val key =
            privateMethod(
                "routeCandidateKey",
                Int::class.java,
                Int::class.java,
                KeyDescriptor::class.java,
            )
        assertReplyAttempt {
            key.invoke(
                Keystore2Interceptor,
                transactionCode("GET_KEY_ENTRY_TRANSACTION"),
                fixture.uid,
                descriptor(fixture.id.alias),
            )
        }
        fixture.backend.failureStage = null
        assertReplyAttempt {
            key.invoke(
                Keystore2Interceptor,
                transactionCode("DELETE_KEY_TRANSACTION"),
                fixture.uid,
                descriptor(fixture.id.alias),
            )
        }
        val grant =
            privateMethod(
                "routeCandidateGrant",
                Int::class.java,
                KeyDescriptor::class.java,
                Int::class.java,
            )
        assertReplyAttempt {
            grant.invoke(Keystore2Interceptor, fixture.uid, descriptor(fixture.id.alias), 7)
        }
        assertEquals(listOf("list", "get", "get"), fixture.backend.calls)
    }

    private fun assertReplyAttempt(block: () -> Any?) {
        val outcome = runCatching(block)
        val failure = outcome.exceptionOrNull()
        assertTrue(failure == null || failure is java.lang.reflect.InvocationTargetException)
    }

    private fun privateMethod(name: String, vararg types: Class<*>): java.lang.reflect.Method =
        Keystore2Interceptor::class.java.getDeclaredMethod(name, *types).also {
            it.isAccessible = true
        }

    private fun transactionCode(name: String): Int =
        Keystore2Interceptor::class.java.getDeclaredField(name).let {
            it.isAccessible = true
            it.getInt(Keystore2Interceptor)
        }

    private fun descriptor(alias: String) =
        KeyDescriptor().apply {
            domain = Domain.APP
            nspace = -1
            this.alias = alias
            blob = null
        }

    private fun publishRuntime(runtime: CandidateRuntime) {
        val stateClass =
            Class.forName(
                "org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry\$State\$Authorized"
            )
        val constructor = stateClass.getDeclaredConstructor(CandidateRuntime::class.java)
        constructor.isAccessible = true
        val state = constructor.newInstance(runtime)
        CandidateRuntimeRegistry::class.java.getDeclaredField("state").let {
            it.isAccessible = true
            it.set(CandidateRuntimeRegistry, state)
        }
    }
}
