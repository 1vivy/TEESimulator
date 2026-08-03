package org.matrix.TEESimulator

import android.app.ActivityThread
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Looper
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.matrix.TEESimulator.config.BootStateManager
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.AbstractKeystoreInterceptor
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.interception.keystore.KeystoreInterceptor
import org.matrix.TEESimulator.interception.soter.SoterProcessSupervisor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.NativeCertGen
import org.matrix.TEESimulator.rka.bridge.DonorProvisioningRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * Main application object for TEESimulator. This object manages the application's lifecycle,
 * including initialization of interceptors and maintaining the service's primary execution loop.
 */
object App {
    // The delay in milliseconds before retrying to initialize the interceptor.
    private const val RETRY_DELAY_MS = 1000L

    /**
     * The main entry point of the TEESimulator application.
     *
     * @param args Runtime-role arguments supplied by the module supervisor.
     */
    @JvmStatic
    fun main(args: Array<String>) {
        val launchPlan = AppLaunchPlan.parse(args)
        SystemLogger.info("Welcome to TEESimulator!")

        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            SystemLogger.error("Uncaught exception on ${thread.name}", throwable)
        }

        try {
            val systemContext = prepareEnvironment()

            if (launchPlan.startsKeystoreInterception) {
                initializeKeystoreRuntime(systemContext, launchPlan.startsCandidateRuntime)
            }
            if (launchPlan.startsDonorProvisioning) {
                DonorProvisioningRuntime.initializeLifecycle()
            }

            // This starts the message queue processing. It blocks here indefinitely
            // processing messages until Looper.myLooper().quit() is called.
            Looper.loop()
        } catch (e: Exception) {
            SystemLogger.error("A fatal error occurred in the main application thread.", e)
            throw e
        }
    }

    private fun initializeKeystoreRuntime(systemContext: Context, startsCandidateRuntime: Boolean) {
        BootStateManager.apply()

        ConfigurationManager.initialize()
        if (startsCandidateRuntime) {
            CandidateRuntimeRegistry.initializeLifecycle()
        }

        initializeInterceptors()

        // Set up the device's boot key and hash, which are crucial for attestation.
        AndroidDeviceUtils.setupBootKeyAndHash()

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())

        NativeCertGen.initialize("/data/adb/modules/tricky_store/libcertgen.so")

        SoterProcessSupervisor.start(systemContext)
    }

    /** Initializes the necessary Android framework internals to satisfy KeyStore requirements. */
    internal fun prepareEnvironment(): Context {
        // 1. Prepare Main Looper
        if (Looper.getMainLooper() == null) {
            @Suppress("deprecation") Looper.prepareMainLooper()
        }

        // 2. Initialize ActivityThread for the current process
        val activityThread = ActivityThread.systemMain()

        // 3. Get the system context. The stub declares getSystemContext(): ContextImpl
        //    (a bare class), so cast to the Context it really is at runtime for the wiring.
        @Suppress("CAST_NEVER_SUCCEEDS")
        val systemContext = activityThread.getSystemContext() as Context

        // 4. Create a dummy Application object and attach the context
        val app = Application()
        val attachMethod =
            ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
        attachMethod.isAccessible = true
        attachMethod.invoke(app, systemContext)

        // 5. Inject this application object into ActivityThread's mInitialApplication field.
        // This is what KeyStore.getApplicationContext() looks for.
        val mInitialApplicationField =
            ActivityThread::class.java.getDeclaredField("mInitialApplication")
        mInitialApplicationField.isAccessible = true
        mInitialApplicationField.set(activityThread, app)

        return systemContext
    }

    /**
     * Selects and initializes the correct keystore interceptor based on the Android SDK version. It
     * retries initialization until it succeeds.
     */
    private fun initializeInterceptors() {
        val interceptor = selectKeystoreInterceptor()

        // Continuously try to run the interceptor until it's successfully initialized.
        while (!interceptor.tryRunKeystoreInterceptor()) {
            SystemLogger.debug("Retrying interceptor initialization...")
            Thread.sleep(RETRY_DELAY_MS)
        }

        SystemLogger.info("Interceptors initialized successfully.")
    }

    /**
     * Determines which keystore interceptor to use based on the device's Android version.
     *
     * @return The appropriate keystore interceptor instance.
     */
    private fun selectKeystoreInterceptor(): AbstractKeystoreInterceptor =
        when {
            // For Android Q (10) and R (11), use the original KeystoreInterceptor.
            Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
                SystemLogger.info(
                    "Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore.AndroidKeyStoreProvider.install()
                KeystoreInterceptor
            }
            // For Android S (12) and newer, use the Keystore2Interceptor.
            else -> {
                SystemLogger.info(
                    "Using Keystore2Interceptor for Android S and later (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore2.AndroidKeyStoreProvider.install()
                Keystore2Interceptor
            }
        }
}
