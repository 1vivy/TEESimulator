package org.matrix.teesimulator.rkafixture

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class FixtureActivityDelegate(private val commandSurface: FixtureCommandSurface) {
    fun submit(command: FixtureCommand): FixtureCommandResult = commandSurface.execute(command)
}

class FixtureActivity : Activity() {
    private lateinit var delegate: FixtureActivityDelegate

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        delegate = FixtureActivityDelegate((application as FixtureApplication).commandSurface)
        setContentView(TextView(this).apply { text = "RKA fixture command surface" })
    }

    internal fun submit(command: FixtureCommand): FixtureCommandResult = delegate.submit(command)
}
