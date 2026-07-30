package org.matrix.teesimulator.rkahost

object CandidateIdentityGateCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val exit = run(arguments)
        if (exit != 0) kotlin.system.exitProcess(exit)
    }

    internal fun run(arguments: Array<String>): Int {
        if (arguments.isNotEmpty()) {
            println("RESULT=ARGUMENT_INVALID")
            return 1
        }
        println("RESULT=CALLER_FIXTURE_ONLY")
        return 0
    }
}
