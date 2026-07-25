# Two-phone host foundations: RED

Recorded before any `two-phone/src/main` production source existed.

## Command

```text
ANDROID_HOME="$PWD/.android-sdk" ./gradlew --no-daemon :two-phone:test
```

## Result

```text
> Task :two-phone:compileKotlin NO-SOURCE
> Task :two-phone:compileJava NO-SOURCE
> Task :two-phone:compileTestKotlin FAILED

Unresolved reference 'PairIdentity'.
Unresolved reference 'CanonicalBody'.
Unresolved reference 'Session'.
Unresolved reference 'FakeDonorAdapter'.
Unresolved reference 'KeyMintSecurityLevelRoutingSeam'.

Execution failed for task ':two-phone:compileTestKotlin'.
2 actionable tasks: 2 executed
BUILD FAILED in 9s
```

This is the intended RED: the executable contract was present and failed
because the normalized protocol, donor adapter/state machines, and target
routing seam had not been implemented.

An earlier invocation without `ANDROID_HOME` stopped during Android project
configuration and was discarded as environmental rather than behavioral RED.
