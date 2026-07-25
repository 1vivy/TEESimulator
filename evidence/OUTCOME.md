# Verified outcome

Outcome A: probe-only release `v0.1.0-probe.1`.

- G0: PASS (`scripts/verify.sh`).
- G1: STOP (see `2026-07-25-g1-stop.txt`).
- G2: not attempted because G1 did not pass.
- Live insertion: not attempted and forbidden by the gate result.
- Device staging directory: not created; therefore no teardown was required.
- Device mutations, native RKP calls, StrongBox/AVF interception: none.
