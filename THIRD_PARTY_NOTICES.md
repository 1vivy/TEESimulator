# Third-party notices

The existing upstream source tree contains Android Open Source Project header
snapshots under `app/src/main/cpp/external/AOSP`; its notice and Apache-2.0
license text are retained there. Existing Gradle dependencies retain their
upstream licenses and are resolved from their normal repositories.

Pinned Android 16 public Binder and frozen Keystore2 V5 AIDL inputs reside in
`app/src/main/cpp/external/AOSP/android16`. They are Apache-2.0 AOSP source;
immutable Gitiles revisions and SHA-256 values are recorded in that directory's
`PROVENANCE.md`. They are source inputs only and do not include system libraries.

`MhmRdd/google-rkp-sw@8a74e55` is not a dependency, is not vendored, and is
never executed by this project.
