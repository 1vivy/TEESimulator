-keep class org.matrix.TEESimulator.interception.keystore.** { *; }

# These compile-only hidden-API stubs describe boot-class-path parcelables. If R8 renames them,
# Parcel returns the platform type while verifier signatures expect the renamed app type.
-keep class android.hardware.security.keymint.** { *; }
-keep class android.system.keystore2.** { *; }

-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

-keepclasseswithmembers class org.matrix.TEESimulator.App {
    public static void main(java.lang.String[]);
}

-keepclasseswithmembers class org.matrix.TEESimulator.rka.trust.AgentPgpVerifier {
    public static void main(java.lang.String[]);
}

-keepclasseswithmembers class org.matrix.TEESimulator.rka.broker.IrpcIdentityProbe {
    public static void main(java.lang.String[]);
}

-keepclasseswithmembers class org.matrix.TEESimulator.pki.NativeCertGen {
    native <methods>;
    *;
}
-keep class org.matrix.TEESimulator.pki.CertGenConfig { *; }
