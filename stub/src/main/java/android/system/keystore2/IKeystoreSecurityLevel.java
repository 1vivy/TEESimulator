package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.IBinder;
import android.os.IInterface;

import androidx.annotation.Nullable;

public interface IKeystoreSecurityLevel extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreSecurityLevel";

    KeyMetadata generateKey(KeyDescriptor key, @Nullable KeyDescriptor attestationKey,
                            KeyParameter[] params, int flags, byte[] entropy);

    class Stub {
        static final int TRANSACTION_createOperation = IBinder.FIRST_CALL_TRANSACTION;
        static final int TRANSACTION_generateKey = IBinder.FIRST_CALL_TRANSACTION + 1;
        static final int TRANSACTION_importKey = IBinder.FIRST_CALL_TRANSACTION + 2;

        public static IKeystoreSecurityLevel asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
