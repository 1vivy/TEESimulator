package android.system.keystore2;

import android.os.IBinder;

public interface IKeystoreService {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreService";

    IKeystoreSecurityLevel getSecurityLevel(int securityLevel);

    class Stub {
        static final int TRANSACTION_getSecurityLevel = IBinder.FIRST_CALL_TRANSACTION;
        static final int TRANSACTION_getKeyEntry = IBinder.FIRST_CALL_TRANSACTION + 1;
        static final int TRANSACTION_updateSubcomponent = IBinder.FIRST_CALL_TRANSACTION + 2;
        static final int TRANSACTION_listEntries = IBinder.FIRST_CALL_TRANSACTION + 3;
        static final int TRANSACTION_deleteKey = IBinder.FIRST_CALL_TRANSACTION + 4;
        static final int TRANSACTION_listEntriesBatched = IBinder.FIRST_CALL_TRANSACTION + 8;

        public static IKeystoreService asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
