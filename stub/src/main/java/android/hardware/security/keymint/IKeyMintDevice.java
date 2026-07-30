package android.hardware.security.keymint;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

public interface IKeyMintDevice extends IInterface {
    String DESCRIPTOR = "android.hardware.security.keymint.IKeyMintDevice";

    KeyMintHardwareInfo getHardwareInfo() throws RemoteException;

    class Stub {
        public static IKeyMintDevice asInterface(IBinder binder) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
