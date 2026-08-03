package android.hardware.security.keymint;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

public interface IRemotelyProvisionedComponent extends IInterface {
    String DESCRIPTOR = "android.hardware.security.keymint.IRemotelyProvisionedComponent";

    RpcHardwareInfo getHardwareInfo() throws RemoteException;

    byte[] generateEcdsaP256KeyPair(boolean testMode, MacedPublicKey macedPublicKey)
            throws RemoteException;

    byte[] generateCertificateRequestV2(MacedPublicKey[] keysToSign, byte[] challenge)
            throws RemoteException;

    class Stub {
        public static IRemotelyProvisionedComponent asInterface(IBinder binder) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
