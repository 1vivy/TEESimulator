package android.hardware.security.keymint;

import android.hardware.security.secureclock.TimeStampToken;
import android.os.IInterface;
import android.os.RemoteException;

public interface IKeyMintOperation extends IInterface {
    void updateAad(byte[] input, HardwareAuthToken authToken, TimeStampToken timeStampToken)
            throws RemoteException;

    byte[] update(byte[] input, HardwareAuthToken authToken, TimeStampToken timeStampToken)
            throws RemoteException;

    byte[] finish(
            byte[] input,
            byte[] signature,
            HardwareAuthToken authToken,
            TimeStampToken timeStampToken,
            byte[] confirmationToken)
            throws RemoteException;

    void abort() throws RemoteException;
}
