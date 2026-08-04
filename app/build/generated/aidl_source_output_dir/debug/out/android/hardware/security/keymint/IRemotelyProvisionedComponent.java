/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /home/vivy/Projects/TEESimulator/.android-sdk/build-tools/36.0.0/aidl -p/home/vivy/Projects/TEESimulator/.android-sdk/platforms/android-36/framework.aidl -o/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/build/generated/aidl_source_output_dir/debug/out -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/debug/aidl -d/tmp/aidl11980180748007382332.d /home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package android.hardware.security.keymint;
public interface IRemotelyProvisionedComponent extends android.os.IInterface
{
  /** Default implementation for IRemotelyProvisionedComponent. */
  public static class Default implements android.hardware.security.keymint.IRemotelyProvisionedComponent
  {
    @Override public android.hardware.security.keymint.RpcHardwareInfo getHardwareInfo() throws android.os.RemoteException
    {
      return null;
    }
    @Override public byte[] generateEcdsaP256KeyPair(boolean testMode, android.hardware.security.keymint.MacedPublicKey macedPublicKey) throws android.os.RemoteException
    {
      return null;
    }
    @Override public byte[] generateCertificateRequest(boolean testMode, android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] endpointEncryptionCertChain, byte[] challenge, android.hardware.security.keymint.DeviceInfo deviceInfo, android.hardware.security.keymint.ProtectedData protectedData) throws android.os.RemoteException
    {
      return null;
    }
    @Override public byte[] generateCertificateRequestV2(android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] challenge) throws android.os.RemoteException
    {
      return null;
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements android.hardware.security.keymint.IRemotelyProvisionedComponent
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an android.hardware.security.keymint.IRemotelyProvisionedComponent interface,
     * generating a proxy if needed.
     */
    public static android.hardware.security.keymint.IRemotelyProvisionedComponent asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof android.hardware.security.keymint.IRemotelyProvisionedComponent))) {
        return ((android.hardware.security.keymint.IRemotelyProvisionedComponent)iin);
      }
      return new android.hardware.security.keymint.IRemotelyProvisionedComponent.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      java.lang.String descriptor = DESCRIPTOR;
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(descriptor);
      }
      if (code == INTERFACE_TRANSACTION) {
        reply.writeString(descriptor);
        return true;
      }
      switch (code)
      {
        case TRANSACTION_getHardwareInfo:
        {
          android.hardware.security.keymint.RpcHardwareInfo _result = this.getHardwareInfo();
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_generateEcdsaP256KeyPair:
        {
          boolean _arg0;
          _arg0 = (0!=data.readInt());
          android.hardware.security.keymint.MacedPublicKey _arg1;
          _arg1 = new android.hardware.security.keymint.MacedPublicKey();
          byte[] _result = this.generateEcdsaP256KeyPair(_arg0, _arg1);
          reply.writeNoException();
          reply.writeByteArray(_result);
          _Parcel.writeTypedObject(reply, _arg1, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_generateCertificateRequest:
        {
          boolean _arg0;
          _arg0 = (0!=data.readInt());
          android.hardware.security.keymint.MacedPublicKey[] _arg1;
          _arg1 = data.createTypedArray(android.hardware.security.keymint.MacedPublicKey.CREATOR);
          byte[] _arg2;
          _arg2 = data.createByteArray();
          byte[] _arg3;
          _arg3 = data.createByteArray();
          android.hardware.security.keymint.DeviceInfo _arg4;
          _arg4 = new android.hardware.security.keymint.DeviceInfo();
          android.hardware.security.keymint.ProtectedData _arg5;
          _arg5 = new android.hardware.security.keymint.ProtectedData();
          byte[] _result = this.generateCertificateRequest(_arg0, _arg1, _arg2, _arg3, _arg4, _arg5);
          reply.writeNoException();
          reply.writeByteArray(_result);
          _Parcel.writeTypedObject(reply, _arg4, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          _Parcel.writeTypedObject(reply, _arg5, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_generateCertificateRequestV2:
        {
          android.hardware.security.keymint.MacedPublicKey[] _arg0;
          _arg0 = data.createTypedArray(android.hardware.security.keymint.MacedPublicKey.CREATOR);
          byte[] _arg1;
          _arg1 = data.createByteArray();
          byte[] _result = this.generateCertificateRequestV2(_arg0, _arg1);
          reply.writeNoException();
          reply.writeByteArray(_result);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements android.hardware.security.keymint.IRemotelyProvisionedComponent
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      @Override public android.hardware.security.keymint.RpcHardwareInfo getHardwareInfo() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        android.hardware.security.keymint.RpcHardwareInfo _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getHardwareInfo, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, android.hardware.security.keymint.RpcHardwareInfo.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public byte[] generateEcdsaP256KeyPair(boolean testMode, android.hardware.security.keymint.MacedPublicKey macedPublicKey) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        byte[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(((testMode)?(1):(0)));
          boolean _status = mRemote.transact(Stub.TRANSACTION_generateEcdsaP256KeyPair, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createByteArray();
          if ((0!=_reply.readInt())) {
            macedPublicKey.readFromParcel(_reply);
          }
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public byte[] generateCertificateRequest(boolean testMode, android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] endpointEncryptionCertChain, byte[] challenge, android.hardware.security.keymint.DeviceInfo deviceInfo, android.hardware.security.keymint.ProtectedData protectedData) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        byte[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(((testMode)?(1):(0)));
          _data.writeTypedArray(keysToSign, 0);
          _data.writeByteArray(endpointEncryptionCertChain);
          _data.writeByteArray(challenge);
          boolean _status = mRemote.transact(Stub.TRANSACTION_generateCertificateRequest, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createByteArray();
          if ((0!=_reply.readInt())) {
            deviceInfo.readFromParcel(_reply);
          }
          if ((0!=_reply.readInt())) {
            protectedData.readFromParcel(_reply);
          }
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public byte[] generateCertificateRequestV2(android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] challenge) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        byte[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeTypedArray(keysToSign, 0);
          _data.writeByteArray(challenge);
          boolean _status = mRemote.transact(Stub.TRANSACTION_generateCertificateRequestV2, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createByteArray();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
    }
    static final int TRANSACTION_getHardwareInfo = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_generateEcdsaP256KeyPair = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_generateCertificateRequest = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_generateCertificateRequestV2 = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "android.hardware.security.keymint.IRemotelyProvisionedComponent";
  public static final int STATUS_FAILED = 1;
  public static final int STATUS_INVALID_MAC = 2;
  public static final int STATUS_PRODUCTION_KEY_IN_TEST_REQUEST = 3;
  public static final int STATUS_TEST_KEY_IN_PRODUCTION_REQUEST = 4;
  public static final int STATUS_INVALID_EEK = 5;
  public static final int STATUS_REMOVED = 6;
  public android.hardware.security.keymint.RpcHardwareInfo getHardwareInfo() throws android.os.RemoteException;
  public byte[] generateEcdsaP256KeyPair(boolean testMode, android.hardware.security.keymint.MacedPublicKey macedPublicKey) throws android.os.RemoteException;
  public byte[] generateCertificateRequest(boolean testMode, android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] endpointEncryptionCertChain, byte[] challenge, android.hardware.security.keymint.DeviceInfo deviceInfo, android.hardware.security.keymint.ProtectedData protectedData) throws android.os.RemoteException;
  public byte[] generateCertificateRequestV2(android.hardware.security.keymint.MacedPublicKey[] keysToSign, byte[] challenge) throws android.os.RemoteException;
  /** @hide */
  static class _Parcel {
    static private <T> T readTypedObject(
        android.os.Parcel parcel,
        android.os.Parcelable.Creator<T> c) {
      if (parcel.readInt() != 0) {
          return c.createFromParcel(parcel);
      } else {
          return null;
      }
    }
    static private <T extends android.os.Parcelable> void writeTypedObject(
        android.os.Parcel parcel, T value, int parcelableFlags) {
      if (value != null) {
        parcel.writeInt(1);
        value.writeToParcel(parcel, parcelableFlags);
      } else {
        parcel.writeInt(0);
      }
    }
  }
}
