/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /home/vivy/Projects/TEESimulator/.android-sdk/build-tools/36.0.0/aidl -p/home/vivy/Projects/TEESimulator/.android-sdk/platforms/android-36/framework.aidl -o/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/build/generated/aidl_source_output_dir/debug/out -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/debug/aidl -d/tmp/aidl3164643883831451383.d /home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl/android/hardware/security/keymint/IKeyMintOperation.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package android.hardware.security.keymint;
/** @hide */
public interface IKeyMintOperation extends android.os.IInterface
{
  /** Default implementation for IKeyMintOperation. */
  public static class Default implements android.hardware.security.keymint.IKeyMintOperation
  {
    @Override public void updateAad(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException
    {
    }
    @Override public byte[] update(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException
    {
      return null;
    }
    @Override public byte[] finish(byte[] input, byte[] signature, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timestampToken, byte[] confirmationToken) throws android.os.RemoteException
    {
      return null;
    }
    @Override public void abort() throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements android.hardware.security.keymint.IKeyMintOperation
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an android.hardware.security.keymint.IKeyMintOperation interface,
     * generating a proxy if needed.
     */
    public static android.hardware.security.keymint.IKeyMintOperation asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof android.hardware.security.keymint.IKeyMintOperation))) {
        return ((android.hardware.security.keymint.IKeyMintOperation)iin);
      }
      return new android.hardware.security.keymint.IKeyMintOperation.Stub.Proxy(obj);
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
        case TRANSACTION_updateAad:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          android.hardware.security.keymint.HardwareAuthToken _arg1;
          _arg1 = _Parcel.readTypedObject(data, android.hardware.security.keymint.HardwareAuthToken.CREATOR);
          android.hardware.security.secureclock.TimeStampToken _arg2;
          _arg2 = _Parcel.readTypedObject(data, android.hardware.security.secureclock.TimeStampToken.CREATOR);
          this.updateAad(_arg0, _arg1, _arg2);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_update:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          android.hardware.security.keymint.HardwareAuthToken _arg1;
          _arg1 = _Parcel.readTypedObject(data, android.hardware.security.keymint.HardwareAuthToken.CREATOR);
          android.hardware.security.secureclock.TimeStampToken _arg2;
          _arg2 = _Parcel.readTypedObject(data, android.hardware.security.secureclock.TimeStampToken.CREATOR);
          byte[] _result = this.update(_arg0, _arg1, _arg2);
          reply.writeNoException();
          reply.writeByteArray(_result);
          break;
        }
        case TRANSACTION_finish:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          byte[] _arg1;
          _arg1 = data.createByteArray();
          android.hardware.security.keymint.HardwareAuthToken _arg2;
          _arg2 = _Parcel.readTypedObject(data, android.hardware.security.keymint.HardwareAuthToken.CREATOR);
          android.hardware.security.secureclock.TimeStampToken _arg3;
          _arg3 = _Parcel.readTypedObject(data, android.hardware.security.secureclock.TimeStampToken.CREATOR);
          byte[] _arg4;
          _arg4 = data.createByteArray();
          byte[] _result = this.finish(_arg0, _arg1, _arg2, _arg3, _arg4);
          reply.writeNoException();
          reply.writeByteArray(_result);
          break;
        }
        case TRANSACTION_abort:
        {
          this.abort();
          reply.writeNoException();
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements android.hardware.security.keymint.IKeyMintOperation
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
      @Override public void updateAad(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(input);
          _Parcel.writeTypedObject(_data, authToken, 0);
          _Parcel.writeTypedObject(_data, timeStampToken, 0);
          boolean _status = mRemote.transact(Stub.TRANSACTION_updateAad, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public byte[] update(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        byte[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(input);
          _Parcel.writeTypedObject(_data, authToken, 0);
          _Parcel.writeTypedObject(_data, timeStampToken, 0);
          boolean _status = mRemote.transact(Stub.TRANSACTION_update, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createByteArray();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public byte[] finish(byte[] input, byte[] signature, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timestampToken, byte[] confirmationToken) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        byte[] _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(input);
          _data.writeByteArray(signature);
          _Parcel.writeTypedObject(_data, authToken, 0);
          _Parcel.writeTypedObject(_data, timestampToken, 0);
          _data.writeByteArray(confirmationToken);
          boolean _status = mRemote.transact(Stub.TRANSACTION_finish, _data, _reply, 0);
          _reply.readException();
          _result = _reply.createByteArray();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public void abort() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_abort, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_updateAad = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_update = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_finish = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_abort = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "android.hardware.security.keymint.IKeyMintOperation";
  public void updateAad(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException;
  public byte[] update(byte[] input, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timeStampToken) throws android.os.RemoteException;
  public byte[] finish(byte[] input, byte[] signature, android.hardware.security.keymint.HardwareAuthToken authToken, android.hardware.security.secureclock.TimeStampToken timestampToken, byte[] confirmationToken) throws android.os.RemoteException;
  public void abort() throws android.os.RemoteException;
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
