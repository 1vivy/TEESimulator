/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /home/vivy/Projects/TEESimulator/.android-sdk/build-tools/36.0.0/aidl -p/home/vivy/Projects/TEESimulator/.android-sdk/platforms/android-36/framework.aidl -o/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/build/generated/aidl_source_output_dir/debug/out -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/debug/aidl -d/tmp/aidl8828223612318524735.d /home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl/android/hardware/security/keymint/RpcHardwareInfo.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package android.hardware.security.keymint;
public class RpcHardwareInfo implements android.os.Parcelable
{
  public int versionNumber = 0;
  public java.lang.String rpcAuthorName;
  public int supportedEekCurve = 0;
  public java.lang.String uniqueId;
  public int supportedNumKeysInCsr = 4;
  public static final android.os.Parcelable.Creator<RpcHardwareInfo> CREATOR = new android.os.Parcelable.Creator<RpcHardwareInfo>() {
    @Override
    public RpcHardwareInfo createFromParcel(android.os.Parcel _aidl_source) {
      RpcHardwareInfo _aidl_out = new RpcHardwareInfo();
      _aidl_out.readFromParcel(_aidl_source);
      return _aidl_out;
    }
    @Override
    public RpcHardwareInfo[] newArray(int _aidl_size) {
      return new RpcHardwareInfo[_aidl_size];
    }
  };
  @Override public final void writeToParcel(android.os.Parcel _aidl_parcel, int _aidl_flag)
  {
    int _aidl_start_pos = _aidl_parcel.dataPosition();
    _aidl_parcel.writeInt(0);
    _aidl_parcel.writeInt(versionNumber);
    _aidl_parcel.writeString(rpcAuthorName);
    _aidl_parcel.writeInt(supportedEekCurve);
    _aidl_parcel.writeString(uniqueId);
    _aidl_parcel.writeInt(supportedNumKeysInCsr);
    int _aidl_end_pos = _aidl_parcel.dataPosition();
    _aidl_parcel.setDataPosition(_aidl_start_pos);
    _aidl_parcel.writeInt(_aidl_end_pos - _aidl_start_pos);
    _aidl_parcel.setDataPosition(_aidl_end_pos);
  }
  public final void readFromParcel(android.os.Parcel _aidl_parcel)
  {
    int _aidl_start_pos = _aidl_parcel.dataPosition();
    int _aidl_parcelable_size = _aidl_parcel.readInt();
    try {
      if (_aidl_parcelable_size < 4) throw new android.os.BadParcelableException("Parcelable too small");;
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      versionNumber = _aidl_parcel.readInt();
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      rpcAuthorName = _aidl_parcel.readString();
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      supportedEekCurve = _aidl_parcel.readInt();
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      uniqueId = _aidl_parcel.readString();
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      supportedNumKeysInCsr = _aidl_parcel.readInt();
    } finally {
      if (_aidl_start_pos > (Integer.MAX_VALUE - _aidl_parcelable_size)) {
        throw new android.os.BadParcelableException("Overflow in the size of parcelable");
      }
      _aidl_parcel.setDataPosition(_aidl_start_pos + _aidl_parcelable_size);
    }
  }
  public static final int CURVE_NONE = 0;
  public static final int CURVE_P256 = 1;
  public static final int CURVE_25519 = 2;
  public static final int MIN_SUPPORTED_NUM_KEYS_IN_CSR = 20;
  @Override
  public int describeContents() {
    int _mask = 0;
    return _mask;
  }
}
