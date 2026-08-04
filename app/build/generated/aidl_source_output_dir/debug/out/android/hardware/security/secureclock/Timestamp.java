/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /home/vivy/Projects/TEESimulator/.android-sdk/build-tools/36.0.0/aidl -p/home/vivy/Projects/TEESimulator/.android-sdk/platforms/android-36/framework.aidl -o/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/build/generated/aidl_source_output_dir/debug/out -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/debug/aidl -d/tmp/aidl11525121330932436151.d /home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl/android/hardware/security/secureclock/Timestamp.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package android.hardware.security.secureclock;
/** @hide */
public class Timestamp implements android.os.Parcelable
{
  public long milliSeconds = 0L;
  public static final android.os.Parcelable.Creator<Timestamp> CREATOR = new android.os.Parcelable.Creator<Timestamp>() {
    @Override
    public Timestamp createFromParcel(android.os.Parcel _aidl_source) {
      Timestamp _aidl_out = new Timestamp();
      _aidl_out.readFromParcel(_aidl_source);
      return _aidl_out;
    }
    @Override
    public Timestamp[] newArray(int _aidl_size) {
      return new Timestamp[_aidl_size];
    }
  };
  @Override public final void writeToParcel(android.os.Parcel _aidl_parcel, int _aidl_flag)
  {
    int _aidl_start_pos = _aidl_parcel.dataPosition();
    _aidl_parcel.writeInt(0);
    _aidl_parcel.writeLong(milliSeconds);
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
      milliSeconds = _aidl_parcel.readLong();
    } finally {
      if (_aidl_start_pos > (Integer.MAX_VALUE - _aidl_parcelable_size)) {
        throw new android.os.BadParcelableException("Overflow in the size of parcelable");
      }
      _aidl_parcel.setDataPosition(_aidl_start_pos + _aidl_parcelable_size);
    }
  }
  @Override
  public int describeContents() {
    int _mask = 0;
    return _mask;
  }
}
