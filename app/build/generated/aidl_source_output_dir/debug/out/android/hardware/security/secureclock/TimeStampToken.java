/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: /home/vivy/Projects/TEESimulator/.android-sdk/build-tools/36.0.0/aidl -p/home/vivy/Projects/TEESimulator/.android-sdk/platforms/android-36/framework.aidl -o/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/build/generated/aidl_source_output_dir/debug/out -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl -I/home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/debug/aidl -d/tmp/aidl803744533352534288.d /home/vivy/.paseo/worktrees/3rxln21n/tearful-turkey/app/src/main/aidl/android/hardware/security/secureclock/TimeStampToken.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package android.hardware.security.secureclock;
/** @hide */
public class TimeStampToken implements android.os.Parcelable
{
  public long challenge = 0L;
  public android.hardware.security.secureclock.Timestamp timestamp;
  public byte[] mac;
  public static final android.os.Parcelable.Creator<TimeStampToken> CREATOR = new android.os.Parcelable.Creator<TimeStampToken>() {
    @Override
    public TimeStampToken createFromParcel(android.os.Parcel _aidl_source) {
      TimeStampToken _aidl_out = new TimeStampToken();
      _aidl_out.readFromParcel(_aidl_source);
      return _aidl_out;
    }
    @Override
    public TimeStampToken[] newArray(int _aidl_size) {
      return new TimeStampToken[_aidl_size];
    }
  };
  @Override public final void writeToParcel(android.os.Parcel _aidl_parcel, int _aidl_flag)
  {
    int _aidl_start_pos = _aidl_parcel.dataPosition();
    _aidl_parcel.writeInt(0);
    _aidl_parcel.writeLong(challenge);
    _Parcel.writeTypedObject(_aidl_parcel, timestamp, _aidl_flag);
    _aidl_parcel.writeByteArray(mac);
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
      challenge = _aidl_parcel.readLong();
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      timestamp = _Parcel.readTypedObject(_aidl_parcel, android.hardware.security.secureclock.Timestamp.CREATOR);
      if (_aidl_parcel.dataPosition() - _aidl_start_pos >= _aidl_parcelable_size) return;
      mac = _aidl_parcel.createByteArray();
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
    _mask |= describeContents(timestamp);
    return _mask;
  }
  private int describeContents(Object _v) {
    if (_v == null) return 0;
    if (_v instanceof android.os.Parcelable) {
      return ((android.os.Parcelable) _v).describeContents();
    }
    return 0;
  }
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
