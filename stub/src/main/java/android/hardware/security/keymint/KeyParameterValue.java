package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public final class KeyParameterValue implements Parcelable {
    public static final int algorithm = 1;
    public static final int blob = 14;
    public static final int blockMode = 2;
    public static final int boolValue = 10;
    public static final int dateTime = 13;
    public static final int digest = 4;
    public static final int ecCurve = 5;
    public static final int hardwareAuthenticatorType = 8;
    public static final int integer = 11;
    public static final int invalid = 0;
    public static final int keyPurpose = 7;
    public static final int longInteger = 12;
    public static final int origin = 6;
    public static final int paddingMode = 3;
    public static final int securityLevel = 9;
    public static final Creator<KeyParameterValue> CREATOR = new Creator<KeyParameterValue>() {
        @Override
        public KeyParameterValue createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public KeyParameterValue[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    private int tag = invalid;
    private Object value = 0;

    public KeyParameterValue() {}

    protected KeyParameterValue(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static KeyParameterValue invalid(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setInvalid(_value);
        return result;
    }

    public static KeyParameterValue algorithm(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setAlgorithm(_value);
        return result;
    }

    public static KeyParameterValue blockMode(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setBlockMode(_value);
        return result;
    }

    public static KeyParameterValue paddingMode(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setPaddingMode(_value);
        return result;
    }

    public static KeyParameterValue digest(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setDigest(_value);
        return result;
    }

    public static KeyParameterValue ecCurve(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setEcCurve(_value);
        return result;
    }

    public static KeyParameterValue origin(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setOrigin(_value);
        return result;
    }

    public static KeyParameterValue keyPurpose(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setKeyPurpose(_value);
        return result;
    }

    public static KeyParameterValue hardwareAuthenticatorType(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setHardwareAuthenticatorType(_value);
        return result;
    }

    public static KeyParameterValue securityLevel(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setSecurityLevel(_value);
        return result;
    }

    public static KeyParameterValue boolValue(boolean _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setBoolValue(_value);
        return result;
    }

    public static KeyParameterValue integer(int _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setInteger(_value);
        return result;
    }

    public static KeyParameterValue longInteger(long _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setLongInteger(_value);
        return result;
    }

    public static KeyParameterValue dateTime(long _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setDateTime(_value);
        return result;
    }

    public static KeyParameterValue blob(byte[] _value) {
        KeyParameterValue result = new KeyParameterValue();
        result.setBlob(_value);
        return result;
    }

    public int getTag() {
        return tag;
    }

    public int getInvalid() {
        return intValue(invalid);
    }

    public void setInvalid(int _value) {
        set(invalid, _value);
    }

    public int getAlgorithm() {
        return intValue(algorithm);
    }

    public void setAlgorithm(int _value) {
        set(algorithm, _value);
    }

    public int getBlockMode() {
        return intValue(blockMode);
    }

    public void setBlockMode(int _value) {
        set(blockMode, _value);
    }

    public int getPaddingMode() {
        return intValue(paddingMode);
    }

    public void setPaddingMode(int _value) {
        set(paddingMode, _value);
    }

    public int getDigest() {
        return intValue(digest);
    }

    public void setDigest(int _value) {
        set(digest, _value);
    }

    public int getEcCurve() {
        return intValue(ecCurve);
    }

    public void setEcCurve(int _value) {
        set(ecCurve, _value);
    }

    public int getOrigin() {
        return intValue(origin);
    }

    public void setOrigin(int _value) {
        set(origin, _value);
    }

    public int getKeyPurpose() {
        return intValue(keyPurpose);
    }

    public void setKeyPurpose(int _value) {
        set(keyPurpose, _value);
    }

    public int getHardwareAuthenticatorType() {
        return intValue(hardwareAuthenticatorType);
    }

    public void setHardwareAuthenticatorType(int _value) {
        set(hardwareAuthenticatorType, _value);
    }

    public int getSecurityLevel() {
        return intValue(securityLevel);
    }

    public void setSecurityLevel(int _value) {
        set(securityLevel, _value);
    }

    public boolean getBoolValue() {
        requireTag(boolValue);
        return (Boolean) value;
    }

    public void setBoolValue(boolean _value) {
        set(boolValue, _value);
    }

    public int getInteger() {
        return intValue(integer);
    }

    public void setInteger(int _value) {
        set(integer, _value);
    }

    public long getLongInteger() {
        requireTag(longInteger);
        return (Long) value;
    }

    public void setLongInteger(long _value) {
        set(longInteger, _value);
    }

    public long getDateTime() {
        requireTag(dateTime);
        return (Long) value;
    }

    public void setDateTime(long _value) {
        set(dateTime, _value);
    }

    public byte[] getBlob() {
        requireTag(blob);
        return ((byte[]) value).clone();
    }

    public void setBlob(byte[] _value) {
        set(blob, _value.clone());
    }

    private int intValue(int expectedTag) {
        requireTag(expectedTag);
        return (Integer) value;
    }

    private void requireTag(int expectedTag) {
        if (tag != expectedTag) {
            throw new IllegalStateException("bad access: " + expectedTag + ", " + tag + " is available");
        }
    }

    private void set(int newTag, Object newValue) {
        tag = newTag;
        value = newValue;
    }


    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        throw new UnsupportedOperationException("STUB!");
    }
}
