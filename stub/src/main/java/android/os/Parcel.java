package android.os;

import java.util.ArrayList;
import java.util.List;

public class Parcel {
    private final List<Object> values = new ArrayList<>();
    private int position;

    public static Parcel obtain() {
        return new Parcel();
    }

    public void recycle() {}

    public void setDataPosition(int position) {
        this.position = position;
    }

    public int dataPosition() {
        return position;
    }

    public int dataSize() {
        return values.size();
    }

    public void appendFrom(Parcel source, int offset, int length) {
        values.addAll(source.values.subList(offset, offset + length));
    }

    public void writeInterfaceToken(String descriptor) {
        values.add(descriptor);
    }

    public void enforceInterface(String descriptor) {
        String actual = (String) values.get(position++);
        if (!descriptor.equals(actual)) throw new SecurityException("wrong interface descriptor");
    }

    public void writeLong(long value) {
        values.add(value);
    }

    public long readLong() {
        return (Long) values.get(position++);
    }

    public void writeInt(int value) {
        values.add(value);
    }

    public int readInt() {
        return (Integer) values.get(position++);
    }

    public void writeBoolean(boolean value) {
        values.add(value);
    }

    public boolean readBoolean() {
        return (Boolean) values.get(position++);
    }

    public void writeString(String value) {
        values.add(value);
    }

    public String readString() {
        return (String) values.get(position++);
    }

    public void writeStrongBinder(IBinder value) {
        values.add(value);
    }

    public IBinder readStrongBinder() {
        return (IBinder) values.get(position++);
    }

    public <T extends Parcelable> void writeTypedObject(T value, int flags) {
        values.add(value);
    }

    @SuppressWarnings("unchecked")
    public <T> T readTypedObject(Parcelable.Creator<T> creator) {
        return (T) values.get(position++);
    }

    public <T extends Parcelable> void writeTypedArray(T[] value, int flags) {
        values.add(value);
    }

    @SuppressWarnings("unchecked")
    public <T> T[] createTypedArray(Parcelable.Creator<T> creator) {
        return (T[]) values.get(position++);
    }

    public void writeByteArray(byte[] value) {
        values.add(value);
    }

    public void writeNoException() {
        values.add(null);
    }

    public void writeException(Exception value) {
        values.add(value);
    }

    public void readException() {
        Object value = values.get(position++);
        if (value instanceof RuntimeException) throw (RuntimeException) value;
        if (value instanceof Exception) throw new RuntimeException((Exception) value);
    }
}
