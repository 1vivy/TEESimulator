package android.hardware.security.keymint;

public class AttestationKey {
    public byte[] keyBlob;
    public KeyParameter[] attestKeyParams;
    public byte[] issuerSubjectName;
}
