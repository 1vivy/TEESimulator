package android.hardware.security.keymint;

public class KeyCreationResult {
    public byte[] keyBlob;
    public KeyCharacteristics[] keyCharacteristics;
    public Certificate[] certificateChain;
}
