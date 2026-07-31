package android.hardware.security.keymint;

public class BeginResult {
    public long challenge;
    public KeyParameter[] params;
    public IKeyMintOperation operation;
}
