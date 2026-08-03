/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
interface IKeyMintDevice {
  android.hardware.security.keymint.KeyMintHardwareInfo getHardwareInfo();
  void addRngEntropy(in byte[] data);
  android.hardware.security.keymint.KeyCreationResult generateKey(in android.hardware.security.keymint.KeyParameter[] keyParams, in @nullable android.hardware.security.keymint.AttestationKey attestationKey);
  android.hardware.security.keymint.KeyCreationResult importKey(in android.hardware.security.keymint.KeyParameter[] keyParams, in android.hardware.security.keymint.KeyFormat keyFormat, in byte[] keyData, in @nullable android.hardware.security.keymint.AttestationKey attestationKey);
  android.hardware.security.keymint.KeyCreationResult importWrappedKey(in byte[] wrappedKeyData, in byte[] wrappingKeyBlob, in byte[] maskingKey, in android.hardware.security.keymint.KeyParameter[] unwrappingParams, in long passwordSid, in long biometricSid);
  byte[] upgradeKey(in byte[] keyBlobToUpgrade, in android.hardware.security.keymint.KeyParameter[] upgradeParams);
  void deleteKey(in byte[] keyBlob);
  void deleteAllKeys();
  void destroyAttestationIds();
  android.hardware.security.keymint.BeginResult begin(in android.hardware.security.keymint.KeyPurpose purpose, in byte[] keyBlob, in android.hardware.security.keymint.KeyParameter[] params, in @nullable android.hardware.security.keymint.HardwareAuthToken authToken);
  /**
   * @deprecated Method has never been used due to design limitations
   */
  void deviceLocked(in boolean passwordOnly, in @nullable android.hardware.security.secureclock.TimeStampToken timestampToken);
  void earlyBootEnded();
  byte[] convertStorageKeyToEphemeral(in byte[] storageKeyBlob);
  android.hardware.security.keymint.KeyCharacteristics[] getKeyCharacteristics(in byte[] keyBlob, in byte[] appId, in byte[] appData);
  byte[16] getRootOfTrustChallenge();
  byte[] getRootOfTrust(in byte[16] challenge);
  void sendRootOfTrust(in byte[] rootOfTrust);
  void setAdditionalAttestationInfo(in android.hardware.security.keymint.KeyParameter[] info);
  const int AUTH_TOKEN_MAC_LENGTH = 32;
}
