/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
interface IKeyMintOperation {
  void updateAad(in byte[] input, in @nullable android.hardware.security.keymint.HardwareAuthToken authToken, in @nullable android.hardware.security.secureclock.TimeStampToken timeStampToken);
  byte[] update(in byte[] input, in @nullable android.hardware.security.keymint.HardwareAuthToken authToken, in @nullable android.hardware.security.secureclock.TimeStampToken timeStampToken);
  byte[] finish(in @nullable byte[] input, in @nullable byte[] signature, in @nullable android.hardware.security.keymint.HardwareAuthToken authToken, in @nullable android.hardware.security.secureclock.TimeStampToken timestampToken, in @nullable byte[] confirmationToken);
  void abort();
}
