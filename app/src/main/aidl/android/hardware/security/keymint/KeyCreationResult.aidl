/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */

parcelable KeyCreationResult {
  byte[] keyBlob;
  android.hardware.security.keymint.KeyCharacteristics[] keyCharacteristics;
  android.hardware.security.keymint.Certificate[] certificateChain;
}
