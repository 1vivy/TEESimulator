/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */

parcelable KeyCharacteristics {
  android.hardware.security.keymint.SecurityLevel securityLevel = android.hardware.security.keymint.SecurityLevel.SOFTWARE;
  android.hardware.security.keymint.KeyParameter[] authorizations;
}
