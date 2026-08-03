/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */

parcelable BeginResult {
  long challenge;
  android.hardware.security.keymint.KeyParameter[] params;
  android.hardware.security.keymint.IKeyMintOperation operation;
}
