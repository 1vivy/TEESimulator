/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@RustDerive(Clone=true, Eq=true, Hash=true, Ord=true, PartialEq=true, PartialOrd=true)
parcelable AttestationKey {
  byte[] keyBlob;
  android.hardware.security.keymint.KeyParameter[] attestKeyParams;
  byte[] issuerSubjectName;
}
