/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@RustDerive(Clone=true, Eq=true, Hash=true, Ord=true, PartialEq=true, PartialOrd=true)
parcelable KeyMintHardwareInfo {
  int versionNumber;
  android.hardware.security.keymint.SecurityLevel securityLevel = android.hardware.security.keymint.SecurityLevel.SOFTWARE;
  @utf8InCpp String keyMintName;
  @utf8InCpp String keyMintAuthorName;
  boolean timestampTokenRequired;
}
