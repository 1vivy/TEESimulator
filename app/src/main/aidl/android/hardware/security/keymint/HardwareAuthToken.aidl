/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@RustDerive(Clone=true, Eq=true, Hash=true, Ord=true, PartialEq=true, PartialOrd=true)
parcelable HardwareAuthToken {
  long challenge;
  long userId;
  long authenticatorId;
  android.hardware.security.keymint.HardwareAuthenticatorType authenticatorType = android.hardware.security.keymint.HardwareAuthenticatorType.NONE;
  android.hardware.security.secureclock.Timestamp timestamp;
  byte[] mac;
}
