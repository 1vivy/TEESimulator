/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.secureclock;
/* @hide */
@RustDerive(Clone=true, Eq=true, Hash=true, Ord=true, PartialEq=true, PartialOrd=true)
parcelable TimeStampToken {
  long challenge;
  android.hardware.security.secureclock.Timestamp timestamp;
  byte[] mac;
}
