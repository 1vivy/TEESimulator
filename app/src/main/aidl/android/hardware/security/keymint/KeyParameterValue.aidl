/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@RustDerive(Clone=true, Eq=true, Hash=true, Ord=true, PartialEq=true, PartialOrd=true)
union KeyParameterValue {
  int invalid;
  android.hardware.security.keymint.Algorithm algorithm;
  android.hardware.security.keymint.BlockMode blockMode;
  android.hardware.security.keymint.PaddingMode paddingMode;
  android.hardware.security.keymint.Digest digest;
  android.hardware.security.keymint.EcCurve ecCurve;
  android.hardware.security.keymint.KeyOrigin origin;
  android.hardware.security.keymint.KeyPurpose keyPurpose;
  android.hardware.security.keymint.HardwareAuthenticatorType hardwareAuthenticatorType;
  android.hardware.security.keymint.SecurityLevel securityLevel;
  boolean boolValue;
  int integer;
  long longInteger;
  long dateTime;
  byte[] blob;
}
