/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@Backing(type="int")
enum HardwareAuthenticatorType {
  NONE = 0,
  PASSWORD = (1 << 0) /* 1 */,
  FINGERPRINT = (1 << 1) /* 2 */,
  ANY = 0xFFFFFFFF,
}
