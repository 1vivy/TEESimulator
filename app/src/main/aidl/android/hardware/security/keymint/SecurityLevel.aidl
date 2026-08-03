/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@Backing(type="int")
enum SecurityLevel {
  SOFTWARE = 0,
  TRUSTED_ENVIRONMENT = 1,
  STRONGBOX = 2,
  KEYSTORE = 100,
}
