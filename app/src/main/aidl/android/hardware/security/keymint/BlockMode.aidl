/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@Backing(type="int")
enum BlockMode {
  ECB = 1,
  CBC = 2,
  CTR = 3,
  GCM = 32,
}
