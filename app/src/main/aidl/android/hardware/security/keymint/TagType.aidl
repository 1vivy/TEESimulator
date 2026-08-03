/*
 * Copyright (C) The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;
/* @hide */
@Backing(type="int")
enum TagType {
  INVALID = (0 << 28) /* 0 */,
  ENUM = (1 << 28) /* 268435456 */,
  ENUM_REP = (2 << 28) /* 536870912 */,
  UINT = (3 << 28) /* 805306368 */,
  UINT_REP = (4 << 28) /* 1073741824 */,
  ULONG = (5 << 28) /* 1342177280 */,
  DATE = (6 << 28) /* 1610612736 */,
  BOOL = (7 << 28) /* 1879048192 */,
  BIGNUM = (8 << 28) /* -2147483648 */,
  BYTES = (9 << 28) /* -1879048192 */,
  ULONG_REP = (10 << 28) /* -1610612736 */,
}
