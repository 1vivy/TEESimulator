/*
 * Copyright (C) 2020 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;

parcelable RpcHardwareInfo {
    int versionNumber;
    String rpcAuthorName;
    int supportedEekCurve = CURVE_NONE;
    @nullable String uniqueId;
    int supportedNumKeysInCsr = 4;

    const int CURVE_NONE = 0;
    const int CURVE_P256 = 1;
    const int CURVE_25519 = 2;
    const int MIN_SUPPORTED_NUM_KEYS_IN_CSR = 20;
}
