/*
 * Copyright (C) 2020 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.hardware.security.keymint;

import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.MacedPublicKey;
import android.hardware.security.keymint.ProtectedData;
import android.hardware.security.keymint.RpcHardwareInfo;

interface IRemotelyProvisionedComponent {
    RpcHardwareInfo getHardwareInfo();
    byte[] generateEcdsaP256KeyPair(in boolean testMode, out MacedPublicKey macedPublicKey);
    byte[] generateCertificateRequest(
        in boolean testMode,
        in MacedPublicKey[] keysToSign,
        in byte[] endpointEncryptionCertChain,
        in byte[] challenge,
        out DeviceInfo deviceInfo,
        out ProtectedData protectedData
    );
    byte[] generateCertificateRequestV2(in MacedPublicKey[] keysToSign, in byte[] challenge);

    const int STATUS_FAILED = 1;
    const int STATUS_INVALID_MAC = 2;
    const int STATUS_PRODUCTION_KEY_IN_TEST_REQUEST = 3;
    const int STATUS_TEST_KEY_IN_PRODUCTION_REQUEST = 4;
    const int STATUS_INVALID_EEK = 5;
    const int STATUS_REMOVED = 6;
}
