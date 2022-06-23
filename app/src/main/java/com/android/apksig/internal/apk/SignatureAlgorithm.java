/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.apk;

import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.Pair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * APK Signing Block signature algorithm.
 */
public enum SignatureAlgorithm {
    // TODO reserve the 0x0000 ID to mean null
    /**
     * RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-256 in 1 MB chunks.
     */
    RSA_PSS_WITH_SHA256(
            0x0101,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "RSA",
            Pair.of("SHA256withRSA/PSS",
                    new PSSParameterSpec(
                            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1)),
            AndroidSdkVersion.N),

    /**
     * RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-512 in 1 MB chunks.
     */
    RSA_PSS_WITH_SHA512(
            0x0102,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "RSA",
            Pair.of(
                    "SHA512withRSA/PSS",
                    new PSSParameterSpec(
                            "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)),
            AndroidSdkVersion.N),

    /** RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
    RSA_PKCS1_V1_5_WITH_SHA256(
            0x0103,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "RSA",
            Pair.of("SHA256withRSA", null),
            AndroidSdkVersion.N),

    /** RSASSA-PKCS1-v1_5 with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks. */
    RSA_PKCS1_V1_5_WITH_SHA512(
            0x0104,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "RSA",
            Pair.of("SHA512withRSA", null),
            AndroidSdkVersion.N),

    /** ECDSA with SHA2-256 digest, c