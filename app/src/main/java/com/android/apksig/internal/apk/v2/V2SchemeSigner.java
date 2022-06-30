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

package com.android.apksig.internal.apk.v2;

import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements;
import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes;
import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodeCertificates;
import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodePublicKey;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * APK Signature Scheme v2 signer.
 *
 * <p>APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
 * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
 * uncompressed contents of ZIP entries.
 *
 * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
 */
public abstract class V2SchemeSigner {
    /*
     * The two main goals of APK Signature Scheme v2 are:
     * 1. Detect any unauthorized modifications to the APK. This is achieved by making the signature
     *    cover every byte of the APK being signed.
     * 2. Enable much faster signature and integrity verification. This is achieved by requiring
     *    only a minimal amount of APK parsing before the signature is verified, thus completely
     *    bypassing ZIP entry decompression and by making integrity verification parallelizable by
     *    employing a hash tree.
     *
     * The generated signature block is wrapped into an APK Signing Block and inserted into the
     * original APK immediately before the start of ZIP Central Directory. This is to ensure that
     * JAR and ZIP parsers continue to work on the signed APK. The APK Signing Block is designed for
     * extensibility. For example, a future signature scheme could insert its signatures there as
     * well. The contract of the APK Signing Block is that all contents outside of the block must be
     * protected by signatures inside the block.
     */

    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;

    /** Hidden constructor to prevent instantiation. */
    private V2SchemeSigner() {}

    /**
     * Gets the APK Signature Scheme v2 signature algorithms to be used for signing an APK using the
     * provided key.
     *
     * @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
     *        AndroidManifest.xml minSdkVersion attribute).
     *
     * @throws InvalidKeyException if the provided key is not suitable for signing APKs using
     *         APK Signature Scheme v2
     */
    public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(
            PublicKey signingKey, int minSdkVersion, boolean apkSigningBlockPaddingSupported)
            throws InvalidKeyException {
        String keyAlgorithm = signingKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgor