/*
 * Copyright (C) 2018 The Android Open Source Project
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

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkSigningBlockNotFoundException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.util.ByteBufferDataSource;
import com.android.apksig.internal.util.ChainedDataSource;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.VerityTreeBuilder;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.RunnablesExecutor;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class ApkSigningBlockUtils {

    private static final char[] HEX_DIGITS = "01234567890abcdef".toCharArray();
    private static final long CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1024 * 1024;
    public static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;
    public static final byte[] APK_SIGNING_BLOCK_MAGIC =
          new byte[] {
              0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
              0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
          };
    private static final int VERITY_PADDING_BLOCK_ID = 0x42726577;

    public static final int VERSION_JAR_SIGNATURE_SCHEME = 1;
    public static final int VERSION_APK_SIGNATURE_SCHEME_V2 = 2;
    public static final int VERSION_APK_SIGNATURE_SCHEME_V3 = 3;


    /**
     * Returns positive number if {@code alg1} is preferred over {@code alg2}, {@code -1} if
     * {@code alg2} is preferred over {@code alg1}, and {@code 0} if there is no preference.
     */
    public static int compareSignatureAlgorithm(SignatureAlgorithm alg1, SignatureAlgorithm alg2) {
        ContentDigestAlgorithm digestAlg1 = alg1.getContentDigestAlgorithm();
        ContentDigestAlgorithm digestAlg2 = alg2.getContentDigestAlgorithm();
        return compareContentDigestAlgorithm(digestAlg1, digestAlg2);
    }

    /**
     * Returns a positive number if {@code alg1} is preferred over {@code alg2}, a negative number
     * if {@code alg2} is preferred over {@code alg1}, or {@code 0} if there is no preference.
     */
    private static int compareContentDigestAlgorithm(
            ContentDigestAlgorithm alg1,
            ContentDigestAlgorithm alg2) {
        switch (alg1) {
            case CHUNKED_SHA256:
                switch (alg2) {
                    case CHUNKED_SHA256:
                        return 0;
                    case CHUNKED_SHA512:
                    case VERITY_CHUNKED_SHA256:
                        return -1;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            case CHUNKED_SHA512:
                switch (alg2) {
                    case CHUNKED_SHA256:
                    case VERITY_CHUNKED_SHA256:
                        return 1;
                    case CHUNKED_SHA512:
                        return 0;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            case VERITY_CHUNKED_SHA256:
                switch (alg2) {
                    case CHUNKED_SHA256:
                        return 1;
                    case VERITY_CHUNKED_SHA256:
                        return 0;
                    case CHUNKED_SHA512:
                        return -1;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            default:
                throw new IllegalArgumentException("Unknown alg1: " + alg1);
        }
    }



    /**
     * Verifies integrity of the APK outside of the APK Signing Block by computing digests of the
     * APK and comparing them against the digests listed in APK Signing Block. The expected digests
     * are taken from {@code SignerInfos} of the provided {@code result}.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on Android. No errors are added to the {@code result} if the APK's
     * integrity is expected to verify on Android for each algorithm in
     * {@code contentDigestAlgorithms}.
     *
     * <p>The reason this method is currently not parameterized by a
     * {@code [minSdkVersion, maxSdkVersion]} range is that up until now content digest algorithms
     * exhibit the same behavior on all Android platform versions.
     */
    