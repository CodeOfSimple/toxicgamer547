
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

package com.android.apksig;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.AndroidBinXmlParser;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.apk.v2.V2SchemeVerifier;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.RunnablesExecutor;
import com.android.apksig.zip.ZipFormatException;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * APK signature verifier which mimics the behavior of the Android platform.
 *
 * <p>The verifier is designed to closely mimic the behavior of Android platforms. This is to enable
 * the verifier to be used for checking whether an APK's signatures are expected to verify on
 * Android.
 *
 * <p>Use {@link Builder} to obtain instances of this verifier.
 *
 * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
 */
public class ApkVerifier {

    private static final Map<Integer, String> SUPPORTED_APK_SIG_SCHEME_NAMES =
            loadSupportedApkSigSchemeNames();

    private static Map<Integer,String> loadSupportedApkSigSchemeNames() {
        Map<Integer, String> supportedMap = new HashMap<>(2);
        supportedMap.put(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2, "APK Signature Scheme v2");
        supportedMap.put(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3, "APK Signature Scheme v3");
        return supportedMap;
    }

    private final File mApkFile;
    private final DataSource mApkDataSource;

    private final Integer mMinSdkVersion;
    private final int mMaxSdkVersion;

    private ApkVerifier(
            File apkFile,
            DataSource apkDataSource,
            Integer minSdkVersion,
            int maxSdkVersion) {
        mApkFile = apkFile;
        mApkDataSource = apkDataSource;
        mMinSdkVersion = minSdkVersion;
        mMaxSdkVersion = maxSdkVersion;
    }

    /**
     * Verifies the APK's signatures and returns the result of verification. The APK can be
     * considered verified iff the result's {@link Result#isVerified()} returns {@code true}.
     * The verification result also includes errors, warnings, and information about signers such
     * as their signing certificates.
     *
     * <p>Verification succeeds iff the APK's signature is expected to verify on all Android
     * platform versions specified via the {@link Builder}. If the APK's signature is expected to
     * not verify on any of the specified platform versions, this method returns a result with one
     * or more errors and whose {@link Result#isVerified()} returns {@code false}, or this method
     * throws an exception.
     *
     * @throws IOException if an I/O error is encountered while reading the APK
     * @throws ApkFormatException if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *         required cryptographic algorithm implementation is missing
     * @throws IllegalStateException if this verifier's configuration is missing required
     *         information.
     */
    public Result verify() throws IOException, ApkFormatException, NoSuchAlgorithmException,
            IllegalStateException {
        Closeable in = null;
        try {
            DataSource apk;
            if (mApkDataSource != null) {
                apk = mApkDataSource;
            } else if (mApkFile != null) {
                RandomAccessFile f = new RandomAccessFile(mApkFile, "r");
                in = f;
                apk = DataSources.asDataSource(f, 0, f.length());
            } else {
                throw new IllegalStateException("APK not provided");
            }
            return verify(apk);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * Verifies the APK's signatures and returns the result of verification. The APK can be
     * considered verified iff the result's {@link Result#isVerified()} returns {@code true}.
     * The verification result also includes errors, warnings, and information about signers.
     *
     * @param apk APK file contents
     *
     * @throws IOException if an I/O error is encountered while reading the APK
     * @throws ApkFormatException if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *         required cryptographic algorithm implementation is missing
     */
    private Result verify(DataSource apk)
            throws IOException, ApkFormatException, NoSuchAlgorithmException {
        if (mMinSdkVersion != null) {
            if (mMinSdkVersion < 0) {
                throw new IllegalArgumentException(
                        "minSdkVersion must not be negative: " + mMinSdkVersion);
            }
            if ((mMinSdkVersion != null) && (mMinSdkVersion > mMaxSdkVersion)) {
                throw new IllegalArgumentException(
                        "minSdkVersion (" + mMinSdkVersion + ") > maxSdkVersion (" + mMaxSdkVersion
                                + ")");
            }
        }
        int maxSdkVersion = mMaxSdkVersion;

        ApkUtils.ZipSections zipSections;
        try {
            zipSections = ApkUtils.findZipSections(apk);
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
        }

        ByteBuffer androidManifest = null;

        int minSdkVersion;
        if (mMinSdkVersion != null) {
            // No need to obtain minSdkVersion from the APK's AndroidManifest.xml
            minSdkVersion = mMinSdkVersion;
        } else {
            // Need to obtain minSdkVersion from the APK's AndroidManifest.xml
            if (androidManifest == null) {
                androidManifest = getAndroidManifestFromApk(apk, zipSections);
            }
            minSdkVersion =
                    ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(androidManifest.slice());
            if (minSdkVersion > mMaxSdkVersion) {
                throw new IllegalArgumentException(
                        "minSdkVersion from APK (" + minSdkVersion + ") > maxSdkVersion ("
                                + mMaxSdkVersion + ")");
            }
        }

        Result result = new Result();

        // The SUPPORTED_APK_SIG_SCHEME_NAMES contains the mapping from version number to scheme
        // name, but the verifiers use this parameter as the schemes supported by the target SDK
        // range. Since the code below skips signature verification based on max SDK the mapping of
        // supported schemes needs to be modified to ensure the verifiers do not report a stripped
        // signature for an SDK range that does not support that signature version. For instance an
        // APK with V1, V2, and V3 signatures and a max SDK of O would skip the V3 signature
        // verification, but the SUPPORTED_APK_SIG_SCHEME_NAMES contains version 3, so when the V2
        // verification is performed it would see the stripping protection attribute, see that V3
        // is in the list of supported signatures, and report a stripped signature.
        Map<Integer, String> supportedSchemeNames;
        if (maxSdkVersion >= AndroidSdkVersion.P) {
            supportedSchemeNames = SUPPORTED_APK_SIG_SCHEME_NAMES;
        } else if (maxSdkVersion >= AndroidSdkVersion.N) {
            supportedSchemeNames = new HashMap<>(1);
            supportedSchemeNames.put(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                    SUPPORTED_APK_SIG_SCHEME_NAMES.get(
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2));
        } else {
            supportedSchemeNames = Collections.EMPTY_MAP;
        }
        // Android N and newer attempts to verify APKs using the APK Signing Block, which can
        // include v2 and/or v3 signatures.  If none is found, it falls back to JAR signature
        // verification. If the signature is found but does not verify, the APK is rejected.
        Set<Integer> foundApkSigSchemeIds = new HashSet<>(2);
        foundApkSigSchemeIds.add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
        FutureTask<ApkSigningBlockUtils.Result> taskV2 = new FutureTask<>(() -> {
            if (maxSdkVersion >= AndroidSdkVersion.N) {
                // Attempt to verify the APK using v2 signing if necessary. Platforms prior to Android P
                // ignore APK Signature Scheme v3 signatures and always attempt to verify either JAR or
                // APK Signature Scheme v2 signatures.  Android P onwards verifies v2 signatures only if
                // no APK Signature Scheme v3 (or newer scheme) signatures were found.
                if (minSdkVersion < AndroidSdkVersion.P || foundApkSigSchemeIds.isEmpty()) {
                    try {
                        RunnablesExecutor executor = RunnablesExecutor.SINGLE_THREADED;
                        return V2SchemeVerifier.verify(
                                executor,
                                apk,
                                zipSections,
                                supportedSchemeNames,
                                foundApkSigSchemeIds,
                                Math.max(minSdkVersion, AndroidSdkVersion.N),
                                maxSdkVersion);
                    } catch (ApkSigningBlockUtils.SignatureNotFoundException ignored) {
                        // v2 signature not required
                    }
                }
            }
            return null;
        });
        // Android O and newer requires that APKs targeting security sandbox version 2 and higher
        // are signed using APK Signature Scheme v2 or newer.
        if (maxSdkVersion >= AndroidSdkVersion.O) {
            if (androidManifest == null) {
                androidManifest = getAndroidManifestFromApk(apk, zipSections);
            }
            int targetSandboxVersion =
                    getTargetSandboxVersionFromBinaryAndroidManifest(androidManifest.slice());
            if (targetSandboxVersion > 1) {
                if (foundApkSigSchemeIds.isEmpty()) {
                    result.addError(
                            Issue.NO_SIG_FOR_TARGET_SANDBOX_VERSION,
                            targetSandboxVersion);
                }
            }
        }

        // Attempt to verify the APK using JAR signing if necessary. Platforms prior to Android N
        // ignore APK Signature Scheme v2 signatures and always attempt to verify JAR signatures.
        // Android N onwards verifies JAR signatures only if no APK Signature Scheme v2 (or newer
        // scheme) signatures were found.
        FutureTask<V1SchemeVerifier.Result> taskV1 = new FutureTask<>(() -> {
            if ((minSdkVersion < AndroidSdkVersion.N) || (foundApkSigSchemeIds.isEmpty())) {
                return V1SchemeVerifier.verify(
                        apk,
                        zipSections,
                        supportedSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion,
                        maxSdkVersion);
            }
            return null;
        });
        ThreadPoolExecutor executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(2);
        executorService.submit(taskV1);
        executorService.submit(taskV2);
        executorService.shutdown();
        try {
            result.mergeFrom(taskV1.get());
            result.mergeFrom(taskV2.get());
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (result.containsErrors()) {
            return result;
        }

        // Check whether v1 and v2 scheme signer identifies match, provided both v1 and v2
        // signatures verified.
        if ((result.isVerifiedUsingV1Scheme()) && (result.isVerifiedUsingV2Scheme())) {
            ArrayList<Result.V1SchemeSignerInfo> v1Signers =
                    new ArrayList<>(result.getV1SchemeSigners());
            ArrayList<Result.V2SchemeSignerInfo> v2Signers =
                    new ArrayList<>(result.getV2SchemeSigners());
            ArrayList<ByteArray> v1SignerCerts = new ArrayList<>();
            ArrayList<ByteArray> v2SignerCerts = new ArrayList<>();
            for (Result.V1SchemeSignerInfo signer : v1Signers) {
                try {
                    v1SignerCerts.add(new ByteArray(signer.getCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    throw new RuntimeException(
                            "Failed to encode JAR signer " + signer.getName() + " certs", e);
                }
            }
            for (Result.V2SchemeSignerInfo signer : v2Signers) {
                try {
                    v2SignerCerts.add(new ByteArray(signer.getCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    throw new RuntimeException(
                            "Failed to encode APK Signature Scheme v2 signer (index: "
                                    + signer.getIndex() + ") certs",
                            e);
                }
            }

            for (int i = 0; i < v1SignerCerts.size(); i++) {
                ByteArray v1Cert = v1SignerCerts.get(i);
                if (!v2SignerCerts.contains(v1Cert)) {
                    Result.V1SchemeSignerInfo v1Signer = v1Signers.get(i);
                    v1Signer.addError(Issue.V2_SIG_MISSING);
                    break;
                }
            }
            for (int i = 0; i < v2SignerCerts.size(); i++) {
                ByteArray v2Cert = v2SignerCerts.get(i);
                if (!v1SignerCerts.contains(v2Cert)) {
                    Result.V2SchemeSignerInfo v2Signer = v2Signers.get(i);
                    v2Signer.addError(Issue.JAR_SIG_MISSING);
                    break;
                }
            }
        }

        // If there is a v3 scheme signer and an earlier scheme signer, make sure that there is a
        // match, or in the event of signing certificate rotation, that the v1/v2 scheme signer
        // matches the oldest signing certificate in the provided SigningCertificateLineage
        if (result.isVerifiedUsingV3Scheme()
                && (result.isVerifiedUsingV1Scheme() || result.isVerifiedUsingV2Scheme())) {
            SigningCertificateLineage lineage = result.getSigningCertificateLineage();
            X509Certificate oldSignerCert;
            if (result.isVerifiedUsingV1Scheme()) {
                List<Result.V1SchemeSignerInfo> v1Signers = result.getV1SchemeSigners();
                if (v1Signers.size() != 1) {
                    // APK Signature Scheme v3 only supports single-signers, error to sign with
                    // multiple and then only one
                    result.addError(Issue.V3_SIG_MULTIPLE_PAST_SIGNERS);