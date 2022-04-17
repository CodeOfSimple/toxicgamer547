
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
import com.android.apksig.apk.ApkSigningBlockNotFoundException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.apk.MinSdkVersionException;
import com.android.apksig.internal.util.ByteBufferDataSource;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.EocdRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.ReadableDataSink;
import com.android.apksig.zip.ZipFormatException;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * APK signer.
 *
 * <p>The signer preserves as much of the input APK as possible. For example, it preserves the
 * order of APK entries and preserves their contents, including compressed form and alignment of
 * data.
 *
 * <p>Use {@link Builder} to obtain instances of this signer.
 *
 * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
 */
public class ApkSigner {

    /**
     * Extensible data block/field header ID used for storing information about alignment of
     * uncompressed entries as well as for aligning the entries's data. See ZIP appnote.txt section
     * 4.5 Extensible data fields.
     */
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID = (short) 0xd935;

    /**
     * Minimum size (in bytes) of the extensible data block/field used for alignment of uncompressed
     * entries.
     */
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_MIN_SIZE_BYTES = 6;

    private static final short ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;

    /**
     * Name of the Android manifest ZIP entry in APKs.
     */
    private static final String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";

    private final List<SignerConfig> mSignerConfigs;
    private final Integer mMinSdkVersion;
    private final boolean mV1SigningEnabled;
    private final boolean mV2SigningEnabled;
    private final boolean mV3SigningEnabled;
    private final boolean mDebuggableApkPermitted;
    private final boolean mOtherSignersSignaturesPreserved;
    private final String mCreatedBy;

    private final ApkSignerEngine mSignerEngine;

    private final File mInputApkFile;
    private final DataSource mInputApkDataSource;

    private final File mOutputApkFile;
    private final DataSink mOutputApkDataSink;
    private final DataSource mOutputApkDataSource;

    private final SigningCertificateLineage mSigningCertificateLineage;

    private ApkSigner(
            List<SignerConfig> signerConfigs,
            Integer minSdkVersion,
            boolean v1SigningEnabled,
            boolean v2SigningEnabled,
            boolean v3SigningEnabled,
            boolean debuggableApkPermitted,
            boolean otherSignersSignaturesPreserved,
            String createdBy,
            ApkSignerEngine signerEngine,
            File inputApkFile,
            DataSource inputApkDataSource,
            File outputApkFile,
            DataSink outputApkDataSink,
            DataSource outputApkDataSource,
            SigningCertificateLineage signingCertificateLineage) {

        mSignerConfigs = signerConfigs;
        mMinSdkVersion = minSdkVersion;
        mV1SigningEnabled = v1SigningEnabled;
        mV2SigningEnabled = v2SigningEnabled;
        mV3SigningEnabled = v3SigningEnabled;
        mDebuggableApkPermitted = debuggableApkPermitted;
        mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
        mCreatedBy = createdBy;

        mSignerEngine = signerEngine;

        mInputApkFile = inputApkFile;
        mInputApkDataSource = inputApkDataSource;

        mOutputApkFile = outputApkFile;
        mOutputApkDataSink = outputApkDataSink;
        mOutputApkDataSource = outputApkDataSource;

        mSigningCertificateLineage = signingCertificateLineage;
    }

    /**
     * Signs the input APK and outputs the resulting signed APK. The input APK is not modified.
     *
     * @throws IOException if an I/O error is encountered while reading or writing the APKs
     * @throws ApkFormatException if the input APK is malformed
     * @throws NoSuchAlgorithmException if the APK signatures cannot be produced or verified because
     *         a required cryptographic algorithm implementation is missing
     * @throws InvalidKeyException if a signature could not be generated because a signing key is
     *         not suitable for generating the signature
     * @throws SignatureException if an error occurred while generating or verifying a signature
     * @throws IllegalStateException if this signer's configuration is missing required information
     *         or if the signing engine is in an invalid state.
     */
    public void sign()
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
                    SignatureException, IllegalStateException {
        Closeable in = null;
        DataSource inputApk;
        try {
            if (mInputApkDataSource != null) {
                inputApk = mInputApkDataSource;
            } else if (mInputApkFile != null) {
                RandomAccessFile inputFile = new RandomAccessFile(mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }

            Closeable out = null;
            try {
                DataSink outputApkOut;
                DataSource outputApkIn;
                if (mOutputApkDataSink != null) {
                    outputApkOut = mOutputApkDataSink;
                    outputApkIn = mOutputApkDataSource;
                } else if (mOutputApkFile != null) {
                    RandomAccessFile outputFile = new RandomAccessFile(mOutputApkFile, "rw");
                    out = outputFile;
                    outputFile.setLength(0);
                    outputApkOut = DataSinks.asDataSink(outputFile);
                    outputApkIn = DataSources.asDataSource(outputFile);
                } else {
                    throw new IllegalStateException("Output APK not specified");
                }

                sign(inputApk, outputApkOut, outputApkIn);
            } finally {
                if (out != null) {
                    out.close();
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private void sign(
            DataSource inputApk,
            DataSink outputApkOut,
            DataSource outputApkIn)
                    throws IOException, ApkFormatException, NoSuchAlgorithmException,
                            InvalidKeyException, SignatureException {
        // Step 1. Find input APK's main ZIP sections
        ApkUtils.ZipSections inputZipSections;
        try {
            inputZipSections = ApkUtils.findZipSections(inputApk);
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
        }
        long inputApkSigningBlockOffset = -1;
        DataSource inputApkSigningBlock = null;
        try {
            ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                    ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
            inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
            inputApkSigningBlock = apkSigningBlockInfo.getContents();
        } catch (ApkSigningBlockNotFoundException e) {
            // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
            // contain this block. It's only needed if the APK is signed using APK Signature Scheme
            // v2 and/or v3.
        }
        DataSource inputApkLfhSection =
                inputApk.slice(
                        0,
                        (inputApkSigningBlockOffset != -1)
                                ? inputApkSigningBlockOffset
                                : inputZipSections.getZipCentralDirectoryOffset());

        // Step 2. Parse the input APK's ZIP Central Directory
        ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
        List<CentralDirectoryRecord> inputCdRecords =
                parseZipCentralDirectory(inputCd, inputZipSections);

        List<Pattern> pinPatterns = extractPinPatterns(inputCdRecords, inputApkLfhSection);
        List<Hints.ByteRange> pinByteRanges = pinPatterns == null ? null : new ArrayList<>();

        // Step 3. Obtain a signer engine instance
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);