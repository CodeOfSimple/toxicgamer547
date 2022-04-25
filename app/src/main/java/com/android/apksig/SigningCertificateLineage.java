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

package com.android.apksig;

import static com.android.apksig.internal.apk.ApkSigningBlockUtils.getLengthPrefixedSlice;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.SignatureInfo;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SigningCertificateLineage;
import com.android.apksig.internal.apk.v3.V3SigningCertificateLineage.SigningCertificateNode;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.RandomAccessFileDataSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipFormatException;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * APK Signer Lineage.
 *
 * <p>The signer lineage contains a history of signing certificates with each ancestor attesting to
 * the validity of its descendant.  Each additional descendant represents a new identity that can be
 * used to sign an APK, and each generation has accompanying attributes which represent how the
 * APK would like to view the older signing certificates, specifically how they should be trusted in
 * certain situations.
 *
 * <p> Its primary use is to enable APK Signing Certificate Rotation.  The Android platform verifies
 * the APK Signer Lineage, and if the current signing certificate for the APK is in the Signer
 * Lineage, and the Lineage contains the certificate the platform associates with the APK, it will
 * allow upgrades to the new certificate.
 *
 * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
 */
public class SigningCertificateLineage {

    public final static int MAGIC = 0x3eff39d1;

    private final static int FIRST_VERSION = 1;

    private static final int CURRENT_VERSION = FIRST_VERSION;

    /** accept data from already installed pkg with this cert */
    private static final int PAST_CERT_INSTALLED_DATA = 1;

    /** accept sharedUserId with pkg with this cert */
    private static final int PAST_CERT_SHARED_USER_ID = 2;

    /** grant SIGNATURE permissions to pkgs with this cert */
    private static final int PAST_CERT_PERMISSION = 4;

    /**
     * Enable updates back to this certificate.  WARNING: this effectively removes any benefit of
     * signing certificate changes, since a compromised key could retake control of an app even
     * after change, and should only be used if there is a problem encountered when trying to ditch
     * an older cert.
     */
    private static final int PAST_CERT_ROLLBACK = 8;

    /**
     * Preserve authenticator module-based access in AccountManager gated by signing certificate.
     */
    private static final int PAST_CERT_AUTH = 16;

    private final int mMinSdkVersion;

    /**
     * The signing lineage is just a list of nodes, with the first being the original signing
     * certificate and the most recent being the one with which the APK is to actually be signed.
     */
    private final List<SigningCertificateNode> mSigningLineage;

    private SigningCertificateLineage(int minSdkVersion, List<SigningCertificateNode> list) {
        mMinSdkVersion = minSdkVersion;
        mSigningLineage = list;
    }

    private static SigningCertificateLineage createSigningLineage(
            int minSdkVersion, SignerConfig parent, SignerCapabilities parentCapabilities,
            SignerConfig child, SignerCapabilities childCapabilities)
            throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException {
        SigningCertificateLineage signingCertificateLineage =
                new SigningCertificateLineage(minSdkVersion, new ArrayList<>());
        signingCertificateLineage =
                signingCertificateLineage.spawnFirstDescendant(parent, parentCapabilities);
        return signingCertificateLineage.spawnDescendant(parent, child, childCapabilities);
    }

    public static SigningCertificateLineage readFromFile(File file)
            throws IOException {
        if (file == null) {
            throw new NullPointerException("file == null");
        }
        RandomAccessFile inputFile = new RandomAccessFile(file, "r");
        return readFromDataSource(DataSources.asDataSource(inputFile));
    }

    public static SigningCertificateLineage readFromDataSource(DataSource dataSource)
            throws IOException {
        if (dataSource == null) {
            throw new NullPointerException("dataSource == null");
        }
        ByteBuffer inBuff = dataSource.getByteBuffer(0, (int) dataSource.size());
        inBuff.order(ByteOrder.LITTLE_ENDIAN);
        return read(inBuff);
    }

    /**
     * Extracts a Signing Certificate Lineage from a v3 signer proof-of-rotation attribute.
     *
     * <note>
     *     this may not give a complete representation of an APK's signing certificate history,
     *     since the APK may have multiple signers corresponding to different platform versions.
     *     Use <code> readFromApkFile</code> to handle this case.
     * </note>
     * @param attrValue
     */
    public static SigningCertificateLineage readFromV3AttributeValue(byte[] attrValue)
            throws IOException {
        List<SigningCertificateNode> parsedLineage =
                V3SigningCertificateLineage.readSigningCertificateLineage(ByteBuffer.wrap(
                        attrValue).order(ByteOrder.LITTLE_ENDIAN));
        int minSdkVersion = calculateMinSdkVersion(parsedLineage);
        return  new SigningCertificateLineage(minSdkVersion, parsedLineage);
    }

    /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the V3
     * signature block of the provided APK File.
     *
     * @throws IllegalArgumentException if the provided APK does not contain a V3 signature block,
     * or if the V3 signature block does not contain a valid lineage.
     */
    public static SigningCertificateLineage readFromApkFile(File apkFile)
            throws IOException, ApkFormatException {
        try (RandomAccessFile f = new RandomAccessFile(apkFile, "r")) {
            DataSource apk = DataSources.asDataSource(f, 0, f.length());
            return readFromApkDataSource(apk);
        }
    }

    /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the V3
     * signature block of the provided APK DataSource.
     *
     * @throws IllegalArgumentException if the provided APK does not contain a V3 signature block,
     * or if the V3 signature block does not contain a valid lineage.
     */
    public static SigningCertificateLineage readFromApkDataSource(DataSource apk)
            throws IOException, ApkFormatException {
        SignatureInfo signatureInfo;
        try {
            ApkUtils.ZipSections zipSections = ApkUtils.findZipSections(apk);
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                    ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
            signatureInfo =
                    ApkSigningBlockUtils.findSignature(apk, zipSections,
                            V3SchemeSigner.APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result);
        } catch (ZipFormatException e) {
            throw new ApkFormatException(e.getMessage());
        } catch (ApkSigningBlockUtils.SignatureNotFoundException e) {
            throw new IllegalArgumentException(
                    "The provided APK does not contain a valid V3 signature block.");
        }

        // FORMAT:
        // * length-prefixed sequence of length-prefixed signers:
        //   * length-prefixed signed data
        //   * minSDK
        //   * maxSDK
        //   * length-prefixed sequence of length-prefixed signatures
        //   * length-prefixed public key
        ByteBuffer signers = getLengthPrefixedSlice(signatureInfo.signatureBlock);
        List<SigningCertificateLineage> lineages = new ArrayList<>(1);
        while (signers.hasRemaining()) {
            ByteBuffer signer = getLengthPrefixedSlice(signers);
            ByteBuffer signedData = getLengthPrefixedSlice(signer);
            try {
                SigningCertificateLineage lineage = readFromSignedData(signedData);
                lineages.add(lineage);
            } catch (IllegalArgumentException ignored) {
                // The current signer block does not contain a valid lineage, but it is possible
                // another block will.
            }
        }
        SigningCertificateLineage result;
        if (lineages.isEmpty()) {
            throw new IllegalArgumentException(
                    "The provided APK does not contain a valid lineage.");
        } else if (lineages.size() > 1) {
            result = consolidateLineages(lineages);
        } else {
            result = lineages.get(0);
        }
        return result;
    }

    /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the provided
     * signed data portion of a signer in a V3 signature block.
     *
     * @throws IllegalArgumentException if the provided signed data does not contain a valid
     * lineage.
     */
    public static SigningCertificateLineage readFromSignedData(ByteBuffer signedData)
            throws IOException, ApkFormatException {
        // FORMAT:
        //   * length-prefixed sequence of length-prefixed digests:
        //   * length-prefixed sequence of certificates:
        //     * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
        //   * uint-32: minSdkVersion
        //   * uint-32: maxSdkVersion
        //   * length-prefixed sequence of length-prefixed additional attributes:
        //     * uint32: ID
        //     * (length - 4) bytes: value
        //     * uint32: Proof-of-rotation ID: 0x3ba06f8c
        //     * length-prefixed proof-of-rotation structure
        // consume the digests through the maxSdkVersion to reach the lineage in the attributes
        getLengthPrefixedSlice(signedData);
        getLengthPrefixedSlice(signedData);
        signedData.getInt();
        signedData.getInt();
        // iterate over the additional attributes adding any lineages to the List
        ByteBuffer additionalAttributes = getLengthPrefixedSlice(signedData);
        List<SigningCertificateLineage> lineages = new ArrayList<>(1);
        while (additionalAttributes.hasRemaining()) {
            ByteBuffer attribute = getLengthPrefixedSlice(additionalAttributes);
            int id = attribute.getInt();
            if (id == V3SchemeSigner.PROOF_OF_ROTATION_ATTR_ID) {
                byte[] value = ByteBufferUtils.toByteArray(attribute);
                SigningCertificateLineage lineage = readFromV3AttributeValue(value);
                lineages.add(lineage);
            }
        }
        SigningCertificateLineage result;
        // There should only be a single attribute with the lineage, but if there are multiple then
        // attempt to consolidate the lineages.
        if (lineages.isEmpty()) {
            throw new IllegalArgumentException("The signed data does not contain a valid lineage.");
        } else if (lineages.size() > 1) {
            result = consolidateLineages(lineages);
        } else {
            result = lineages.get(0);
        }
        return result;
    }

    public void writeToFile(File file) throws IOException {
        if (file == null) {
            throw new NullPointerException("file == null");
        }
        RandomAccessFile outputFile = new RandomAccessFile(file, "rw");
        writeToDataSink(new RandomAccessFileDataSink(outputFile));
    }

    public void writeToDataSink(DataSink dataSink) throws IOException {
        if (dataSink == null) {
            throw new NullPointerException("dataSink == null");
        }
        dataS