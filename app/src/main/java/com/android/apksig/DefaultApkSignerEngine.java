
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
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v1.DigestAlgorithm;
import com.android.apksig.internal.apk.v1.V1SchemeSigner;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.apk.v2.V2SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.jar.ManifestParser;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.TeeDataSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Default implementation of {@link ApkSignerEngine}.
 *
 * <p>Use {@link Builder} to obtain instances of this engine.
 */
public class DefaultApkSignerEngine implements ApkSignerEngine {

    // IMPLEMENTATION NOTE: This engine generates a signed APK as follows:
    // 1. The engine asks its client to output input JAR entries which are not part of JAR
    //    signature.
    // 2. If JAR signing (v1 signing) is enabled, the engine inspects the output JAR entries to
    //    compute their digests, to be placed into output META-INF/MANIFEST.MF. It also inspects
    //    the contents of input and output META-INF/MANIFEST.MF to borrow the main section of the
    //    file. It does not care about individual (i.e., JAR entry-specific) sections. It then
    //    emits the v1 signature (a set of JAR entries) and asks the client to output them.
    // 3. If APK Signature Scheme v2 (v2 signing) is enabled, the engine emits an APK Signing Block
    //    from outputZipSections() and asks its client to insert this block into the output.
    // 4. If APK Signature Scheme v3 (v3 signing) is enabled, the engine includes it in the APK
    //    Signing BLock output from outputZipSections() and asks its client to insert this block
    //    into the output.  If both v2 and v3 signing is enabled, they are both added to the APK
    //    Signing Block before asking the client to insert it into the output.

    private final boolean mV1SigningEnabled;
    private final boolean mV2SigningEnabled;
    private final boolean mV3SigningEnabled;
    private final boolean mDebuggableApkPermitted;
    private final boolean mOtherSignersSignaturesPreserved;
    private final String mCreatedBy;
    private final List<SignerConfig> mSignerConfigs;
    private final int mMinSdkVersion;
    private final SigningCertificateLineage mSigningCertificateLineage;

    private List<V1SchemeSigner.SignerConfig> mV1SignerConfigs = Collections.emptyList();
    private DigestAlgorithm mV1ContentDigestAlgorithm;

    private boolean mClosed;

    private boolean mV1SignaturePending;

    /**
     * Names of JAR entries which this engine is expected to output as part of v1 signing.
     */
    private Set<String> mSignatureExpectedOutputJarEntryNames = Collections.emptySet();

    /** Requests for digests of output JAR entries. */
    private final Map<String, GetJarEntryDataDigestRequest> mOutputJarEntryDigestRequests =
            new HashMap<>();

    /** Digests of output JAR entries. */
    private final Map<String, byte[]> mOutputJarEntryDigests = new HashMap<>();

    /** Data of JAR entries emitted by this engine as v1 signature. */
    private final Map<String, byte[]> mEmittedSignatureJarEntryData = new HashMap<>();

    /** Requests for data of output JAR entries which comprise the v1 signature. */
    private final Map<String, GetJarEntryDataRequest> mOutputSignatureJarEntryDataRequests =
            new HashMap<>();
    /**
     * Request to obtain the data of MANIFEST.MF or {@code null} if the request hasn't been issued.
     */
    private GetJarEntryDataRequest mInputJarManifestEntryDataRequest;

    /**
     * Request to obtain the data of AndroidManifest.xml or {@code null} if the request hasn't been
     * issued.
     */
    private GetJarEntryDataRequest mOutputAndroidManifestEntryDataRequest;

    /**
     * Whether the package being signed is marked as {@code android:debuggable} or {@code null}
     * if this is not yet known.
     */
    private Boolean mDebuggable;

    /**
     * Request to output the emitted v1 signature or {@code null} if the request hasn't been issued.
     */
    private OutputJarSignatureRequestImpl mAddV1SignatureRequest;

    private boolean mV2SignaturePending;
    private boolean mV3SignaturePending;

    /**
     * Request to output the emitted v2 and/or v3 signature(s) {@code null} if the request hasn't
     * been issued.
     */
    private OutputApkSigningBlockRequestImpl mAddSigningBlockRequest;


    private RunnablesExecutor mExecutor = RunnablesExecutor.SINGLE_THREADED;

    private DefaultApkSignerEngine(
            List<SignerConfig> signerConfigs,
            int minSdkVersion,
            boolean v1SigningEnabled,
            boolean v2SigningEnabled,
            boolean v3SigningEnabled,
            boolean debuggableApkPermitted,
            boolean otherSignersSignaturesPreserved,
            String createdBy,
            SigningCertificateLineage signingCertificateLineage) throws InvalidKeyException {
        if (signerConfigs.isEmpty()) {
            throw new IllegalArgumentException("At least one signer config must be provided");
        }
        if (otherSignersSignaturesPreserved) {
            throw new UnsupportedOperationException(
                    "Preserving other signer's signatures is not yet implemented");
        }

        mV1SigningEnabled = v1SigningEnabled;
        mV2SigningEnabled = v2SigningEnabled;
        mV3SigningEnabled = v3SigningEnabled;
        mV1SignaturePending = v1SigningEnabled;
        mV2SignaturePending = v2SigningEnabled;
        mV3SignaturePending = v3SigningEnabled;
        mDebuggableApkPermitted = debuggableApkPermitted;
        mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
        mCreatedBy = createdBy;
        mSignerConfigs = signerConfigs;
        mMinSdkVersion = minSdkVersion;
        mSigningCertificateLineage = signingCertificateLineage;

        if (v1SigningEnabled) {
            if (v3SigningEnabled) {

                // v3 signing only supports single signers, of which the oldest (first) will be the
                // one to use for v1 and v2 signing
                SignerConfig oldestConfig = signerConfigs.get(0);

                // in the event of signing certificate changes, make sure we have the oldest in the
                // signing history to sign with v1
                if (signingCertificateLineage != null) {
                    SigningCertificateLineage subLineage =
                            signingCertificateLineage.getSubLineage(
                                    oldestConfig.mCertificates.get(0));
                    if (subLineage.size() != 1) {
                        throw new IllegalArgumentException(
                                "v1 signing enabled but the oldest signer in the "
                                + "SigningCertificateLineage is missing.  Please provide the oldest"
                                + " signer to enable v1 signing");
                    }
                }
                createV1SignerConfigs(
                        Collections.singletonList(oldestConfig), minSdkVersion);
            } else {
                createV1SignerConfigs(signerConfigs, minSdkVersion);
            }
        }
    }

    private void createV1SignerConfigs(List<SignerConfig> signerConfigs, int minSdkVersion)
            throws InvalidKeyException {
        mV1SignerConfigs = new ArrayList<>(signerConfigs.size());
        Map<String, Integer> v1SignerNameToSignerIndex = new HashMap<>(signerConfigs.size());
        DigestAlgorithm v1ContentDigestAlgorithm = null;
        for (int i = 0; i < signerConfigs.size(); i++) {
            SignerConfig signerConfig = signerConfigs.get(i);
            List<X509Certificate> certificates = signerConfig.getCertificates();
            PublicKey publicKey = certificates.get(0).getPublicKey();

            String v1SignerName = V1SchemeSigner.getSafeSignerName(signerConfig.getName());
            // Check whether the signer's name is unique among all v1 signers
            Integer indexOfOtherSignerWithSameName =
                    v1SignerNameToSignerIndex.put(v1SignerName, i);
            if (indexOfOtherSignerWithSameName != null) {
                throw new IllegalArgumentException(
                        "Signers #" + (indexOfOtherSignerWithSameName + 1)
                        + " and #" + (i + 1)
                        + " have the same name: " + v1SignerName
                        + ". v1 signer names must be unique");
            }

            DigestAlgorithm v1SignatureDigestAlgorithm =
                    V1SchemeSigner.getSuggestedSignatureDigestAlgorithm(
                            publicKey, minSdkVersion);
            V1SchemeSigner.SignerConfig v1SignerConfig = new V1SchemeSigner.SignerConfig();
            v1SignerConfig.name = v1SignerName;
            v1SignerConfig.privateKey = signerConfig.getPrivateKey();
            v1SignerConfig.certificates = certificates;
            v1SignerConfig.signatureDigestAlgorithm = v1SignatureDigestAlgorithm;
            // For digesting contents of APK entries and of MANIFEST.MF, pick the algorithm
            // of comparable strength to the digest algorithm used for computing the signature.
            // When there are multiple signers, pick the strongest digest algorithm out of their
            // signature digest algorithms. This avoids reducing the digest strength used by any
            // of the signers to protect APK contents.
            if (v1ContentDigestAlgorithm == null) {
                v1ContentDigestAlgorithm = v1SignatureDigestAlgorithm;
            } else {
                if (DigestAlgorithm.BY_STRENGTH_COMPARATOR.compare(
                        v1SignatureDigestAlgorithm, v1ContentDigestAlgorithm) > 0) {
                    v1ContentDigestAlgorithm = v1SignatureDigestAlgorithm;
                }
            }
            mV1SignerConfigs.add(v1SignerConfig);
        }
        mV1ContentDigestAlgorithm = v1ContentDigestAlgorithm;
        mSignatureExpectedOutputJarEntryNames =
                V1SchemeSigner.getOutputEntryNames(mV1SignerConfigs);
    }

    private List<ApkSigningBlockUtils.SignerConfig> createV2SignerConfigs(
            boolean apkSigningBlockPaddingSupported) throws InvalidKeyException {
        if (mV3SigningEnabled) {

            // v3 signing only supports single signers, of which the oldest (first) will be the one
            // to use for v1 and v2 signing
            List<ApkSigningBlockUtils.SignerConfig> signerConfig =
                    new ArrayList<>();

            SignerConfig oldestConfig = mSignerConfigs.get(0);

            // first make sure that if we have signing certificate history that the oldest signer
            // corresponds to the oldest ancestor
            if (mSigningCertificateLineage != null) {
                SigningCertificateLineage subLineage =
                        mSigningCertificateLineage.getSubLineage(oldestConfig.mCertificates.get(0));
                if (subLineage.size() != 1) {
                    throw new IllegalArgumentException("v2 signing enabled but the oldest signer in"
                                    + " the SigningCertificateLineage is missing.  Please provide"
                                    + " the oldest signer to enable v2 signing.");
                }
            }
            signerConfig.add(
                    createSigningBlockSignerConfig(
                            mSignerConfigs.get(0), apkSigningBlockPaddingSupported,
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2));
            return signerConfig;
        } else {
            return createSigningBlockSignerConfigs(apkSigningBlockPaddingSupported,
                    ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
        }
    }

    private List<ApkSigningBlockUtils.SignerConfig> createV3SignerConfigs(
            boolean apkSigningBlockPaddingSupported) throws InvalidKeyException {
        List<ApkSigningBlockUtils.SignerConfig> rawConfigs =
                createSigningBlockSignerConfigs(apkSigningBlockPaddingSupported,
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);

        List<ApkSigningBlockUtils.SignerConfig> processedConfigs = new ArrayList<>();

        // we have our configs, now touch them up to appropriately cover all SDK levels since APK
        // signature scheme v3 was introduced
        int currentMinSdk = Integer.MAX_VALUE;
        for (int i = rawConfigs.size() - 1; i >= 0; i--) {
            ApkSigningBlockUtils.SignerConfig config = rawConfigs.get(i);
            if (config.signatureAlgorithms == null) {
                // no valid algorithm was found for this signer, and we haven't yet covered all
                // platform versions, something's wrong
                String keyAlgorithm = config.certificates.get(0).getPublicKey().getAlgorithm();
                throw new InvalidKeyException("Unsupported key algorithm " + keyAlgorithm + " is "
                        + "not supported for APK Signature Scheme v3 signing");
            }
            if (i == rawConfigs.size() - 1) {
                // first go through the loop, config should support all future platform versions.
                // this assumes we don't deprecate support for signers in the future.  If we do,
                // this needs to change
                config.maxSdkVersion = Integer.MAX_VALUE;
            } else {
                // otherwise, we only want to use this signer up to the minimum platform version
                // on which a newer one is acceptable
                config.maxSdkVersion = currentMinSdk - 1;
            }
            config.minSdkVersion = getMinSdkFromV3SignatureAlgorithms(config.signatureAlgorithms);
            if (mSigningCertificateLineage != null) {
                config.mSigningCertificateLineage =
                        mSigningCertificateLineage.getSubLineage(config.certificates.get(0));
            }
            // we know that this config will be used, so add it to our result, order doesn't matter
            // at this point (and likely only one will be needed
            processedConfigs.add(config);
            currentMinSdk = config.minSdkVersion;
            if (currentMinSdk <= mMinSdkVersion || currentMinSdk <= AndroidSdkVersion.P) {
                // this satisfies all we need, stop here
                break;
            }
        }
        if (currentMinSdk > AndroidSdkVersion.P && currentMinSdk > mMinSdkVersion) {
            // we can't cover all desired SDK versions, abort
            throw new InvalidKeyException("Provided key algorithms not supported on all desired "
                    + "Android SDK versions");
        }
        return processedConfigs;
    }

    private int getMinSdkFromV3SignatureAlgorithms(List<SignatureAlgorithm> algorithms) {
        int min = Integer.MAX_VALUE;
        for (SignatureAlgorithm algorithm : algorithms) {
            int current = algorithm.getMinSdkVersion();
            if (current < min) {
                if (current <= mMinSdkVersion || current <= AndroidSdkVersion.P) {
                    // this algorithm satisfies all of our needs, no need to keep looking
                    return current;
                } else {
                    min = current;
                }
            }
        }
        return min;
    }

    private List<ApkSigningBlockUtils.SignerConfig> createSigningBlockSignerConfigs(
            boolean apkSigningBlockPaddingSupported, int schemeId) throws InvalidKeyException {
        List<ApkSigningBlockUtils.SignerConfig> signerConfigs =
                new ArrayList<>(mSignerConfigs.size());
        for (int i = 0; i < mSignerConfigs.size(); i++) {
            SignerConfig signerConfig = mSignerConfigs.get(i);
            signerConfigs.add(
                    createSigningBlockSignerConfig(
                            signerConfig, apkSigningBlockPaddingSupported, schemeId));
        }
        return signerConfigs;
    }

    private ApkSigningBlockUtils.SignerConfig createSigningBlockSignerConfig(
            SignerConfig signerConfig, boolean apkSigningBlockPaddingSupported, int schemeId)
                    throws InvalidKeyException {
        List<X509Certificate> certificates = signerConfig.getCertificates();
        PublicKey publicKey = certificates.get(0).getPublicKey();

        ApkSigningBlockUtils.SignerConfig newSignerConfig =
                new ApkSigningBlockUtils.SignerConfig();
        newSignerConfig.privateKey = signerConfig.getPrivateKey();
        newSignerConfig.certificates = certificates;

        switch (schemeId) {
            case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                newSignerConfig.signatureAlgorithms =
                        V2SchemeSigner.getSuggestedSignatureAlgorithms(publicKey, mMinSdkVersion,
                                apkSigningBlockPaddingSupported);
                break;
            case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                try {
                    newSignerConfig.signatureAlgorithms =
                            V3SchemeSigner.getSuggestedSignatureAlgorithms(
                                    publicKey, mMinSdkVersion, apkSigningBlockPaddingSupported);
                } catch (InvalidKeyException e) {

                    // It is possible for a signer used for v1/v2 signing to not be allowed for use
                    // with v3 signing.  This is ok as long as there exists a more recent v3 signer
                    // that covers all supported platform versions.  Populate signatureAlgorithm
                    // with null, it will be cleaned-up in a later step.
                    newSignerConfig.signatureAlgorithms = null;
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown APK Signature Scheme ID requested");
        }
        return newSignerConfig;
    }

    private boolean isDebuggable(String entryName) {
        return mDebuggableApkPermitted
                || !ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.equals(entryName);
    }

    /**
     * Initializes DefaultApkSignerEngine with the existing MANIFEST.MF. This reads existing digests
     * from the MANIFEST.MF file (they are assumed correct) and stores them for the final signature
     * without recalculation. This step has a significant performance benefit in case of incremental
     * build.
     *
     * This method extracts and stored computed digest for every entry that it would compute it for
     * in the {@link #outputJarEntry(String)} method
     *
     * @param manifestBytes raw representation of MANIFEST.MF file
     * @param entryNames a set of expected entries names
     * @return set of entry names which were processed by the engine during the initialization, a
     *         subset of entryNames
     */
    @Override
    @SuppressWarnings("AndroidJdkLibsChecker")
    public Set<String> initWith(byte[] manifestBytes, Set<String> entryNames) {
        V1SchemeVerifier.Result dummyResult = new V1SchemeVerifier.Result();
        Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> sections =
                V1SchemeVerifier.parseManifest(manifestBytes, entryNames, dummyResult);
        String alg = V1SchemeSigner.getJcaMessageDigestAlgorithm(mV1ContentDigestAlgorithm);
        Stream<Map.Entry<String, ManifestParser.Section>> entryStream;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            entryStream = sections.getSecond().entrySet().parallelStream();
        }
        else {
            entryStream = sections.getSecond().entrySet().stream();
        }
        entryStream.filter(entry->V1SchemeSigner.isJarEntryDigestNeededInManifest(entry.getKey()) &&
                isDebuggable(entry.getKey()) && entryNames.contains(entry.getKey())).forEach(entry->{
            Optional<V1SchemeVerifier.NamedDigest> extractedDigest =
                    V1SchemeVerifier.getDigestsToVerify(
                            entry.getValue(), "-Digest", mMinSdkVersion, Integer.MAX_VALUE).stream()
                            .filter(d -> d.jcaDigestAlgorithm.equals(alg))
                            .findFirst();

            extractedDigest.ifPresent(