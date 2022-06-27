
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

package com.android.apksig.internal.apk.v1;

import com.android.apksig.ApkVerifier.Issue;
import com.android.apksig.ApkVerifier.IssueWithParams;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.jar.ManifestParser;
import com.android.apksig.internal.pkcs7.Attribute;
import com.android.apksig.internal.pkcs7.ContentInfo;
import com.android.apksig.internal.pkcs7.IssuerAndSerialNumber;
import com.android.apksig.internal.pkcs7.Pkcs7Constants;
import com.android.apksig.internal.pkcs7.Pkcs7DecodingException;
import com.android.apksig.internal.pkcs7.SignedData;
import com.android.apksig.internal.pkcs7.SignerIdentifier;
import com.android.apksig.internal.pkcs7.SignerInfo;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.X509CertificateUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.InclusiveIntRange;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;

import net.fornwall.apksigner.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;

import javax.security.auth.x500.X500Principal;

/**
 * APK verifier which uses JAR signing (aka v1 signing scheme).
 *
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File">Signed JAR File</a>
 */
public abstract class V1SchemeVerifier {

    private static final String MANIFEST_ENTRY_NAME = V1SchemeSigner.MANIFEST_ENTRY_NAME;

    private V1SchemeVerifier() {}

    /**
     * Verifies the provided APK's JAR signatures and returns the result of verification. APK is
     * considered verified only if {@link Result#verified} is {@code true}. If verification fails,
     * the result will contain errors -- see {@link Result#getErrors()}.
     *
     * <p>Verification succeeds iff the APK's JAR signatures are expected to verify on all Android
     * platform versions in the {@code [minSdkVersion, maxSdkVersion]} range. If the APK's signature
     * is expected to not verify on any of the specified platform versions, this method returns a
     * result with one or more errors and whose {@code Result.verified == false}, or this method
     * throws an exception.
     *
     * @throws ApkFormatException if the APK is malformed
     * @throws IOException if an I/O error occurs when reading the APK
     * @throws NoSuchAlgorithmException if the APK's JAR signatures cannot be verified because a
     *         required cryptographic algorithm implementation is missing
     */
    public static Result verify(
            DataSource apk,
            ApkUtils.ZipSections apkSections,
            Map<Integer, String> supportedApkSigSchemeNames,
            Set<Integer> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion) throws IOException, ApkFormatException, NoSuchAlgorithmException {
        if (minSdkVersion > maxSdkVersion) {
            throw new IllegalArgumentException(
                    "minSdkVersion (" + minSdkVersion + ") > maxSdkVersion (" + maxSdkVersion
                            + ")");
        }

        Result result = new Result();

        // Parse the ZIP Central Directory and check that there are no entries with duplicate names.
        List<CentralDirectoryRecord> cdRecords = parseZipCentralDirectory(apk, apkSections);
        Set<String> cdEntryNames = checkForDuplicateEntries(cdRecords, result);
        if (result.containsErrors()) {
            return result;
        }

        // Verify JAR signature(s).
        Signers.verify(
                apk,
                apkSections.getZipCentralDirectoryOffset(),
                cdRecords,
                cdEntryNames,
                supportedApkSigSchemeNames,
                foundApkSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);

        return result;
    }

    /**
     * Returns the set of entry names and reports any duplicate entry names in the {@code result}
     * as errors.
     */
    private static Set<String> checkForDuplicateEntries(
            List<CentralDirectoryRecord> cdRecords, Result result) {
        Set<String> cdEntryNames = new HashSet<>(cdRecords.size());
        Set<String> duplicateCdEntryNames = null;
        for (CentralDirectoryRecord cdRecord : cdRecords) {
            String entryName = cdRecord.getName();
            if (!cdEntryNames.add(entryName)) {
                // This is an error. Report this once per duplicate name.
                if (duplicateCdEntryNames == null) {
                    duplicateCdEntryNames = new HashSet<>();
                }
                if (duplicateCdEntryNames.add(entryName)) {
                    result.addError(Issue.JAR_SIG_DUPLICATE_ZIP_ENTRY, entryName);
                }
            }
        }
        return cdEntryNames;
    }

    /**
    * Parses raw representation of MANIFEST.MF file into a pair of main entry manifest section
    * representation and a mapping between entry name and its manifest section representation.
    *
    * @param manifestBytes raw representation of Manifest.MF
    * @param cdEntryNames expected set of entry names
    * @param result object to keep track of errors that happened during the parsing
    * @return a pair of main entry manifest section representation and a mapping between entry name
    *     and its manifest section representation
    */
    public static Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> parseManifest(
            byte[] manifestBytes, Set<String> cdEntryNames, Result result) {
        ManifestParser manifest = new ManifestParser(manifestBytes);
        ManifestParser.Section manifestMainSection = manifest.readSection();
        List<ManifestParser.Section> manifestIndividualSections = manifest.readAllSections();
        Map<String, ManifestParser.Section> entryNameToManifestSection =
                new HashMap<>(manifestIndividualSections.size());
        int manifestSectionNumber = 0;
        for (ManifestParser.Section manifestSection : manifestIndividualSections) {
            manifestSectionNumber++;
            String entryName = manifestSection.getName();
            if (entryName == null) {
                result.addError(Issue.JAR_SIG_UNNNAMED_MANIFEST_SECTION, manifestSectionNumber);
                continue;
            }
            if (entryNameToManifestSection.put(entryName, manifestSection) != null) {
                result.addError(Issue.JAR_SIG_DUPLICATE_MANIFEST_SECTION, entryName);
                continue;
            }
            if (!cdEntryNames.contains(entryName)) {
                result.addError(
                        Issue.JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST, entryName);
                continue;
            }
        }
        return Pair.of(manifestMainSection, entryNameToManifestSection);
    }

    /**
     * All JAR signers of an APK.
     */
    private static class Signers {

        /**
         * Verifies JAR signatures of the provided APK and populates the provided result container
         * with errors, warnings, and information about signers. The APK is considered verified if
         * the {@link Result#verified} is {@code true}.
         */
        private static void verify(
                DataSource apk,
                long cdStartOffset,
                List<CentralDirectoryRecord> cdRecords,
                Set<String> cdEntryNames,
                Map<Integer, String> supportedApkSigSchemeNames,
                Set<Integer> foundApkSigSchemeIds,
                int minSdkVersion,
                int maxSdkVersion,
                Result result) throws ApkFormatException, IOException, NoSuchAlgorithmException {

            // Find JAR manifest and signature block files.
            CentralDirectoryRecord manifestEntry = null;
            Map<String, CentralDirectoryRecord> sigFileEntries = new HashMap<>(1);
            List<CentralDirectoryRecord> sigBlockEntries = new ArrayList<>(1);
            for (CentralDirectoryRecord cdRecord : cdRecords) {
                String entryName = cdRecord.getName();
                if (!entryName.startsWith("META-INF/")) {
                    continue;
                }
                if ((manifestEntry == null) && (MANIFEST_ENTRY_NAME.equals(entryName))) {
                    manifestEntry = cdRecord;
                    continue;
                }
                if (entryName.endsWith(".SF")) {
                    sigFileEntries.put(entryName, cdRecord);
                    continue;
                }
                if ((entryName.endsWith(".RSA"))
                        || (entryName.endsWith(".DSA"))
                        || (entryName.endsWith(".EC"))) {
                    sigBlockEntries.add(cdRecord);
                    continue;
                }
            }
            if (manifestEntry == null) {
                result.addError(Issue.JAR_SIG_NO_MANIFEST);
                return;
            }

            // Parse the JAR manifest and check that all JAR entries it references exist in the APK.
            byte[] manifestBytes;
            try {
                manifestBytes =
                        LocalFileRecord.getUncompressedData(apk, manifestEntry, cdStartOffset);
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed ZIP entry: " + manifestEntry.getName(), e);
            }

            Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> manifestSections =
                    parseManifest(manifestBytes, cdEntryNames, result);

            if (result.containsErrors()) {
                return;
            }

            ManifestParser.Section manifestMainSection = manifestSections.getFirst();
            Map<String, ManifestParser.Section> entryNameToManifestSection =
                    manifestSections.getSecond();

            // STATE OF AFFAIRS:
            // * All JAR entries listed in JAR manifest are present in the APK.

            // Identify signers
            List<Signer> signers = new ArrayList<>(sigBlockEntries.size());
            for (CentralDirectoryRecord sigBlockEntry : sigBlockEntries) {
                String sigBlockEntryName = sigBlockEntry.getName();
                int extensionDelimiterIndex = sigBlockEntryName.lastIndexOf('.');
                if (extensionDelimiterIndex == -1) {
                    throw new RuntimeException(
                            "Signature block file name does not contain extension: "
                                    + sigBlockEntryName);
                }
                String sigFileEntryName =
                        sigBlockEntryName.substring(0, extensionDelimiterIndex) + ".SF";
                CentralDirectoryRecord sigFileEntry = sigFileEntries.get(sigFileEntryName);
                if (sigFileEntry == null) {
                    result.addWarning(
                            Issue.JAR_SIG_MISSING_FILE, sigBlockEntryName, sigFileEntryName);
                    continue;
                }
                String signerName = sigBlockEntryName.substring("META-INF/".length());
                Result.SignerInfo signerInfo =
                        new Result.SignerInfo(
                                signerName, sigBlockEntryName, sigFileEntry.getName());
                Signer signer = new Signer(signerName, sigBlockEntry, sigFileEntry, signerInfo);
                signers.add(signer);
            }
            if (signers.isEmpty()) {
                result.addError(Issue.JAR_SIG_NO_SIGNATURES);
                return;
            }

            // Verify each signer's signature block file .(RSA|DSA|EC) against the corresponding
            // signature file .SF. Any error encountered for any signer terminates verification, to
            // mimic Android's behavior.
            for (Signer signer : signers) {
                signer.verifySigBlockAgainstSigFile(
                        apk, cdStartOffset, minSdkVersion, maxSdkVersion);
                if (signer.getResult().containsErrors()) {
                    result.signers.add(signer.getResult());
                }
            }
            if (result.containsErrors()) {
                return;
            }
            // STATE OF AFFAIRS:
            // * All JAR entries listed in JAR manifest are present in the APK.
            // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).

            // Verify each signer's signature file (.SF) against the JAR manifest.
            List<Signer> remainingSigners = new ArrayList<>(signers.size());
            for (Signer signer : signers) {
                signer.verifySigFileAgainstManifest(
                        manifestBytes,
                        manifestMainSection,
                        entryNameToManifestSection,
                        supportedApkSigSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion,
                        maxSdkVersion);
                if (signer.isIgnored()) {
                    result.ignoredSigners.add(signer.getResult());
                } else {
                    if (signer.getResult().containsErrors()) {
                        result.signers.add(signer.getResult());
                    } else {
                        remainingSigners.add(signer);
                    }
                }
            }
            if (result.containsErrors()) {
                return;
            }
            signers = remainingSigners;
            if (signers.isEmpty()) {
                result.addError(Issue.JAR_SIG_NO_SIGNATURES);
                return;
            }
            // STATE OF AFFAIRS:
            // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).
            // * Contents of all JAR manifest sections listed in .SF files verify against .SF files.
            // * All JAR entries listed in JAR manifest are present in the APK.

            // Verify data of JAR entries against JAR manifest and .SF files. On Android, an APK's
            // JAR entry is considered signed by signers associated with an .SF file iff the entry
            // is mentioned in the .SF file and the entry's digest(s) mentioned in the JAR manifest
            // match theentry's uncompressed data. Android requires that all such JAR entries are
            // signed by the same set of signers. This set may be smaller than the set of signers
            // we've identified so far.
            Set<Signer> apkSigners =
                    verifyJarEntriesAgainstManifestAndSigners(
                            apk,
                            cdStartOffset,
                            cdRecords,
                            entryNameToManifestSection,
                            signers,
                            minSdkVersion,
                            maxSdkVersion,
                            result);
            if (result.containsErrors()) {
                return;
            }
            // STATE OF AFFAIRS:
            // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).
            // * Contents of all JAR manifest sections listed in .SF files verify against .SF files.
            // * All JAR entries listed in JAR manifest are present in the APK.
            // * All JAR entries present in the APK and supposed to be covered by JAR signature
            //   (i.e., reside outside of META-INF/) are covered by signatures from the same set
            //   of signers.

            // Report any JAR entries which aren't covered by signature.
            Set<String> signatureEntryNames = new HashSet<>(1 + result.signers.size() * 2);
            signatureEntryNames.add(manifestEntry.getName());
            for (Signer signer : apkSigners) {
                signatureEntryNames.add(signer.getSignatureBlockEntryName());
                signatureEntryNames.add(signer.getSignatureFileEntryName());
            }
            for (CentralDirectoryRecord cdRecord : cdRecords) {
                String entryName = cdRecord.getName();
                if ((entryName.startsWith("META-INF/"))
                        && (!entryName.endsWith("/"))
                        && (!signatureEntryNames.contains(entryName))) {
                    result.addWarning(Issue.JAR_SIG_UNPROTECTED_ZIP_ENTRY, entryName);
                }
            }

            // Reflect the sets of used signers and ignored signers in the result.
            for (Signer signer : signers) {
                if (apkSigners.contains(signer)) {
                    result.signers.add(signer.getResult());
                } else {
                    result.ignoredSigners.add(signer.getResult());
                }
            }

            result.verified = true;
        }
    }

    static class Signer {
        private final String mName;
        private final Result.SignerInfo mResult;
        private final CentralDirectoryRecord mSignatureFileEntry;
        private final CentralDirectoryRecord mSignatureBlockEntry;
        private boolean mIgnored;

        private byte[] mSigFileBytes;
        private Set<String> mSigFileEntryNames;

        private Signer(
                String name,
                CentralDirectoryRecord sigBlockEntry,
                CentralDirectoryRecord sigFileEntry,
                Result.SignerInfo result) {
            mName = name;
            mResult = result;
            mSignatureBlockEntry = sigBlockEntry;
            mSignatureFileEntry = sigFileEntry;
        }

        public String getName() {
            return mName;
        }

        public String getSignatureFileEntryName() {
            return mSignatureFileEntry.getName();
        }

        public String getSignatureBlockEntryName() {
            return mSignatureBlockEntry.getName();
        }

        void setIgnored() {
            mIgnored = true;
        }

        public boolean isIgnored() {
            return mIgnored;
        }

        public Set<String> getSigFileEntryNames() {
            return mSigFileEntryNames;
        }

        public Result.SignerInfo getResult() {
            return mResult;
        }

        public void verifySigBlockAgainstSigFile(
                DataSource apk, long cdStartOffset, int minSdkVersion, int maxSdkVersion)
                        throws IOException, ApkFormatException, NoSuchAlgorithmException {
            // Obtain the signature block from the APK
            byte[] sigBlockBytes;
            try {
                sigBlockBytes =
                        LocalFileRecord.getUncompressedData(
                                apk, mSignatureBlockEntry, cdStartOffset);
            } catch (ZipFormatException e) {
                throw new ApkFormatException(
                        "Malformed ZIP entry: " + mSignatureBlockEntry.getName(), e);
            }
            // Obtain the signature file from the APK
            try {
                mSigFileBytes =
                        LocalFileRecord.getUncompressedData(
                                apk, mSignatureFileEntry, cdStartOffset);
            } catch (ZipFormatException e) {
                throw new ApkFormatException(
                        "Malformed ZIP entry: " + mSignatureFileEntry.getName(), e);
            }

            // Extract PKCS #7 SignedData from the signature block
            SignedData signedData;
            try {
                ContentInfo contentInfo =
                        Asn1BerParser.parse(ByteBuffer.wrap(sigBlockBytes), ContentInfo.class);
                if (!Pkcs7Constants.OID_SIGNED_DATA.equals(contentInfo.contentType)) {
                    throw new Asn1DecodingException(
                          "Unsupported ContentInfo.contentType: " + contentInfo.contentType);
                }
                signedData =
                        Asn1BerParser.parse(contentInfo.content.getEncoded(), SignedData.class);
            } catch (Asn1DecodingException e) {
                e.printStackTrace();
                mResult.addError(
                        Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                return;
            }

            if (signedData.signerInfos.isEmpty()) {
                mResult.addError(Issue.JAR_SIG_NO_SIGNERS, mSignatureBlockEntry.getName());
                return;
            }

            // Find the first SignedData.SignerInfos element which verifies against the signature
            // file
            SignerInfo firstVerifiedSignerInfo = null;
            X509Certificate firstVerifiedSignerInfoSigningCertificate = null;
            // Prior to Android N, Android attempts to verify only the first SignerInfo. From N
            // onwards, Android attempts to verify all SignerInfos and then picks the first verified
            // SignerInfo.
            List<SignerInfo> unverifiedSignerInfosToTry;
            if (minSdkVersion < AndroidSdkVersion.N) {
                unverifiedSignerInfosToTry =
                        Collections.singletonList(signedData.signerInfos.get(0));
            } else {
                unverifiedSignerInfosToTry = signedData.signerInfos;
            }
            List<X509Certificate> signedDataCertificates = null;
            for (SignerInfo unverifiedSignerInfo : unverifiedSignerInfosToTry) {
                // Parse SignedData.certificates -- they are needed to verify SignerInfo
                if (signedDataCertificates == null) {
                    try {
                        signedDataCertificates = parseCertificates(signedData.certificates);
                    } catch (CertificateException e) {
                        mResult.addError(
                                Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                        return;
                    }
                }

                // Verify SignerInfo
                X509Certificate signingCertificate;
                try {
                    signingCertificate =
                            verifySignerInfoAgainstSigFile(
                                    signedData,
                                    signedDataCertificates,
                                    unverifiedSignerInfo,
                                    mSigFileBytes,
                                    minSdkVersion,
                                    maxSdkVersion);
                    if (mResult.containsErrors()) {
                        return;
                    }
                    if (signingCertificate != null) {
                        // SignerInfo verified
                        if (firstVerifiedSignerInfo == null) {
                            firstVerifiedSignerInfo = unverifiedSignerInfo;
                            firstVerifiedSignerInfoSigningCertificate = signingCertificate;
                        }
                    }
                } catch (Pkcs7DecodingException e) {
                    mResult.addError(
                            Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                    return;
                } catch (InvalidKeyException | SignatureException e) {
                    mResult.addError(
                            Issue.JAR_SIG_VERIFY_EXCEPTION,
                            mSignatureBlockEntry.getName(),
                            mSignatureFileEntry.getName(),
                            e);
                    return;
                }
            }
            if (firstVerifiedSignerInfo == null) {
                // No SignerInfo verified
                mResult.addError(
                        Issue.JAR_SIG_DID_NOT_VERIFY,
                        mSignatureBlockEntry.getName(),
                        mSignatureFileEntry.getName());
                return;
            }
            // Verified
            List<X509Certificate> signingCertChain =
                    getCertificateChain(
                            signedDataCertificates, firstVerifiedSignerInfoSigningCertificate);
            mResult.certChain.clear();
            mResult.certChain.addAll(signingCertChain);
        }

        /**
         * Returns the signing certificate if the provided {@link SignerInfo} verifies against the
         * contents of the provided signature file, or {@code null} if it does not verify.
         */
        private X509Certificate verifySignerInfoAgainstSigFile(
                SignedData signedData,
                Collection<X509Certificate> signedDataCertificates,
                SignerInfo signerInfo,
                byte[] signatureFile,
                int minSdkVersion,
                int maxSdkVersion)
                        throws Pkcs7DecodingException, NoSuchAlgorithmException,
                                InvalidKeyException, SignatureException {
            String digestAlgorithmOid = signerInfo.digestAlgorithm.algorithm;
            String signatureAlgorithmOid = signerInfo.signatureAlgorithm.algorithm;
            InclusiveIntRange desiredApiLevels =
                    InclusiveIntRange.fromTo(minSdkVersion, maxSdkVersion);
            List<InclusiveIntRange> apiLevelsWhereDigestAndSigAlgorithmSupported =
                    getSigAlgSupportedApiLevels(digestAlgorithmOid, signatureAlgorithmOid);
            List<InclusiveIntRange> apiLevelsWhereDigestAlgorithmNotSupported =
                    desiredApiLevels.getValuesNotIn(apiLevelsWhereDigestAndSigAlgorithmSupported);
            if (!apiLevelsWhereDigestAlgorithmNotSupported.isEmpty()) {
                String digestAlgorithmUserFriendly =
                        OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(
                                digestAlgorithmOid);
                if (digestAlgorithmUserFriendly == null) {
                    digestAlgorithmUserFriendly = digestAlgorithmOid;
                }
                String signatureAlgorithmUserFriendly =
                        OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(
                                signatureAlgorithmOid);
                if (signatureAlgorithmUserFriendly == null) {
                    signatureAlgorithmUserFriendly = signatureAlgorithmOid;
                }
                StringBuilder apiLevelsUserFriendly = new StringBuilder();
                for (InclusiveIntRange range : apiLevelsWhereDigestAlgorithmNotSupported) {
                    if (apiLevelsUserFriendly.length() > 0) {
                        apiLevelsUserFriendly.append(", ");
                    }
                    if (range.getMin() == range.getMax()) {
                        apiLevelsUserFriendly.append(String.valueOf(range.getMin()));
                    } else if (range.getMax() == Integer.MAX_VALUE) {
                        apiLevelsUserFriendly.append(range.getMin() + "+");
                    } else {
                        apiLevelsUserFriendly.append(range.getMin() + "-" + range.getMax());
                    }
                }
                mResult.addError(
                        Issue.JAR_SIG_UNSUPPORTED_SIG_ALG,
                        mSignatureBlockEntry.getName(),
                        digestAlgorithmOid,
                        signatureAlgorithmOid,
                        apiLevelsUserFriendly.toString(),
                        digestAlgorithmUserFriendly,
                        signatureAlgorithmUserFriendly);
                return null;
            }

            // From the bag of certs, obtain the certificate referenced by the SignerInfo,
            // and verify the cryptographic signature in the SignerInfo against the certificate.

            // Locate the signing certificate referenced by the SignerInfo
            X509Certificate signingCertificate =
                    findCertificate(signedDataCertificates, signerInfo.sid);
            if (signingCertificate == null) {
                throw new SignatureException(
                        "Signing certificate referenced in SignerInfo not found in"
                                + " SignedData");
            }

            // Check whether the signing certificate is acceptable. Android performs these
            // checks explicitly, instead of delegating this to
            // Signature.initVerify(Certificate).
            if (signingCertificate.hasUnsupportedCriticalExtension()) {
                throw new SignatureException(
                        "Signing certificate has unsupported critical extensions");
            }
            boolean[] keyUsageExtension = signingCertificate.getKeyUsage();
            if (keyUsageExtension != null) {
                boolean digitalSignature =
                        (keyUsageExtension.length >= 1) && (keyUsageExtension[0]);
                boolean nonRepudiation =
                        (keyUsageExtension.length >= 2) && (keyUsageExtension[1]);
                if ((!digitalSignature) && (!nonRepudiation)) {
                    throw new SignatureException(
                            "Signing certificate not authorized for use in digital signatures"
                                    + ": keyUsage extension missing digitalSignature and"
                                    + " nonRepudiation");
                }
            }

            // Verify the cryptographic signature in SignerInfo against the certificate's
            // public key
            String jcaSignatureAlgorithm =
                    getJcaSignatureAlgorithm(digestAlgorithmOid, signatureAlgorithmOid);
            Signature s = Signature.getInstance(jcaSignatureAlgorithm);
            s.initVerify(signingCertificate.getPublicKey());
            if (signerInfo.signedAttrs != null) {
                // Signed attributes present -- verify signature against the ASN.1 DER encoded form
                // of signed attributes. This verifies integrity of the signature file because
                // signed attributes must contain the digest of the signature file.
                if (minSdkVersion < AndroidSdkVersion.KITKAT) {
                    // Prior to Android KitKat, APKs with signed attributes are unsafe:
                    // * The APK's contents are not protected by the JAR signature because the
                    //   digest in signed attributes is not verified. This means an attacker can
                    //   arbitrarily modify the APK without invalidating its signature.
                    // * Luckily, the signature over signed attributes was verified incorrectly
                    //   (over the verbatim IMPLICIT [0] form rather than over re-encoded
                    //   UNIVERSAL SET form) which means that JAR signatures which would verify on
                    //   pre-KitKat Android and yet do not protect the APK from modification could
                    //   be generated only by broken tools or on purpose by the entity signing the
                    //   APK.
                    //
                    // We thus reject such unsafe APKs, even if they verify on platforms before
                    // KitKat.
                    throw new SignatureException(
                            "APKs with Signed Attributes broken on platforms with API Level < "
                                    + AndroidSdkVersion.KITKAT);
                }
                try {