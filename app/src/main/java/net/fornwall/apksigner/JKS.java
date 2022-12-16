
/* JKS.java -- implementation of the "JKS" key store.
   Copyright (C) 2003  Casey Marshall <rsdio@metastatic.org>

Permission to use, copy, modify, distribute, and sell this software and
its documentation for any purpose is hereby granted without fee,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation.  No representations are made about the
suitability of this software for any purpose.  It is provided "as is"
without express or implied warranty.

This program was derived by reverse-engineering Sun's own
implementation, using only the public API that is available in the 1.4.1
JDK.  Hence nothing in this program is, or is derived from, anything
copyrighted by Sun Microsystems.  While the "Binary Evaluation License
Agreement" that the JDK is licensed under contains blanket statements
that forbid reverse-engineering (among other things), it is my position
that US copyright law does not and cannot forbid reverse-engineering of
software to produce a compatible implementation.  There are, in fact,
numerous clauses in copyright law that specifically allow
reverse-engineering, and therefore I believe it is outside of Sun's
power to enforce restrictions on reverse-engineering of their software,
and it is irresponsible for them to claim they can.  */

package net.fornwall.apksigner;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is an implementation of Sun's proprietary key store algorithm, called "JKS" for "Java Key Store". This
 * implementation was created entirely through reverse-engineering.
 *
 * <p>
 * The format of JKS files is, from the start of the file:
 *
 * <ol>
 * <li>Magic bytes. This is a four-byte integer, in big-endian byte order, equal to <code>0xFEEDFEED</code>.</li>
 * <li>The version number (probably), as a four-byte integer (all multibyte integral types are in big-endian byte
 * order). The current version number (in modern distributions of the JDK) is 2.</li>
 * <li>The number of entries in this keystore, as a four-byte integer. Call this value <i>n</i></li>
 * <li>Then, <i>n</i> times:
 * <ol>
 * <li>The entry type, a four-byte int. The value 1 denotes a private key entry, and 2 denotes a trusted certificate.</li>
 * <li>The entry's alias, formatted as strings such as those written by <a
 * href="http://java.sun.com/j2se/1.4.1/docs/api/java/io/DataOutput.html#writeUTF(java.lang.String)"
 * >DataOutput.writeUTF(String)</a>.</li>
 * <li>An eight-byte integer, representing the entry's creation date, in milliseconds since the epoch.
 *
 * <p>
 * Then, if the entry is a private key entry:
 * <ol>
 * <li>The size of the encoded key as a four-byte int, then that number of bytes. The encoded key is the DER encoded
 * bytes of the <a
 * href="http://java.sun.com/j2se/1.4.1/docs/api/javax/crypto/EncryptedPrivateKeyInfo.html">EncryptedPrivateKeyInfo</a>
 * structure (the encryption algorithm is discussed later).</li>
 * <li>A four-byte integer, followed by that many encoded certificates, encoded as described in the trusted certificates
 * section.</li>
 * </ol>
 *
 * <p>
 * Otherwise, the entry is a trusted certificate, which is encoded as the name of the encoding algorithm (e.g. X.509),
 * encoded the same way as alias names. Then, a four-byte integer representing the size of the encoded certificate, then
 * that many bytes representing the encoded certificate (e.g. the DER bytes in the case of X.509).</li>
 * </ol>
 * </li>
 * <li>Then, the signature.</li>
 * </ol>
 * </ol> </li> </ol>
 *
 * <p>
 * (See <a href="http://metastatic.org/source/genkey.java">this file</a> for some idea of how I was able to figure out these algorithms)
 * </p>
 *
 * <p>
 * Decrypting the key works as follows:
 *
 * <ol>
 * <li>The key length is the length of the ciphertext minus 40. The encrypted key, <code>ekey</code>, is the middle
 * bytes of the ciphertext.</li>
 * <li>Take the first 20 bytes of the encrypted key as a seed value, <code>K[0]</code>.</li>
 * <li>Compute <code>K[1] ... K[n]</code>, where <code>|K[i]| = 20</code>, <code>n = ceil(|ekey| / 20)</code>, and
 * <code>K[i] = SHA-1(UTF-16BE(password) + K[i-1])</code>.</li>
 * <li><code>key = ekey ^ (K[1] + ... + K[n])</code>.</li>
 * <li>The last 20 bytes are the checksum, computed as <code>H =
 * SHA-1(UTF-16BE(password) + key)</code>. If this value does not match the last 20 bytes of the ciphertext, output
 * <code>FAIL</code>. Otherwise, output <code>key</code>.</li>
 * </ol>
 *
 * <p>
 * The signature is defined as <code>SHA-1(UTF-16BE(password) +
 * US_ASCII("Mighty Aphrodite") + encoded_keystore)</code> (yup, Sun engineers are just that clever).
 *
 * <p>
 * (Above, SHA-1 denotes the secure hash algorithm, UTF-16BE the big-endian byte representation of a UTF-16 string, and
 * US_ASCII the ASCII byte representation of the string.)
 *
 * <p>
 * The original source code by Casey Marshall of this class should be available in the file <a
 * href="http://metastatic.org/source/JKS.java">http://metastatic.org/source/JKS.java</a>.
 *
 * <p>
 * Changes by Ken Ellinwood:
 * <ul>
 * <li>Fixed a NullPointerException in engineLoad(). This method must return gracefully if the keystore input stream is
 * null.</li>
 * <li>engineGetCertificateEntry() was updated to return the first cert in the chain for private key entries.</li>
 * <li>Lowercase the alias names, otherwise keytool chokes on the file created by this code.</li>
 * <li>Fixed the integrity check in engineLoad(), previously the exception was never thrown regardless of password
 * value.</li>
 * </ul>
 * 
 * @author Casey Marshall (rsdio@metastatic.org)
 * @author Ken Ellinwood
 */
public class JKS extends KeyStoreSpi {

	/** Ah, Sun. So goddamned clever with those magic bytes. */
	private static final int MAGIC = 0xFEEDFEED;
