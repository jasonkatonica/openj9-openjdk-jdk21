/*
 * Copyright (c) 2019, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
 * ===========================================================================
 */
package sun.security.ssl;

import sun.security.util.RawKeySpec;

import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.DestroyFailedException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
/*[IF OPENJCEPLUS_SUPPORT]*/
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
/*[ENDIF] OPENJCEPLUS_SUPPORT */
import jdk.internal.access.SharedSecrets;

/**
 * A common class for creating various KeyDerivation types.
 */
public class KAKeyDerivation implements SSLKeyDerivation {

    private final String algorithmName;
    private final HandshakeContext context;
    private final PrivateKey localPrivateKey;
    private final PublicKey peerPublicKey;
    private final byte[] keyshare;
    private final Provider provider;

    /*[IF OPENJCEPLUS_SUPPORT]*/
    // OpenJCEPlus HKDF support for post-quantum TLS 1.3 key derivation
    private static final Constructor<?> hkdfExtractCtor;
    private static final boolean openJCEPlusAvailable;

    static {
        Constructor<?> extractCtor = null;
        boolean available = false;
        
        try {
            // Load OpenJCEPlus HKDF parameter spec class (available in both
            // OpenJCEPlus and OpenJCEPlusFIPS providers)
            Class<?> hkdfExtractSpec = Class.forName(
                    "ibm.security.internal.spec.HKDFExtractParameterSpec",
                    true, ClassLoader.getSystemClassLoader());
            extractCtor = hkdfExtractSpec.getDeclaredConstructor(
                    SecretKey.class, byte[].class, String.class);
            available = true;
        } catch (ClassNotFoundException | NoSuchMethodException exc) {
            // OpenJCEPlus classes not available - will use standard HKDF
        }
        
        hkdfExtractCtor = extractCtor;
        openJCEPlusAvailable = available;
    }
    /*[ENDIF] OPENJCEPLUS_SUPPORT */

    // Constructor called by Key Agreement
    KAKeyDerivation(String algorithmName,
            HandshakeContext context,
            PrivateKey localPrivateKey,
            PublicKey peerPublicKey) {
        this(algorithmName, null, context, localPrivateKey,
                peerPublicKey, null);
    }

    // When the constructor called by KEM: store the client's public key or the
    // encapsulated message in keyshare.
    KAKeyDerivation(String algorithmName,
                    NamedGroup namedGroup,
                    HandshakeContext context,
                    PrivateKey localPrivateKey,
                    PublicKey peerPublicKey,
                    byte[] keyshare) {
        this.algorithmName = algorithmName;
        this.context = context;
        this.localPrivateKey = localPrivateKey;
        this.peerPublicKey = peerPublicKey;
        this.keyshare = keyshare;
        this.provider = (namedGroup != null) ? namedGroup.getProvider() : null;
    }

    @Override
    public SecretKey deriveKey(String algorithm,
            AlgorithmParameterSpec params) throws IOException {
        if (!context.negotiatedProtocol.useTLS13PlusSpec()) {
            return t12DeriveKey(algorithm, params);
        } else {
            return t13DeriveKey(algorithm, params);
        }
    }

    /**
     * Handle the TLSv1-1.2 objects, which don't use the HKDF algorithms.
     */
    private SecretKey t12DeriveKey(String algorithm,
            AlgorithmParameterSpec params) throws IOException {
        try {
            KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
            ka.init(localPrivateKey);
            ka.doPhase(peerPublicKey, true);
            SecretKey preMasterSecret
                    = ka.generateSecret("TlsPremasterSecret");
            SSLMasterKeyDerivation mskd
                    = SSLMasterKeyDerivation.valueOf(
                            context.negotiatedProtocol);
            if (mskd == null) {
                // unlikely
                throw new SSLHandshakeException(
                        "No expected master key derivation for protocol: "
                        + context.negotiatedProtocol.name);
            }
            SSLKeyDerivation kd = mskd.createKeyDerivation(
                    context, preMasterSecret);
            return kd.deriveKey("MasterSecret", params);
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        }
    }

    private SecretKey deriveHandshakeSecret(String label,
            SecretKey sharedSecret)
            throws GeneralSecurityException, IOException {
        SecretKey earlySecret = null;
        SecretKey saltSecret = null;
        SecretKey ikm = null;

        CipherSuite.HashAlg hashAlg = context.negotiatedCipherSuite.hashAlg;
        SSLKeyDerivation kd = context.handshakeKeyDerivation;
        try {
            if (kd == null) {   // No PSK is in use.
                // If PSK is not in use Early Secret will still be
                // HKDF-Extract(0, 0).
                byte[] zeros = new byte[hashAlg.hashLength];
                SecretKeySpec zeroKey = new SecretKeySpec(zeros, "TlsPremasterSecret");
                
                /*[IF OPENJCEPLUS_SUPPORT]*/
                // Try OpenJCEPlus HKDF first for post-quantum TLS 1.3 support
                earlySecret = tryOpenJCEPlusExtract(hashAlg.name, zeros, zeroKey, "TlsEarlySecret");
                if (earlySecret == null) {
                /*[ENDIF] OPENJCEPLUS_SUPPORT */
                    HKDF initialHkdf = new HKDF(hashAlg.name);
                    earlySecret = initialHkdf.extract(zeros, zeroKey, "TlsEarlySecret");
                /*[IF OPENJCEPLUS_SUPPORT]*/
                }
                /*[ENDIF] OPENJCEPLUS_SUPPORT */
                kd = new SSLSecretDerivation(context, earlySecret);
            }

            // derive salt secret
            saltSecret = kd.deriveKey("TlsSaltSecret", null);

            // derive handshake secret
            // For hybrid post-quantum key exchange, combine the classical and PQ shared secrets
            if (sharedSecret instanceof Hybrid.SecretKeyImpl hsk) {
                byte[] combined = hsk.getEncoded();
                if (combined == null) {
                    throw new SSLHandshakeException(
                            "Hybrid secret key has no encoded form");
                }
                ikm = new SecretKeySpec(combined, "TlsPremasterSecret");
                java.util.Arrays.fill(combined, (byte)0);
            } else {
                ikm = sharedSecret;
            }

            /*[IF OPENJCEPLUS_SUPPORT]*/
            // Try OpenJCEPlus HKDF first for post-quantum TLS 1.3 support
            SecretKey result = tryOpenJCEPlusExtract(hashAlg.name, saltSecret.getEncoded(), ikm, label);
            if (result != null) {
                return result;
            }
            /*[ENDIF] OPENJCEPLUS_SUPPORT */
            
            // Fall back to standard HKDF
            HKDF hkdf = new HKDF(hashAlg.name);
            return hkdf.extract(saltSecret, ikm, label);
        } finally {
            destroySecretKey(earlySecret);
            destroySecretKey(saltSecret);
            if (ikm != null && ikm != sharedSecret) destroySecretKey(ikm);
        }
    }

    /*[IF OPENJCEPLUS_SUPPORT]*/
    /**
     * Attempt to perform HKDF extract operation using OpenJCEPlus provider.
     * This method tries to use the OpenJCEPlus HKDF implementation (available in both
     * OpenJCEPlus and OpenJCEPlusFIPS providers) for post-quantum TLS 1.3 key derivation.
     * If OpenJCEPlus is not available or the operation fails, returns null to allow
     * fallback to the standard HKDF implementation.
     *
     * @param hashAlg the hash algorithm name (e.g., "SHA-256", "SHA-384")
     * @param salt the salt value as a byte array
     * @param inputKey the input keying material
     * @param keyAlg the algorithm name for the resulting SecretKey
     * @return the extracted secret key, or null if OpenJCEPlus is not available
     */
    private SecretKey tryOpenJCEPlusExtract(String hashAlg, byte[] salt,
            SecretKey inputKey, String keyAlg) {
        if (!openJCEPlusAvailable) {
            return null;
        }

        try {
            // Convert hash algorithm name to OpenJCEPlus format
            // e.g., "SHA-256" -> "kda-hkdf-with-sha256"
            String hkdfAlg = "kda-hkdf-with-" + hashAlg.replace("-", "").toLowerCase();
            
            // Try to get KeyGenerator - will succeed if OpenJCEPlus or OpenJCEPlusFIPS
            // is in the provider list
            KeyGenerator hkdfGenerator = KeyGenerator.getInstance(hkdfAlg);
            
            // Get the provider name for debug logging
            String providerName = hkdfGenerator.getProvider().getName();
            
            // Create HKDFExtractParameterSpec using reflection
            AlgorithmParameterSpec extractSpec = (AlgorithmParameterSpec) hkdfExtractCtor.newInstance(
                    inputKey, salt, keyAlg);
            
            hkdfGenerator.init(extractSpec);
            SecretKey result = hkdfGenerator.generateKey();
            
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.info("KAKeyDerivation: Using " + providerName + " HKDF extract for " + keyAlg);
            }
            
            return result;
        } catch (NoSuchAlgorithmException nsae) {
            // OpenJCEPlus provider not in the provider list, fall back to standard HKDF
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("KAKeyDerivation: OpenJCEPlus HKDF not available, using standard HKDF");
            }
            return null;
        } catch (ClassCastException | IllegalAccessException | InstantiationException
                | InvalidAlgorithmParameterException | InvocationTargetException exc) {
            // Unexpected error with OpenJCEPlus, fall back to standard HKDF
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("KAKeyDerivation: Error using OpenJCEPlus HKDF, falling back to standard: "
                        + exc.getMessage());
            }
            return null;
        }
    }
    /*[ENDIF] OPENJCEPLUS_SUPPORT */
    /**
     * This method is called by the server to perform KEM encapsulation.
     * It uses the client's public key (sent by the client as a keyshare)
     * to encapsulate a shared secret and returns the encapsulated message.
     *
     * Package-private, used from KeyShareExtension.SHKeyShareProducer::
     * produce().
     */
    KEM.Encapsulated encapsulate(String algorithm, SecureRandom random)
            throws IOException {
        //System.out.println("DEBUG [KAKeyDerivation.encapsulate] Called with algorithm: " + algorithm);
        SecretKey sharedSecret = null;

        if (keyshare == null) {
            throw new IOException("No keyshare available for KEM " +
                    "encapsulation");
        }

        try {
            KeyFactory kf = (provider != null) ?
                    KeyFactory.getInstance(algorithmName, provider) :
                    KeyFactory.getInstance(algorithmName);
            var pk = kf.generatePublic(new RawKeySpec(keyshare));

            KEM kem = (provider != null) ?
                    KEM.getInstance(algorithmName, provider) :
                    KEM.getInstance(algorithmName);
            KEM.Encapsulator e = kem.newEncapsulator(pk, random);
            KEM.Encapsulated enc = e.encapsulate(0, e.secretSize(), algorithm);
            sharedSecret = enc.key();

            SecretKey derived = deriveHandshakeSecret(algorithm, sharedSecret);

            return new KEM.Encapsulated(derived, enc.encapsulation(), null);
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            destroySecretKey(sharedSecret);
        }
    }

    /**
     * Handle the TLSv1.3 objects, which use the HKDF algorithms.
     */
    private SecretKey t13DeriveKey(String type, AlgorithmParameterSpec params)
            throws IOException {
        SecretKey sharedSecret = null;

        try {
            if (keyshare != null) {
                // Using KEM: called by the client after receiving the KEM
                // ciphertext (keyshare) from the server in ServerHello.
                // The client decapsulates it using its private key.
                KEM kem = (provider != null)
                        ? KEM.getInstance(algorithmName, provider)
                        : KEM.getInstance(algorithmName);
                var decapsulator = kem.newDecapsulator(localPrivateKey);
                sharedSecret = decapsulator.decapsulate(
                        keyshare, 0, decapsulator.secretSize(),
                        "TlsPremasterSecret");
            } else {
                // Using traditional DH-style Key Agreement
                KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
                ka.init(localPrivateKey);
                ka.doPhase(peerPublicKey, true);
                sharedSecret = ka.generateSecret("TlsPremasterSecret");
            }

            return deriveHandshakeSecret(type, sharedSecret);
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            destroySecretKey(sharedSecret);
        }
    }

    // destroy secret keys in a best-effort way
    private static void destroySecretKey(SecretKey... keys) {
        for (SecretKey k : keys) {
            if (k != null) {
                if (k instanceof SecretKeySpec sk) {
                    SharedSecrets.getJavaxCryptoSpecAccess()
                            .clearSecretKeySpec(sk);
                } else if (k.getClass().getName().equals("com.sun.crypto.provider.PBKDF2KeyImpl")) {
                    try {
                        java.lang.reflect.Method m = k.getClass().getDeclaredMethod("clear");
                        m.invoke(k);
                    } catch (Exception e) {
                        // swallow
                    }
                } else {
                    try {
                        k.destroy();
                    } catch (DestroyFailedException e) {
                        // swallow
                    }
                }
            }
        }
    }
}
