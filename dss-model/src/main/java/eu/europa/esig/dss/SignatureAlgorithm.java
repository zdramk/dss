/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Supported signature algorithms.
 *
 */
public class SignatureAlgorithm implements Serializable {

	private static final Map<String, SignatureAlgorithm> NAME_ALGORITHMS = new ConcurrentHashMap<>();

	private static final Map<String, SignatureAlgorithm> XML_ALGORITHMS = new ConcurrentHashMap<>();

	private static final Map<SignatureAlgorithm, String> XML_ALGORITHMS_FOR_KEY = new ConcurrentHashMap<>();

	private static final Map<String, SignatureAlgorithm> OID_ALGORITHMS = new ConcurrentHashMap<>();

	private static final Map<String, SignatureAlgorithm> JAVA_ALGORITHMS = new ConcurrentHashMap<>();

	private static final Map<SignatureAlgorithm, String> JAVA_ALGORITHMS_FOR_KEY = new ConcurrentHashMap<>();

	public static SignatureAlgorithm RSA_SHA1 =
		withJAVA("SHA1withRSA",
			withOID("1.3.14.3.2.29",
				withOID("1.2.840.113549.1.1.5",
					withXML("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
						register("RSA_SHA1",
							EncryptionAlgorithm.RSA, DigestAlgorithm.SHA1, DSSProvider.PROVIDER_NAME))))),

	RSA_SHA224 =
		withJAVA("SHA224withRSA",
			withOID("1.2.840.113549.1.1.14",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
					register("RSA_SHA224",
						EncryptionAlgorithm.RSA, DigestAlgorithm.SHA224, DSSProvider.PROVIDER_NAME)))),

	RSA_SHA256 =
		withJAVA("SHA256withRSA",
			withOID("1.2.840.113549.1.1.11",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
					register("RSA_SHA256",
						EncryptionAlgorithm.RSA, DigestAlgorithm.SHA256, DSSProvider.PROVIDER_NAME)))),

	RSA_SHA384 =
		withJAVA("SHA384withRSA",
			withOID("1.2.840.113549.1.1.12",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
					register("RSA_SHA384",
						EncryptionAlgorithm.RSA, DigestAlgorithm.SHA384, DSSProvider.PROVIDER_NAME)))),

	RSA_SHA512 =
		withJAVA("SHA512withRSA",
			withOID("1.2.840.113549.1.1.13",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
					register("RSA_SHA512",
						EncryptionAlgorithm.RSA, DigestAlgorithm.SHA512, DSSProvider.PROVIDER_NAME)))),

	RSA_SHA3_224 =
		withJAVA("SHA3-224withRSA",
			withOID("2.16.840.1.101.3.4.3.13",
				register("RSA_SHA3_224",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_224, DSSProvider.PROVIDER_NAME))),

	RSA_SHA3_256 =
		withJAVA("SHA3-256withRSA",
			withOID("2.16.840.1.101.3.4.3.14",
				register("RSA_SHA3_256",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_256, DSSProvider.PROVIDER_NAME))),

	RSA_SHA3_384 =
		withJAVA("SHA3-384withRSA",
			withOID("2.16.840.1.101.3.4.3.15",
				register("RSA_SHA3_384",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_384, DSSProvider.PROVIDER_NAME))),

	RSA_SHA3_512 =
		withJAVA("SHA3-512withRSA",
			withOID("2.16.840.1.101.3.4.3.16",
				register("RSA_SHA3_512",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_512, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA1_MGF1 =
		withJAVA("SHA1withRSAandMGF1",
			withOID("1.2.840.113549.1.1.10",
				withXML("http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1",
					register("RSA_SSA_PSS_SHA1_MGF1",
						EncryptionAlgorithm.RSA, DigestAlgorithm.SHA1, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME)))),

	RSA_SSA_PSS_SHA224_MGF1 =
		withJAVA("SHA224withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1",
				register("RSA_SSA_PSS_SHA224_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA224, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA256_MGF1 =
		withJAVA("SHA256withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
				register("RSA_SSA_PSS_SHA256_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA384_MGF1 =
		withJAVA("SHA384withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
				register("RSA_SSA_PSS_SHA384_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA384, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA512_MGF1 =
		withJAVA("SHA512withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
				register("RSA_SSA_PSS_SHA512_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA512, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA3_224_MGF1 =
		withJAVA("SHA3-224withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1",
				register("RSA_SSA_PSS_SHA3_224_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_224, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA3_256_MGF1 =
		withJAVA("SHA3-256withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1",
				register("RSA_SSA_PSS_SHA3_256_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_256, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA3_384_MGF1 =
		withJAVA("SHA3-384withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1",
				register("RSA_SSA_PSS_SHA3_384_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_384, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_SSA_PSS_SHA3_512_MGF1 =
		withJAVA("SHA3-512withRSAandMGF1",
			withXML("http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1",
				register("RSA_SSA_PSS_SHA3_512_MGF1",
					EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_512, MaskGenerationFunction.MGF1, DSSProvider.PROVIDER_NAME))),

	RSA_RIPEMD160 =
		withJAVA("RIPEMD160withRSA",
			withOID("1.3.36.3.3.1.2",
				withXML("http://www.w3.org/2001/04/xmldsig-more/rsa-ripemd160",
					withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160",
						register("RSA_RIPEMD160",
							EncryptionAlgorithm.RSA, DigestAlgorithm.RIPEMD160, DSSProvider.PROVIDER_NAME))))),

	RSA_MD5 =
		withJAVA("MD5withRSA",
			withOID("1.2.840.113549.1.1.4",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
					register("RSA_MD5",
						EncryptionAlgorithm.RSA, DigestAlgorithm.MD5, DSSProvider.PROVIDER_NAME)))),

	RSA_MD2 =
		withJAVA("MD2withRSA",
			withOID("1.2.840.113549.1.1.2",
				withXML("http://www.w3.org/2001/04/xmldsig-more#rsa-md2",
					register("RSA_MD2",
						EncryptionAlgorithm.RSA, DigestAlgorithm.MD2, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA1 =
		withJAVA("SHA1withECDSA",
			withOID("1.2.840.10045.4.1",
				withXML("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
					register("ECDSA_SHA1",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA1, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA224 =
		withJAVA("SHA224withECDSA",
			withOID("1.2.840.10045.4.3.1",
				withXML("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
					register("ECDSA_SHA224",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA224, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA256 =
		withJAVA("SHA256withECDSA",
			withOID("1.2.840.10045.4.3.2",
				withXML("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
					register("ECDSA_SHA256",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA256, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA384 =
		withJAVA("SHA384withECDSA",
			withOID("1.2.840.10045.4.3.3",
				withXML("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
					register("ECDSA_SHA384",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA384, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA512 =
		withJAVA("SHA512withECDSA",
			withOID("1.2.840.10045.4.3.4",
				withXML("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
					register("ECDSA_SHA512",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA512, DSSProvider.PROVIDER_NAME)))),

	ECDSA_SHA3_224 =
		withJAVA("SHA3-224withECDSA",
			withOID("2.16.840.1.101.3.4.3.9",
				register("ECDSA_SHA3_224",
					EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_224, DSSProvider.PROVIDER_NAME))),

	ECDSA_SHA3_256 =
		withJAVA("SHA3-256withECDSA",
			withOID("2.16.840.1.101.3.4.3.10",
				register("ECDSA_SHA3_256",
					EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_256, DSSProvider.PROVIDER_NAME))),

	ECDSA_SHA3_384 =
		withJAVA("SHA3-384withECDSA",
			withOID("2.16.840.1.101.3.4.3.11",
				register("ECDSA_SHA3_384",
					EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_384, DSSProvider.PROVIDER_NAME))),

	ECDSA_SHA3_512 =
		withJAVA("SHA3-512withECDSA",
			withOID("2.16.840.1.101.3.4.3.12",
				register("ECDSA_SHA3_512",
					EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_512, DSSProvider.PROVIDER_NAME))),

	ECDSA_RIPEMD160 =
		withJAVA("RIPEMD160withECDSA",
			withOID("0.4.0.127.0.7.1.1.4.1.6",
				withXML("http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160",
					register("ECDSA_RIPEMD160",
						EncryptionAlgorithm.ECDSA, DigestAlgorithm.RIPEMD160, DSSProvider.PROVIDER_NAME)))),

	DSA_SHA1 =
		withJAVA("SHA1withDSA",
			withOID("1.2.14888.3.0.1",
				withOID("1.2.840.10040.4.3",
					withXML("http://www.w3.org/2000/09/xmldsig#dsa-sha1",
						register("DSA_SHA1",
							EncryptionAlgorithm.DSA, DigestAlgorithm.SHA1, DSSProvider.PROVIDER_NAME))))),

	DSA_SHA224 =
		withJAVA("SHA224withDSA",
			withOID("2.16.840.1.101.3.4.3.1",
				register("DSA_SHA224",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA224, DSSProvider.PROVIDER_NAME))),

	DSA_SHA256 =
		withJAVA("SHA256withDSA",
			withOID("2.16.840.1.101.3.4.3.2",
				withXML("http://www.w3.org/2009/xmldsig11#dsa-sha256",
					register("DSA_SHA256",
						EncryptionAlgorithm.DSA, DigestAlgorithm.SHA256, DSSProvider.PROVIDER_NAME)))),

	DSA_SHA384 =
		withJAVA("SHA384withDSA",
			withOID("2.16.840.1.101.3.4.3.3",
				register("DSA_SHA384",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA384, DSSProvider.PROVIDER_NAME))),

	DSA_SHA512 =
		withJAVA("SHA512withDSA",
			withOID("2.16.840.1.101.3.4.3.4",
				register("DSA_SHA512",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA512, DSSProvider.PROVIDER_NAME))),

	DSA_SHA3_224 =
		withJAVA("SHA3-224withDSA",
			withOID("2.16.840.1.101.3.4.3.5",
				register("DSA_SHA3_224",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_224, DSSProvider.PROVIDER_NAME))),

	DSA_SHA3_256 =
		withJAVA("SHA3-256withDSA",
			withOID("2.16.840.1.101.3.4.3.6",
				register("DSA_SHA3_256",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_256, DSSProvider.PROVIDER_NAME))),

	DSA_SHA3_384 =
		withJAVA("SHA3-384withDSA",
			withOID("2.16.840.1.101.3.4.3.7",
				register("DSA_SHA3_384",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_384, DSSProvider.PROVIDER_NAME))),

	DSA_SHA3_512 =
		withJAVA("SHA3-512withDSA",
			withOID("2.16.840.1.101.3.4.3.8",
				register("DSA_SHA3_512",
					EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_512, DSSProvider.PROVIDER_NAME))),

	HMAC_SHA1 =
		withJAVA("SHA1withHMAC",
			withOID("1.2.840.113549.2.7",
				withXML("http://www.w3.org/2000/09/xmldsig#hmac-sha1",
					register("HMAC_SHA1",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA1, DSSProvider.PROVIDER_NAME)))),

	HMAC_SHA224 =
		withJAVA("SHA224withHMAC",
			withOID("1.2.840.113549.2.8",
				withXML("http://www.w3.org/2001/04/xmldsig-more#hmac-sha224",
					register("HMAC_SHA224",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA224, DSSProvider.PROVIDER_NAME)))),

	HMAC_SHA256 =
		withJAVA("SHA256withHMAC",
			withOID("1.2.840.113549.2.9",
				withXML("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
					register("HMAC_SHA256",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA256, DSSProvider.PROVIDER_NAME)))),

	HMAC_SHA384 =
		withJAVA("SHA384withHMAC",
			withOID("1.2.840.113549.2.10",
				withXML("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
					register("HMAC_SHA384",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA384, DSSProvider.PROVIDER_NAME)))),

	HMAC_SHA512 =
		withJAVA("SHA512withHMAC",
			withOID("1.2.840.113549.2.11",
				withXML("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
					register("HMAC_SHA512",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA512, DSSProvider.PROVIDER_NAME)))),

	HMAC_SHA3_224 =
		withJAVA("SHA3-224withHMAC",
			withOID("2.16.840.1.101.3.4.2.13",
				register("HMAC_SHA3_224",
					EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_224, DSSProvider.PROVIDER_NAME))),

	HMAC_SHA3_256 =
		withJAVA("SHA3-256withHMAC",
			withOID("2.16.840.1.101.3.4.2.14",
				register("HMAC_SHA3_256",
					EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_256, DSSProvider.PROVIDER_NAME))),

	HMAC_SHA3_384 =
		withJAVA("SHA3-384withHMAC",
			withOID("2.16.840.1.101.3.4.2.15",
				register("HMAC_SHA3_384",
					EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_384, DSSProvider.PROVIDER_NAME))),

	HMAC_SHA3_512 =
		withJAVA("SHA3-512withHMAC",
			withOID("2.16.840.1.101.3.4.2.16",
				register("HMAC_SHA3_512",
					EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_512, DSSProvider.PROVIDER_NAME))),

	HMAC_RIPEMD160 =
		withJAVA("RIPEMD160withHMAC",
			withOID("1.3.6.1.5.5.8.1.4",
				withXML("http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160",
					register("HMAC_RIPEMD160",
						EncryptionAlgorithm.HMAC, DigestAlgorithm.RIPEMD160, DSSProvider.PROVIDER_NAME))));

	private final String name;

	private final EncryptionAlgorithm encryptionAlgo;

	private final DigestAlgorithm digestAlgo;

	private final MaskGenerationFunction maskGenerationFunction;

	private final String providerName;

	private static final List<SignatureAlgorithm> ALGORITHMS = Collections.synchronizedList(new ArrayList<>());

	public static SignatureAlgorithm withXML(String xml, SignatureAlgorithm algorithm) {
		XML_ALGORITHMS.put(xml, algorithm);
		XML_ALGORITHMS_FOR_KEY.put(algorithm, xml);
		return algorithm;
	}

	public static SignatureAlgorithm withOID(String oid, SignatureAlgorithm algorithm) {
		OID_ALGORITHMS.put(oid, algorithm);
		return algorithm;
	}

	public static SignatureAlgorithm withJAVA(String javaAlgorithm, SignatureAlgorithm algorithm) {
		JAVA_ALGORITHMS.put(javaAlgorithm, algorithm);
		JAVA_ALGORITHMS_FOR_KEY.put(algorithm, javaAlgorithm);
		return algorithm;
	}

	public static SignatureAlgorithm forXML(final String xmlName) {
		final SignatureAlgorithm algorithm = XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + xmlName);
		}
		return algorithm;
	}

	/**
	 * This method return the {@code SignatureAlgorithm} or the default value if the algorithm is unknown.
	 *
	 * @param xmlName
	 *            XML URI of the given algorithm
	 * @param defaultValue
	 *            the default value to be returned if not found
	 * @return {@code SignatureAlgorithm} or default value
	 */
	public static SignatureAlgorithm forXML(final String xmlName, final SignatureAlgorithm defaultValue) {
		final SignatureAlgorithm algorithm = XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			return defaultValue;
		}
		return algorithm;
	}

	public static SignatureAlgorithm forOID(final String oid) {
		final SignatureAlgorithm algorithm = OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	public static SignatureAlgorithm forName(final String oid) {
		final SignatureAlgorithm algorithm = NAME_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * For given signature algorithm and digest algorithm this function returns the Java form of the signature algorithm
	 * Signature Algorithms
	 *
	 * The algorithm names in this section can be specified when generating an instance of Signature.
	 *
	 * NONEwithRSA - The RSA signature algorithm which does not use a digesting algorithm (e.g. MD5/SHA1) before
	 * performing the RSA operation. For more information about the RSA
	 * Signature algorithms, please see PKCS1.
	 *
	 * MD2withRSA MD5withRSA - The MD2/MD5 with RSA Encryption signature algorithm which uses the MD2/MD5 digest
	 * algorithm and RSA to create and verify RSA digital signatures as
	 * defined in PKCS1.
	 *
	 * SHA1withRSA SHA256withRSA SHA384withRSA SHA512withRSA - The signature algorithm with SHA-* and the RSA encryption
	 * algorithm as defined in the OSI Interoperability Workshop,
	 * using the padding conventions described in PKCS1.
	 *
	 * NONEwithDSA - The Digital Signature Algorithm as defined in FIPS PUB 186-2. The data must be exactly 20 bytes in
	 * length. This algorithms is also known under the alias name
	 * of rawDSA.
	 *
	 * SHA1withDSA - The DSA with SHA-1 signature algorithm which uses the SHA-1 digest algorithm and DSA to create and
	 * verify DSA digital signatures as defined in FIPS PUB 186.
	 *
	 * NONEwithECDSA SHA1withECDSA SHA256withECDSA SHA384withECDSA SHA512withECDSA (ECDSA) - The ECDSA signature
	 * algorithms as defined in ANSI X9.62. Note:"ECDSA" is an ambiguous
	 * name for the "SHA1withECDSA" algorithm and should not be used. The formal name "SHA1withECDSA" should be used
	 * instead.
	 *
	 * {@code <digest>with<encryption>} - Use this to form a name for a signature algorithm with a particular message
	 * digest
	 * (such as MD2 or MD5) and algorithm (such as RSA or DSA), just
	 * as was done for the explicitly-defined standard names in this section (MD2withRSA, etc.). For the new signature
	 * schemes defined in PKCS1 v 2.0, for which the
	 * {@code <digest>with<encryption>} form is insufficient, {@code <digest>with<encryption>and<mgf>} can be used to
	 * form a name. Here,
	 * {@code <mgf>} should be replaced by a mask generation function
	 * such as MGF1. Example: MD5withRSAandMGF1.
	 *
	 * @param javaName
	 *            the java name
	 * @return the corresponding SignatureAlgorithm
	 */
	public static SignatureAlgorithm forJAVA(final String javaName) {
		final SignatureAlgorithm algorithm = JAVA_ALGORITHMS.get(javaName);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + javaName);
		}
		return algorithm;
	}

	/**
	 * For given encryption algorithm and digest algorithm this function returns the signature algorithm.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @return the corresponding combination of both algorithms
	 */
	public static SignatureAlgorithm getAlgorithm(final EncryptionAlgorithm encryptionAlgorithm,
												  final DigestAlgorithm digestAlgorithm) {
		return getAlgorithm(encryptionAlgorithm, digestAlgorithm, null);
	}

	/**
	 * For given encryption algorithm and digest algorithm this function returns the signature algorithm.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @param mgf
	 *            the mask generation function
	 * @return the corresponding combination of both algorithms
	 */
	public static SignatureAlgorithm getAlgorithm(final EncryptionAlgorithm encryptionAlgorithm,
												  final DigestAlgorithm digestAlgorithm,
												  final MaskGenerationFunction mgf) {

		StringBuilder sb = new StringBuilder();
		sb.append(digestAlgorithm.getName());
		sb.append("with");
		sb.append(encryptionAlgorithm.getName());
		if (mgf != null) {
			sb.append("andMGF1");
		}
		return forJAVA(sb.toString());
	}

	public static SignatureAlgorithm[] values() {
		return ALGORITHMS.toArray(new SignatureAlgorithm[0]);
	}

	public static SignatureAlgorithm register(final String name,
											  final EncryptionAlgorithm encryptionAlgorithm,
											  final DigestAlgorithm digestAlgorithm,
											  final String providerName) {
		return new SignatureAlgorithm(name, encryptionAlgorithm, digestAlgorithm, null, providerName);
	}

	public static SignatureAlgorithm register(final String name,
											  final EncryptionAlgorithm encryptionAlgorithm,
											  final DigestAlgorithm digestAlgorithm,
											  final MaskGenerationFunction maskGenerationFunction,
											  final String providerName) {
		return new SignatureAlgorithm(name, encryptionAlgorithm, digestAlgorithm, maskGenerationFunction, providerName);
	}

	/**
	 * The default constructor.
	 *
	 * @param name
	 *            name of algorithm
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @param providerName
	 *            the name of security provider
	 */
	private SignatureAlgorithm(final String name,
							   final EncryptionAlgorithm encryptionAlgorithm,
							   final DigestAlgorithm digestAlgorithm,
							   final String providerName) {
		this(name, encryptionAlgorithm, digestAlgorithm, null, providerName);
	}

	/**
	 * The default constructor.
	 *
	 * @param name
	 *            name of algorithm
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @param maskGenerationFunction
	 *            the mask generation function
	 * @param providerName
	 *            the name of security provider
	 */
	private SignatureAlgorithm(final String name,
							   final EncryptionAlgorithm encryptionAlgorithm,
							   final DigestAlgorithm digestAlgorithm,
							   final MaskGenerationFunction maskGenerationFunction,
							   final String providerName) {
		this.name = name;
		this.encryptionAlgo = encryptionAlgorithm;
		this.digestAlgo = digestAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
		this.providerName = providerName;
		NAME_ALGORITHMS.put(name, this);
	}


	public Signature getAlgorithmInstance() throws NoSuchAlgorithmException {
		try {
			return Signature.getInstance(getJCEId(), getProviderName());
		} catch (NoSuchProviderException e) {
			return Signature.getInstance(getName());
		}
	}

	public String getName() {
		return name;
	}

	/**
	 * This method returns the encryption algorithm.
	 *
	 * @return the encryption algorithm
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgo;
	}

	/**
	 * This method returns the digest algorithm.
	 *
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgo;
	}

	/**
	 * This method returns the mask generation function.
	 *
	 * @return the mask generation function
	 */
	public MaskGenerationFunction getMaskGenerationFunction() {
		return maskGenerationFunction;
	}

	/**
	 * Returns the XML ID of the signature algorithm.
	 *
	 * @return the XML URI for the current signature algorithm.
	 */
	public String getXMLId() {
		return XML_ALGORITHMS_FOR_KEY.get(this);
	}

	/**
	 * Returns algorithm identifier corresponding to JAVA JCE class names.
	 *
	 * @return the java name for the current signature algorithm.
	 */
	public String getJCEId() {
		return JAVA_ALGORITHMS_FOR_KEY.get(this);
	}

	/**
	 * Returns security provider name that provides algorithm implementation
	 * @return provider name
	 */
	public String getProviderName() {
		return providerName;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SignatureAlgorithm that = (SignatureAlgorithm) o;
		return Objects.equals(name, that.name) &&
			Objects.equals(encryptionAlgo, that.encryptionAlgo) &&
			Objects.equals(digestAlgo, that.digestAlgo) &&
			maskGenerationFunction == that.maskGenerationFunction &&
			Objects.equals(providerName, that.providerName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, encryptionAlgo, digestAlgo, maskGenerationFunction, providerName);
	}

	@Override
	public String toString() {
		return name;
	}
}
