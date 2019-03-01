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
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Supported signature encryption algorithms.
 */
public class EncryptionAlgorithm implements Serializable {

	private static final Map<String, EncryptionAlgorithm> OID_ALGORITHMS = new ConcurrentHashMap<>();
	private static final Map<String, EncryptionAlgorithm> NAME_ALGORITHMS = new ConcurrentHashMap<>();

	public static EncryptionAlgorithm RSA = register("RSA",
		"1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding", DSSProvider.PROVIDER_NAME);

	public static EncryptionAlgorithm DSA = register("DSA",
		"1.2.840.10040.4.1", "DSA", DSSProvider.PROVIDER_NAME);

	public static EncryptionAlgorithm ECDSA =
		withAlias("ECC",
			withAlias("EC",
				register("ECDSA",
					"1.2.840.10045.2.1", "ECDSA", DSSProvider.PROVIDER_NAME)));

	public static EncryptionAlgorithm HMAC = register("HMAC",
		"", "", DSSProvider.PROVIDER_NAME);

	private String name;
	private String oid;
	private String padding;
	private String providerName;

	public static EncryptionAlgorithm withAlias(String alias, EncryptionAlgorithm algorithm) {
		NAME_ALGORITHMS.put(alias, algorithm);
		return algorithm;
	}

	/**
	 * Returns the encryption algorithm associated to the given OID.
	 *
	 * @param oid
	 *            the ASN1 algorithm OID
	 * @return the linked encryption algorithm
	 * @throws DSSException
	 *             if the oid doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forOID(String oid) throws DSSException {
		EncryptionAlgorithm algorithm = OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the encryption algorithm name
	 * @return the linked encryption algorithm
	 * @throws DSSException
	 *             if the name doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forName(final String name) throws DSSException {
		EncryptionAlgorithm algorithm = NAME_ALGORITHMS.get(name);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + name);
		}
		return algorithm;
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the encryption algorithm name
	 * @param defaultValue
	 *            The default value for the {@code EncryptionAlgorithm}
	 * @return the corresponding {@code EncryptionAlgorithm} or the default value
	 */
	public static EncryptionAlgorithm forName(final String name, final EncryptionAlgorithm defaultValue) {
		EncryptionAlgorithm algorithm = NAME_ALGORITHMS.get(name);
		if (algorithm == null) {
			return defaultValue;
		}
		return algorithm;
	}

	public static EncryptionAlgorithm register(final String name, final String oid,
											   final String padding, final String providerName) {
		return new EncryptionAlgorithm(name, oid, padding, providerName);
	}

	private EncryptionAlgorithm(String name, String oid, String padding, String providerName) {
		this.name = name;
		this.oid = oid;
		this.padding = padding;
		this.providerName = providerName;

		OID_ALGORITHMS.put(oid, this);
		NAME_ALGORITHMS.put(name, this);
	}


	public KeyPairGenerator getAlgorithmInstance() throws NoSuchAlgorithmException {
		try {
			return KeyPairGenerator.getInstance(getName(), getProviderName());
		} catch (NoSuchProviderException e) {
			return KeyPairGenerator.getInstance(name);
		}
	}

	/**
	 * Get the algorithm name
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the ASN1 algorithm OID
	 * 
	 * @return the OID
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Get the algorithm padding
	 * 
	 * @return the padding
	 */
	public String getPadding() {
		return padding;
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
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		EncryptionAlgorithm that = (EncryptionAlgorithm) o;
		return Objects.equals(name, that.name) &&
			Objects.equals(oid, that.oid) &&
			Objects.equals(padding, that.padding) &&
			Objects.equals(providerName, that.providerName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, oid, padding, providerName);
	}

	@Override
	public String toString() {
		return name;
	}
}
