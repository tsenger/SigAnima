/*
 * SigAnima - ECDSA Signing Applet. 
 *
 * Copyright (C) 2012 tsenger
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package de.tsenger.siganima.applet;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;


public class SecP224r1DomainParameter {
	
	/**
	 * Key object which implements the interface type <code>ECPublicKey</code>
	 * for EC operations over large prime fields.
	 */
	public static final byte TYPE_EC_FP_PUBLIC = 11;

	/**
	 * Key object which implements the interface type <code>ECPrivateKey</code>
	 * for EC operations over large prime fields.
	 */
	public static final byte TYPE_EC_FP_PRIVATE = 12;

	// sec224r1 parameter
    public final static byte[] p_secp224r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };

    public final static byte[] a_secp224r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE };

    public final static byte[] b_secp224r1 = { (byte) 0xB4, (byte) 0x05, (byte) 0x0A, (byte) 0x85, (byte) 0x0C, (byte) 0x04,
        (byte) 0xB3, (byte) 0xAB, (byte) 0xF5, (byte) 0x41, (byte) 0x32, (byte) 0x56, (byte) 0x50, (byte) 0x44,
        (byte) 0xB0, (byte) 0xB7, (byte) 0xD7, (byte) 0xBF, (byte) 0xD8, (byte) 0xBA, (byte) 0x27, (byte) 0x0B,
        (byte) 0x39, (byte) 0x43, (byte) 0x23, (byte) 0x55, (byte) 0xFF, (byte) 0xB4 };

    public final static byte[] P_secp224r1 = {
        (byte) 0x04, // uncompressed
        (byte) 0xB7, (byte) 0x0E, (byte) 0x0C, (byte) 0xBD, (byte) 0x6B, (byte) 0xB4, (byte) 0xBF, (byte) 0x7F,
        (byte) 0x32, (byte) 0x13, (byte) 0x90, (byte) 0xB9, (byte) 0x4A, (byte) 0x03, (byte) 0xC1, (byte) 0xD3,
        (byte) 0x56, (byte) 0xC2, (byte) 0x11, (byte) 0x22, (byte) 0x34, (byte) 0x32, (byte) 0x80, (byte) 0xD6,
        (byte) 0x11, (byte) 0x5C, (byte) 0x1D, (byte) 0x21, (byte) 0xBD, (byte) 0x37, (byte) 0x63, (byte) 0x88,
        (byte) 0xB5, (byte) 0xF7, (byte) 0x23, (byte) 0xFB, (byte) 0x4C, (byte) 0x22, (byte) 0xDF, (byte) 0xE6,
        (byte) 0xCD, (byte) 0x43, (byte) 0x75, (byte) 0xA0, (byte) 0x5A, (byte) 0x07, (byte) 0x47, (byte) 0x64,
        (byte) 0x44, (byte) 0xD5, (byte) 0x81, (byte) 0x99, (byte) 0x85, (byte) 0x00, (byte) 0x7E, (byte) 0x34 };

    public final static byte[] m_secp224r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x16, (byte) 0xA2, (byte) 0xE0, (byte) 0xB8, (byte) 0xF0, (byte) 0x3E, (byte) 0x13, (byte) 0xDD,
        (byte) 0x29, (byte) 0x45, (byte) 0x5C, (byte) 0x5C, (byte) 0x2A, (byte) 0x3D };
	
    private static ECPrivateKey ecPrivateKey;
	private static ECPublicKey ecPublicKey;


	private SecP224r1DomainParameter() {
		ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)224, false);
		ecPrivateKey.setFieldFP(p_secp224r1, (short) 0, (short) p_secp224r1.length); // prime p
    	ecPrivateKey.setA(a_secp224r1, (short) 0, (short) a_secp224r1.length); // first coefficient
    	ecPrivateKey.setB(b_secp224r1, (short) 0, (short) b_secp224r1.length); // second coefficient
    	ecPrivateKey.setG(P_secp224r1, (short) 0, (short) P_secp224r1.length); // base point G
    	ecPrivateKey.setR(m_secp224r1, (short) 0, (short) m_secp224r1.length); // order of base point
    	
    	ecPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)224, false);
    	ecPublicKey.setFieldFP(p_secp224r1, (short) 0, (short) p_secp224r1.length); // prime p
    	ecPublicKey.setA(a_secp224r1, (short) 0, (short) a_secp224r1.length); // first coefficient
    	ecPublicKey.setB(b_secp224r1, (short) 0, (short) b_secp224r1.length); // second coefficient
    	ecPublicKey.setG(P_secp224r1, (short) 0, (short) P_secp224r1.length); // base point G
    	ecPublicKey.setR(m_secp224r1, (short) 0, (short) m_secp224r1.length); // order of base point
    	
	}
	
	public static KeyPair getKeyPairParameter() {
		new SecP224r1DomainParameter();
		return new KeyPair(ecPublicKey, ecPrivateKey);
	}

}
