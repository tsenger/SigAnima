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


public class SecP256r1DomainParameter {
	
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
	
	// secp256r1 parameter
    public final static byte[] p_secp256r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
        (byte) 0xFF, (byte) 0xFF };

    public final static byte[] a_secp256r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
        (byte) 0xFF, (byte) 0xFC };

    public final static byte[] b_secp256r1 = { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, 
    	(byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, 
    	(byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, 
    	(byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, 
    	(byte) 0x60, (byte) 0x4B };

    public final static byte[] P_secp256r1 = {
        (byte) 0x04, // uncompressed
        (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, 
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, 
        (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, 
        (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, 
        (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, 
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, 
        (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, 
        (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 };

    public final static byte[] m_secp256r1 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, 
        (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, 
        (byte) 0x25, (byte) 0x51 };
	
    private static ECPrivateKey ecPrivateKey;
	private static ECPublicKey ecPublicKey;


	private SecP256r1DomainParameter() {
		ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
		ecPrivateKey.setFieldFP(p_secp256r1, (short) 0, (short) p_secp256r1.length); // prime p
    	ecPrivateKey.setA(a_secp256r1, (short) 0, (short) a_secp256r1.length); // first coefficient
    	ecPrivateKey.setB(b_secp256r1, (short) 0, (short) b_secp256r1.length); // second coefficient
    	ecPrivateKey.setG(P_secp256r1, (short) 0, (short) P_secp256r1.length); // base point G
    	ecPrivateKey.setR(m_secp256r1, (short) 0, (short) m_secp256r1.length); // order of base point
    	
    	ecPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);
    	ecPublicKey.setFieldFP(p_secp256r1, (short) 0, (short) p_secp256r1.length); // prime p
    	ecPublicKey.setA(a_secp256r1, (short) 0, (short) a_secp256r1.length); // first coefficient
    	ecPublicKey.setB(b_secp256r1, (short) 0, (short) b_secp256r1.length); // second coefficient
    	ecPublicKey.setG(P_secp256r1, (short) 0, (short) P_secp256r1.length); // base point G
    	ecPublicKey.setR(m_secp256r1, (short) 0, (short) m_secp256r1.length); // order of base point
    	
	}
	
	public static KeyPair getKeyPairParameter() {
		new SecP256r1DomainParameter();
		return new KeyPair(ecPublicKey, ecPrivateKey);
	}

}
