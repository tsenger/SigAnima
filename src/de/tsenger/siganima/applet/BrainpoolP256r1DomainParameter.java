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


public class BrainpoolP256r1DomainParameter {
	
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

	// -- BP_curve_P256r1 - ECC Brainpool Standard Curves and Curve Generation v. 1.0 ----------------

    final static byte[] p_BP_curve_P256r1 = { (byte) 0xA9, (byte) 0xFB, (byte) 0x57, (byte) 0xDB, (byte) 0xA1,
        (byte) 0xEE, (byte) 0xA9, (byte) 0xBC, (byte) 0x3E, (byte) 0x66, (byte) 0x0A, (byte) 0x90, (byte) 0x9D,
        (byte) 0x83, (byte) 0x8D, (byte) 0x72, (byte) 0x6E, (byte) 0x3B, (byte) 0xF6, (byte) 0x23, (byte) 0xD5,
        (byte) 0x26, (byte) 0x20, (byte) 0x28, (byte) 0x20, (byte) 0x13, (byte) 0x48, (byte) 0x1D, (byte) 0x1F,
        (byte) 0x6E, (byte) 0x53, (byte) 0x77 };

    final static byte[] a_BP_curve_P256r1 = { (byte) 0x7D, (byte) 0x5A, (byte) 0x09, (byte) 0x75, (byte) 0xFC,
        (byte) 0x2C, (byte) 0x30, (byte) 0x57, (byte) 0xEE, (byte) 0xF6, (byte) 0x75, (byte) 0x30, (byte) 0x41,
        (byte) 0x7A, (byte) 0xFF, (byte) 0xE7, (byte) 0xFB, (byte) 0x80, (byte) 0x55, (byte) 0xC1, (byte) 0x26,
        (byte) 0xDC, (byte) 0x5C, (byte) 0x6C, (byte) 0xE9, (byte) 0x4A, (byte) 0x4B, (byte) 0x44, (byte) 0xF3,
        (byte) 0x30, (byte) 0xB5, (byte) 0xD9 };

    final static byte[] b_BP_curve_P256r1 = { (byte) 0x26, (byte) 0xDC, (byte) 0x5C, (byte) 0x6C, (byte) 0xE9,
        (byte) 0x4A, (byte) 0x4B, (byte) 0x44, (byte) 0xF3, (byte) 0x30, (byte) 0xB5, (byte) 0xD9, (byte) 0xBB,
        (byte) 0xD7, (byte) 0x7C, (byte) 0xBF, (byte) 0x95, (byte) 0x84, (byte) 0x16, (byte) 0x29, (byte) 0x5C,
        (byte) 0xF7, (byte) 0xE1, (byte) 0xCE, (byte) 0x6B, (byte) 0xCC, (byte) 0xDC, (byte) 0x18, (byte) 0xFF,
        (byte) 0x8C, (byte) 0x07, (byte) 0xB6 };

    final static byte[] P_BP_curve_P256r1 = {
        (byte) 0x04, // uncompressed
        (byte) 0x8B, (byte) 0xD2, (byte) 0xAE, (byte) 0xB9, (byte) 0xCB, (byte) 0x7E, (byte) 0x57, (byte) 0xCB,
        (byte) 0x2C, (byte) 0x4B, (byte) 0x48, (byte) 0x2F, (byte) 0xFC, (byte) 0x81, (byte) 0xB7, (byte) 0xAF,
        (byte) 0xB9, (byte) 0xDE, (byte) 0x27, (byte) 0xE1, (byte) 0xE3, (byte) 0xBD, (byte) 0x23, (byte) 0xC2,
        (byte) 0x3A, (byte) 0x44, (byte) 0x53, (byte) 0xBD, (byte) 0x9A, (byte) 0xCE, (byte) 0x32, (byte) 0x62,
        (byte) 0x54, (byte) 0x7E, (byte) 0xF8, (byte) 0x35, (byte) 0xC3, (byte) 0xDA, (byte) 0xC4, (byte) 0xFD,
        (byte) 0x97, (byte) 0xF8, (byte) 0x46, (byte) 0x1A, (byte) 0x14, (byte) 0x61, (byte) 0x1D, (byte) 0xC9,
        (byte) 0xC2, (byte) 0x77, (byte) 0x45, (byte) 0x13, (byte) 0x2D, (byte) 0xED, (byte) 0x8E, (byte) 0x54,
        (byte) 0x5C, (byte) 0x1D, (byte) 0x54, (byte) 0xC7, (byte) 0x2F, (byte) 0x04, (byte) 0x69, (byte) 0x97 };

    final static byte[] m_BP_curve_P256r1 = { (byte) 0xA9, (byte) 0xFB, (byte) 0x57, (byte) 0xDB, (byte) 0xA1,
        (byte) 0xEE, (byte) 0xA9, (byte) 0xBC, (byte) 0x3E, (byte) 0x66, (byte) 0x0A, (byte) 0x90, (byte) 0x9D,
        (byte) 0x83, (byte) 0x8D, (byte) 0x71, (byte) 0x8C, (byte) 0x39, (byte) 0x7A, (byte) 0xA3, (byte) 0xB5,
        (byte) 0x61, (byte) 0xA6, (byte) 0xF7, (byte) 0x90, (byte) 0x1E, (byte) 0x0E, (byte) 0x82, (byte) 0x97,
        (byte) 0x48, (byte) 0x56, (byte) 0xA7 };
	
    private static ECPrivateKey ecPrivateKey;
	private static ECPublicKey ecPublicKey;


	private BrainpoolP256r1DomainParameter() {
		ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
		ecPrivateKey.setFieldFP(p_BP_curve_P256r1, (short) 0, (short) p_BP_curve_P256r1.length); // prime p
    	ecPrivateKey.setA(a_BP_curve_P256r1, (short) 0, (short) a_BP_curve_P256r1.length); // first coefficient
    	ecPrivateKey.setB(b_BP_curve_P256r1, (short) 0, (short) b_BP_curve_P256r1.length); // second coefficient
    	ecPrivateKey.setG(P_BP_curve_P256r1, (short) 0, (short) P_BP_curve_P256r1.length); // base point G
    	ecPrivateKey.setR(m_BP_curve_P256r1, (short) 0, (short) m_BP_curve_P256r1.length); // order of base point
    	
    	ecPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);
    	ecPublicKey.setFieldFP(p_BP_curve_P256r1, (short) 0, (short) p_BP_curve_P256r1.length); // prime p
    	ecPublicKey.setA(a_BP_curve_P256r1, (short) 0, (short) a_BP_curve_P256r1.length); // first coefficient
    	ecPublicKey.setB(b_BP_curve_P256r1, (short) 0, (short) b_BP_curve_P256r1.length); // second coefficient
    	ecPublicKey.setG(P_BP_curve_P256r1, (short) 0, (short) P_BP_curve_P256r1.length); // base point G
    	ecPublicKey.setR(m_BP_curve_P256r1, (short) 0, (short) m_BP_curve_P256r1.length); // order of base point
    	
	}
	
	public static KeyPair getKeyPairParameter() {
		new BrainpoolP256r1DomainParameter();
		return new KeyPair(ecPublicKey, ecPrivateKey);
	}

}
