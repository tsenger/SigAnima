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


public class BrainpoolP320r1DomainParameter {
	
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

	// -- BP_curve_P320r1 - ECC Brainpool Standard Curves and Curve Generation v. 1.0 ----------------

    final static byte[] p_BP_curve_P320r1 = { (byte) 0xD3, (byte) 0x5E, (byte) 0x47, (byte) 0x20, (byte) 0x36,
        (byte) 0xBC, (byte) 0x4F, (byte) 0xB7, (byte) 0xE1, (byte) 0x3C, (byte) 0x78, (byte) 0x5E, (byte) 0xD2,
        (byte) 0x01, (byte) 0xE0, (byte) 0x65, (byte) 0xF9, (byte) 0x8F, (byte) 0xCF, (byte) 0xA6, (byte) 0xF6,
        (byte) 0xF4, (byte) 0x0D, (byte) 0xEF, (byte) 0x4F, (byte) 0x92, (byte) 0xB9, (byte) 0xEC, (byte) 0x78,
        (byte) 0x93, (byte) 0xEC, (byte) 0x28, (byte) 0xFC, (byte) 0xD4, (byte) 0x12, (byte) 0xB1, (byte) 0xF1,
        (byte) 0xB3, (byte) 0x2E, (byte) 0x27 };

    final static byte[] a_BP_curve_P320r1 = { (byte) 0x3E, (byte) 0xE3, (byte) 0x0B, (byte) 0x56, (byte) 0x8F,
        (byte) 0xBA, (byte) 0xB0, (byte) 0xF8, (byte) 0x83, (byte) 0xCC, (byte) 0xEB, (byte) 0xD4, (byte) 0x6D,
        (byte) 0x3F, (byte) 0x3B, (byte) 0xB8, (byte) 0xA2, (byte) 0xA7, (byte) 0x35, (byte) 0x13, (byte) 0xF5,
        (byte) 0xEB, (byte) 0x79, (byte) 0xDA, (byte) 0x66, (byte) 0x19, (byte) 0x0E, (byte) 0xB0, (byte) 0x85,
        (byte) 0xFF, (byte) 0xA9, (byte) 0xF4, (byte) 0x92, (byte) 0xF3, (byte) 0x75, (byte) 0xA9, (byte) 0x7D,
        (byte) 0x86, (byte) 0x0E, (byte) 0xB4 };

    final static byte[] b_BP_curve_P320r1 = { (byte) 0x52, (byte) 0x08, (byte) 0x83, (byte) 0x94, (byte) 0x9D,
        (byte) 0xFD, (byte) 0xBC, (byte) 0x42, (byte) 0xD3, (byte) 0xAD, (byte) 0x19, (byte) 0x86, (byte) 0x40,
        (byte) 0x68, (byte) 0x8A, (byte) 0x6F, (byte) 0xE1, (byte) 0x3F, (byte) 0x41, (byte) 0x34, (byte) 0x95,
        (byte) 0x54, (byte) 0xB4, (byte) 0x9A, (byte) 0xCC, (byte) 0x31, (byte) 0xDC, (byte) 0xCD, (byte) 0x88,
        (byte) 0x45, (byte) 0x39, (byte) 0x81, (byte) 0x6F, (byte) 0x5E, (byte) 0xB4, (byte) 0xAC, (byte) 0x8F,
        (byte) 0xB1, (byte) 0xF1, (byte) 0xA6 };

    final static byte[] P_BP_curve_P320r1 = {
        (byte) 0x04, // uncompressed
        (byte) 0x43, (byte) 0xBD, (byte) 0x7E, (byte) 0x9A, (byte) 0xFB, (byte) 0x53, (byte) 0xD8, (byte) 0xB8,
        (byte) 0x52, (byte) 0x89, (byte) 0xBC, (byte) 0xC4, (byte) 0x8E, (byte) 0xE5, (byte) 0xBF, (byte) 0xE6,
        (byte) 0xF2, (byte) 0x01, (byte) 0x37, (byte) 0xD1, (byte) 0x0A, (byte) 0x08, (byte) 0x7E, (byte) 0xB6,
        (byte) 0xE7, (byte) 0x87, (byte) 0x1E, (byte) 0x2A, (byte) 0x10, (byte) 0xA5, (byte) 0x99, (byte) 0xC7,
        (byte) 0x10, (byte) 0xAF, (byte) 0x8D, (byte) 0x0D, (byte) 0x39, (byte) 0xE2, (byte) 0x06, (byte) 0x11,
        (byte) 0x14, (byte) 0xFD, (byte) 0xD0, (byte) 0x55, (byte) 0x45, (byte) 0xEC, (byte) 0x1C, (byte) 0xC8,
        (byte) 0xAB, (byte) 0x40, (byte) 0x93, (byte) 0x24, (byte) 0x7F, (byte) 0x77, (byte) 0x27, (byte) 0x5E,
        (byte) 0x07, (byte) 0x43, (byte) 0xFF, (byte) 0xED, (byte) 0x11, (byte) 0x71, (byte) 0x82, (byte) 0xEA,
        (byte) 0xA9, (byte) 0xC7, (byte) 0x78, (byte) 0x77, (byte) 0xAA, (byte) 0xAC, (byte) 0x6A, (byte) 0xC7,
        (byte) 0xD3, (byte) 0x52, (byte) 0x45, (byte) 0xD1, (byte) 0x69, (byte) 0x2E, (byte) 0x8E, (byte) 0xE1 };

    final static byte[] m_BP_curve_P320r1 = { (byte) 0xD3, (byte) 0x5E, (byte) 0x47, (byte) 0x20, (byte) 0x36,
        (byte) 0xBC, (byte) 0x4F, (byte) 0xB7, (byte) 0xE1, (byte) 0x3C, (byte) 0x78, (byte) 0x5E, (byte) 0xD2,
        (byte) 0x01, (byte) 0xE0, (byte) 0x65, (byte) 0xF9, (byte) 0x8F, (byte) 0xCF, (byte) 0xA5, (byte) 0xB6,
        (byte) 0x8F, (byte) 0x12, (byte) 0xA3, (byte) 0x2D, (byte) 0x48, (byte) 0x2E, (byte) 0xC7, (byte) 0xEE,
        (byte) 0x86, (byte) 0x58, (byte) 0xE9, (byte) 0x86, (byte) 0x91, (byte) 0x55, (byte) 0x5B, (byte) 0x44,
        (byte) 0xC5, (byte) 0x93, (byte) 0x11 };
	
    private static ECPrivateKey ecPrivateKey;
	private static ECPublicKey ecPublicKey;


	private BrainpoolP320r1DomainParameter() {
		ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)320, false);
		ecPrivateKey.setFieldFP(p_BP_curve_P320r1, (short) 0, (short) p_BP_curve_P320r1.length); // prime p
    	ecPrivateKey.setA(a_BP_curve_P320r1, (short) 0, (short) a_BP_curve_P320r1.length); // first coefficient
    	ecPrivateKey.setB(b_BP_curve_P320r1, (short) 0, (short) b_BP_curve_P320r1.length); // second coefficient
    	ecPrivateKey.setG(P_BP_curve_P320r1, (short) 0, (short) P_BP_curve_P320r1.length); // base point G
    	ecPrivateKey.setR(m_BP_curve_P320r1, (short) 0, (short) m_BP_curve_P320r1.length); // order of base point
    	
    	ecPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)320, false);
    	ecPublicKey.setFieldFP(p_BP_curve_P320r1, (short) 0, (short) p_BP_curve_P320r1.length); // prime p
    	ecPublicKey.setA(a_BP_curve_P320r1, (short) 0, (short) a_BP_curve_P320r1.length); // first coefficient
    	ecPublicKey.setB(b_BP_curve_P320r1, (short) 0, (short) b_BP_curve_P320r1.length); // second coefficient
    	ecPublicKey.setG(P_BP_curve_P320r1, (short) 0, (short) P_BP_curve_P320r1.length); // base point G
    	ecPublicKey.setR(m_BP_curve_P320r1, (short) 0, (short) m_BP_curve_P320r1.length); // order of base point
    	
	}
	
	public static KeyPair getKeyPairParameter() {
		new BrainpoolP320r1DomainParameter();
		return new KeyPair(ecPublicKey, ecPrivateKey);
	}

}
