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


public class BrainpoolP224r1DomainParameter {
	
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

	// -- BP_curve_P224r1 - ECC Brainpool Standard Curves and Curve Generation v. 1.0 ----------------

    public final static byte[] p_BP_curve_P224r1 = { (byte) 0xD7, (byte) 0xC1, (byte) 0x34, (byte) 0xAA, (byte) 0x26,
        (byte) 0x43, (byte) 0x66, (byte) 0x86, (byte) 0x2A, (byte) 0x18, (byte) 0x30, (byte) 0x25, (byte) 0x75,
        (byte) 0xD1, (byte) 0xD7, (byte) 0x87, (byte) 0xB0, (byte) 0x9F, (byte) 0x07, (byte) 0x57, (byte) 0x97,
        (byte) 0xDA, (byte) 0x89, (byte) 0xF5, (byte) 0x7E, (byte) 0xC8, (byte) 0xC0, (byte) 0xFF };

    public final static byte[] a_BP_curve_P224r1 = { (byte) 0x68, (byte) 0xA5, (byte) 0xE6, (byte) 0x2C, (byte) 0xA9,
        (byte) 0xCE, (byte) 0x6C, (byte) 0x1C, (byte) 0x29, (byte) 0x98, (byte) 0x03, (byte) 0xA6, (byte) 0xC1,
        (byte) 0x53, (byte) 0x0B, (byte) 0x51, (byte) 0x4E, (byte) 0x18, (byte) 0x2A, (byte) 0xD8, (byte) 0xB0,
        (byte) 0x04, (byte) 0x2A, (byte) 0x59, (byte) 0xCA, (byte) 0xD2, (byte) 0x9F, (byte) 0x43 };

    public final static byte[] b_BP_curve_P224r1 = { (byte) 0x25, (byte) 0x80, (byte) 0xF6, (byte) 0x3C, (byte) 0xCF,
        (byte) 0xE4, (byte) 0x41, (byte) 0x38, (byte) 0x87, (byte) 0x07, (byte) 0x13, (byte) 0xB1, (byte) 0xA9,
        (byte) 0x23, (byte) 0x69, (byte) 0xE3, (byte) 0x3E, (byte) 0x21, (byte) 0x35, (byte) 0xD2, (byte) 0x66,
        (byte) 0xDB, (byte) 0xB3, (byte) 0x72, (byte) 0x38, (byte) 0x6C, (byte) 0x40, (byte) 0x0B };

    public final static byte[] P_BP_curve_P224r1 = {
        (byte) 0x04, // uncompressed
        (byte) 0x0D, (byte) 0x90, (byte) 0x29, (byte) 0xAD, (byte) 0x2C, (byte) 0x7E, (byte) 0x5C, (byte) 0xF4,
        (byte) 0x34, (byte) 0x08, (byte) 0x23, (byte) 0xB2, (byte) 0xA8, (byte) 0x7D, (byte) 0xC6, (byte) 0x8C,
        (byte) 0x9E, (byte) 0x4C, (byte) 0xE3, (byte) 0x17, (byte) 0x4C, (byte) 0x1E, (byte) 0x6E, (byte) 0xFD,
        (byte) 0xEE, (byte) 0x12, (byte) 0xC0, (byte) 0x7D, (byte) 0x58, (byte) 0xAA, (byte) 0x56, (byte) 0xF7,
        (byte) 0x72, (byte) 0xC0, (byte) 0x72, (byte) 0x6F, (byte) 0x24, (byte) 0xC6, (byte) 0xB8, (byte) 0x9E,
        (byte) 0x4E, (byte) 0xCD, (byte) 0xAC, (byte) 0x24, (byte) 0x35, (byte) 0x4B, (byte) 0x9E, (byte) 0x99,
        (byte) 0xCA, (byte) 0xA3, (byte) 0xF6, (byte) 0xD3, (byte) 0x76, (byte) 0x14, (byte) 0x02, (byte) 0xCD };

    public final static byte[] m_BP_curve_P224r1 = { (byte) 0xD7, (byte) 0xC1, (byte) 0x34, (byte) 0xAA, (byte) 0x26,
        (byte) 0x43, (byte) 0x66, (byte) 0x86, (byte) 0x2A, (byte) 0x18, (byte) 0x30, (byte) 0x25, (byte) 0x75,
        (byte) 0xD0, (byte) 0xFB, (byte) 0x98, (byte) 0xD1, (byte) 0x16, (byte) 0xBC, (byte) 0x4B, (byte) 0x6D,
        (byte) 0xDE, (byte) 0xBC, (byte) 0xA3, (byte) 0xA5, (byte) 0xA7, (byte) 0x93, (byte) 0x9F };
	
    private static ECPrivateKey ecPrivateKey;
	private static ECPublicKey ecPublicKey;


	private BrainpoolP224r1DomainParameter() {
		ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)224, false);
		ecPrivateKey.setFieldFP(p_BP_curve_P224r1, (short) 0, (short) p_BP_curve_P224r1.length); // prime p
    	ecPrivateKey.setA(a_BP_curve_P224r1, (short) 0, (short) a_BP_curve_P224r1.length); // first coefficient
    	ecPrivateKey.setB(b_BP_curve_P224r1, (short) 0, (short) b_BP_curve_P224r1.length); // second coefficient
    	ecPrivateKey.setG(P_BP_curve_P224r1, (short) 0, (short) P_BP_curve_P224r1.length); // base point G
    	ecPrivateKey.setR(m_BP_curve_P224r1, (short) 0, (short) m_BP_curve_P224r1.length); // order of base point
    	
    	ecPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)224, false);
    	ecPublicKey.setFieldFP(p_BP_curve_P224r1, (short) 0, (short) p_BP_curve_P224r1.length); // prime p
    	ecPublicKey.setA(a_BP_curve_P224r1, (short) 0, (short) a_BP_curve_P224r1.length); // first coefficient
    	ecPublicKey.setB(b_BP_curve_P224r1, (short) 0, (short) b_BP_curve_P224r1.length); // second coefficient
    	ecPublicKey.setG(P_BP_curve_P224r1, (short) 0, (short) P_BP_curve_P224r1.length); // base point G
    	ecPublicKey.setR(m_BP_curve_P224r1, (short) 0, (short) m_BP_curve_P224r1.length); // order of base point
    	
	}
	
	public static KeyPair getKeyPairParameter() {
		new BrainpoolP224r1DomainParameter();
		return new KeyPair(ecPublicKey, ecPrivateKey);
	}

}
