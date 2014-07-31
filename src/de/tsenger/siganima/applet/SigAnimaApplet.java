/* This file is part of SigAnima - ECDSA Signing Applet. 
 * This software is based on the "Java Card PKI applet", 2009 
 * from Wojciech Mostowski, woj@cs.ru.nl 
 * 
 * Copyright (C) 2012 Tobias Senger
 * 
 * SigAnima is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SigAnima is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with SigAnima. If not, see <http://www.gnu.org/licenses/>.
*/

//JCOP Extended API 2.4.2 R2
//JavaCard Classic 3.0.1

package de.tsenger.siganima.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;

import org.globalplatform.GPSystem;

import com.nxp.id.jcopx.SignatureX;

/**
 * @author tsenger
 * @version 1.2
 * 
 */
public class SigAnimaApplet extends Applet implements ISO7816 {

	/** AID of this applet */
	private static final byte[] AID = new byte[] { (byte)0xD2, 0x76, 0x00, 0x01, 0x32, 0x45, 0x43, 0x53, 0x49, 0x47};

	/** CLAss byte masks */
	private static final byte CLA_CHAIN = 0x10;
	private static final byte CLA_SM = 0x0C;

	/** INStructions */
	private static final byte INS_READBINARY = (byte) 0xB0;
	private static final byte INS_GETCHALLENGE = (byte) 0x84;
	private static final byte INS_CHANGEREFERENCEDATA = (byte) 0x24;
	private static final byte INS_WRITEBINARY = (byte) 0xD0;
	private static final byte INS_VERIFY = (byte) 0x20;
	private static final byte INS_MSE = (byte) 0x22;
	private static final byte INS_PSO = (byte) 0x2A;
	private static final byte INS_GENERATE_KEY_PAIR = (byte) 0x46;
	private static final byte INS_PUTDATA = (byte)0xDA;
    private static final byte INS_CREATEFILE = (byte)0xE0;

	/** SW-s not defined in the ISO7816 interface */
	private static final short SW_END_OF_FILE = (short) 0x6282;
	private static final short SW_PIN_INCORRECT_TRIES_LEFT = (short) 0x63C0;
	private static final short SW_SECURE_MESSAGING_NOT_SUPPORTED = (short) 0x6882;

	/** Life states of the applet */
	private static final byte STATE_INITIAL = 1;
	private static final byte STATE_PREPERSONALISED = 2;
	private static final byte STATE_PERSONALISED = 3;

	/** Other constants */
	private static final byte MASK_SFI = (byte) 0x80;
	private static final byte MAX_PIN_SIZE = 10;
	private static final byte MIN_PIN_SIZE = 4;
	private static final byte PIN_TRIES = 3;
	private static final byte PUC_SIZE = 10;
	private static final byte PUC_TRIES = 3;

	private RandomData rd = null;
	private OwnerPIN pin = null;
	private OwnerPIN puc = null;

	private byte[] tmp;
	
	private byte[] sigBuffer;
	private Signature sigECDSA;

	private KeyPair[] keyPair = new KeyPair[2];
	private byte selectedKeyId = (byte) 0xFF;
	private byte selectedDpId = (byte) 0xFF;

	private FileSystem fileSystem = null;

	private byte state = 0;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		(new SigAnimaApplet()).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	private SigAnimaApplet() {

		pin = new OwnerPIN(PIN_TRIES, MAX_PIN_SIZE);
		puc = new OwnerPIN(PUC_TRIES, PUC_SIZE);

		rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		fileSystem = new FileSystem((short) 5);
		/*This is the standard file system for our use: 
		 * 3 EFs (FID 53 01 to 53 03) for client/server certificates  and 
		 * 1 EF (FID 54 01) for the root certificate
		 * located in the MF (3F00)
		 */
		fileSystem.fileStructure = new byte[] { (byte) 0xFF, 0x3F, 0,
				(byte) 0xFF, 0x04, 0x09, 0x0E, 0x13, 0x18, 0, 0x53, 1, 0, 1, 0,
				0x53, 2, 0, 2, 0, 0x53, 3, 0, 3, 0, 0x54, 1, 0, 0x10 };
		
		tmp = JCSystem.makeTransientByteArray((short) 40, JCSystem.CLEAR_ON_DESELECT);

		sigBuffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
		sigECDSA = SignatureX.getInstance(SignatureX.ALG_ECDSA_PLAIN, false);

		state = STATE_INITIAL;

	}

	public void process(APDU apdu) {

		byte[] buf = apdu.getBuffer();
		byte cla = buf[OFFSET_CLA];
		byte ins = buf[OFFSET_INS];

		// No secure messaging for the applet
		if ((byte) (cla & CLA_SM) == CLA_SM) {
			ISOException.throwIt(SW_SECURE_MESSAGING_NOT_SUPPORTED);
		}
		// Only PSO can be chained
		if (!(cla == CLA_ISO7816 || (cla == CLA_CHAIN && ins == INS_PSO))) {
			ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
		}

		switch (ins) {
		case INS_SELECT:
			processSelectFile(apdu);
			break;
		case INS_READBINARY:
			processReadBinary(apdu);
			break;
		case INS_WRITEBINARY:
			processWriteBinary(apdu);
			break;
		case INS_VERIFY:
			processVerify(apdu);
			break;
		case INS_GETCHALLENGE:
			processGetChallenge(apdu);
			break;
		case INS_MSE:
			processManageSecurityEnvironment(apdu);
			break;
		case INS_PSO:
			processPerformSecurityOperation(apdu);
			break;
		case INS_GENERATE_KEY_PAIR:
			processGenerateAsymetricKeyPair(apdu);
			break;
		case INS_CREATEFILE:
            processCreateFile(apdu);
            break;
		case INS_PUTDATA:
            processPutData(apdu);
            break;
		case INS_CHANGEREFERENCEDATA:
            processChangeReferenceData(apdu);
            break;
		default:
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Process the SELECT (file) instruction (0xA4) ISO7816-4 Section 7.1.1 only
	 * direct selection available
	 * 
	 */
	private void processSelectFile(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		short lc = unsigned(buf[OFFSET_LC]);

		if (p1 == 0x04) {
			if (lc != (short) AID.length) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			if (Util.arrayCompare(buf, OFFSET_CDATA, AID, (short) 0, lc) != 0) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			return;
		}

		short id = 0;
		switch (p1) {
		case (byte) 0x00:
			// Direct selection of MF, DF, or EF:
			if (lc != 0 && lc != 2) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			if (lc > 0) {
				apdu.setIncomingAndReceive();
				id = Util.makeShort(buf[OFFSET_CDATA],
						buf[(short) (OFFSET_CDATA + 1)]);
			} else {
				id = FileSystem.MASTER_FILE_ID;
			}
			if (!fileSystem.selectEntryAbsolute(id)) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			break;
		case (byte) 0x01:
		case (byte) 0x02:
			// Select the child under the current DF,
			// p1 0x01 DF identifier in data field
			// p1 0x02 EF identifier in data field
			if (lc != 2) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			id = Util.makeShort(buf[OFFSET_CDATA],
					buf[(short) (OFFSET_CDATA + 1)]);
			if (!fileSystem.selectEntryUnderCurrent(id, p1 == (byte) 0x02)) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			break;
		case (byte) 0x03:
			// Select the parent of the current DF
			// no command data
			if (lc != 0) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			if (!fileSystem.selectEntryParent()) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			break;
		case (byte) 0x08:
		case (byte) 0x09:
			// Select by path
			// p1 0x08 from MF
			// p1 0x09 from current DF
			// data field: the path without the head
			if (lc == 0 || (short) (lc % 2) != 0) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			if (!fileSystem.selectEntryByPath(buf, OFFSET_CDATA, lc,
					p1 == (byte) 0x08)) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			break;
		default:
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
	}

    /**
     * Process the READ BINARY instruction (0xB0)
     * ISO7816-4 Section 7.2.3
     * 
     * We handle only the INS == 0xB0 case.
     *
     */
    private void processReadBinary(APDU apdu) {
        if(state != STATE_PERSONALISED) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[OFFSET_P1];
        byte p2 = buf[OFFSET_P2];
        short offset = 0;
        short ef = -1;
        if((byte)(p1 & MASK_SFI) == MASK_SFI) {
            byte sfi = (byte)(p1 & ~MASK_SFI);
            if(sfi >= 0x1F) {
                ISOException.throwIt(SW_INCORRECT_P1P2);
            }
              ef = fileSystem.findCurrentSFI(sfi);
              if(ef == -1) {
                ISOException.throwIt(SW_FILE_NOT_FOUND);
              }
              ef = fileSystem.fileStructure[ef];
            offset = unsigned(p2);
        }else{
            ef = fileSystem.getCurrentIndex();
            if(fileSystem.getFile(ef) == null) {
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);                
            }
            offset = Util.makeShort(p1, p2);
        }
        byte[] file = fileSystem.getFile(ef);
        if(offset > file.length) {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        if(fileSystem.getPerm(ef) == FileSystem.PERM_PIN && !pin.isValidated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short le = apdu.setOutgoing();
        if(le == 0 || le == 256) {
            le = (short)(file.length - offset);
            if(le > 256) le = 256;
        }
        boolean eof = false;
        if((short)(file.length - offset) < le) {
            le = (short)(file.length - offset);
            eof = true;
        }
        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(file, offset, le);
        if(eof) {
            ISOException.throwIt(SW_END_OF_FILE);
        }
    }

	/**
	 * Process the VERIFY instruction (0x20) ISO7816-4 Section 7.5.6
	 * 
	 */
	private void processVerify(APDU apdu) {

		byte[] buf = apdu.getBuffer();
		if (buf[OFFSET_P1] != 0x00 || buf[OFFSET_P2] != 0x00) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		short lc = unsigned(buf[OFFSET_LC]);
		if (lc < MIN_PIN_SIZE || lc > MAX_PIN_SIZE) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		// Pad the PIN to overwrite any possible garbage in the APDU (e.g. Le)
		Util.arrayFillNonAtomic(buf, (short) (OFFSET_CDATA + lc),
				(short) (MAX_PIN_SIZE - lc), (byte) 0x00);
		if (!pin.check(buf, OFFSET_CDATA, MAX_PIN_SIZE)) {
			ISOException.throwIt((short) (SW_PIN_INCORRECT_TRIES_LEFT | pin.getTriesRemaining()));
		}
	}
	
    /**
     * Process the CHANGE REFERENCE DATA instruction (0x24)
     * ISO7816-4 Section 7.5.7
     * 
     * We have two options here: (a) in a production state we can
     * set the PUC with this, (b) in the distribution state and operational
     * state we change the PIN
     */
	private void processChangeReferenceData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = unsigned(buf[OFFSET_LC]);
        byte p1 = buf[OFFSET_P1];
        byte p2 = buf[OFFSET_P2];
        if(state > STATE_INITIAL) {
            // We are changing the PIN, PUC has to be provided
        	// check that P1 is 0x00: verification data (puc) followed by new reference data (pin) 
        	if(p1 != 0x00 || p2 != (byte)0x00) {
        		ISOException.throwIt(SW_INCORRECT_P1P2);
        	}
        	short pinSize = (short)(lc - PUC_SIZE);
        	if(pinSize < MIN_PIN_SIZE || pinSize > MAX_PIN_SIZE) {
           	ISOException.throwIt(SW_WRONG_LENGTH);            
        	}
        	apdu.setIncomingAndReceive();
        	short offset = (short)(OFFSET_CDATA+PUC_SIZE);
        	for(short i=0;i<pinSize;i++) {
        		byte b = buf[(short)(offset+i)];
        		if(b < (byte)0x30 || b > (byte)0x39) {
        			ISOException.throwIt(SW_WRONG_DATA);
        		}            
        	}
        	// Pad the pin with 0x00 to overwrite any garbage, e.g. le
        	Util.arrayFillNonAtomic(buf, (short)(offset+pinSize), (short)(MAX_PIN_SIZE - pinSize), (byte)0x00);
        	if(!puc.check(buf, OFFSET_CDATA, PUC_SIZE)) {
        		ISOException.throwIt((short)(SW_PIN_INCORRECT_TRIES_LEFT | puc.getTriesRemaining()));
        	}
        	pin.update(buf, offset, MAX_PIN_SIZE);
        	pin.resetAndUnblock();
        	if(state == STATE_PREPERSONALISED) {
        		state = STATE_PERSONALISED;
        	}
        } else {
            // State is production, we set the puc
            if(p1 != 0x01 || p2 != 0x00) {
                ISOException.throwIt(SW_INCORRECT_P1P2);
            }
            if(lc != PUC_SIZE) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            apdu.setIncomingAndReceive();
            puc.update(buf, OFFSET_CDATA, (byte)lc);        
            puc.resetAndUnblock();
        }
    }

	/**
	 * Process the GET CHALLENGE instruction (0x84) ISO 7816-4, Section 7.5.3
	 * 
	 */
	private void processGetChallenge(APDU apdu) {

		byte[] buf = apdu.getBuffer();

		if (buf[OFFSET_P1] != 0x00 || buf[OFFSET_P2] != 0x00) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		short le = apdu.setOutgoing();
		if (le == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setOutgoingLength(le);
		rd.generateData(buf, (short) 0, le);
		apdu.sendBytes((short) 0, le);
	}

	/**
	 * Process the MANAGE SECURITY ENVIRONMENT instruction (0x22). ISO7816-4,
	 * Section 7.5.11
	 * 
	 * This command can be also used to prepare key generation. In this case the
	 * algorithm indication is not required, in fact, should not be present.
	 * Note that the key identifiers should be already set up with put data
	 * before that.
	 */
	private void processManageSecurityEnvironment(APDU apdu) {

		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		// P1 should be:
		// (a) 0x40: computation, decipherment, internal authentication, ...
		// (b) 0x01: set
		if (p1 != (byte) 0x41) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		// P2 should be 0xB6 for DST, see ISO7816-4 Table 79
		if (p2 != (byte) 0xb6) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}

		apdu.setIncomingAndReceive();
		short lc = unsigned(buf[OFFSET_LC]);
		short offset = OFFSET_CDATA;        
			
		if (lc == 6) {
			lc += OFFSET_CDATA;
			// Tag for the private key:
	        short do84Offset = getTagOffset(buf, offset, lc, (byte)0x84);
	        if (buf[do84Offset+1]!=1) ISOException.throwIt(SW_WRONG_LENGTH);
	        selectedKeyId = buf[do84Offset+2];
	        
	        // Tag for the standardized Domain Parameter ID:
	        short do80Offset = getTagOffset(buf, offset, lc, (byte)0x80);
	        if (buf[do80Offset+1]!=1) ISOException.throwIt(SW_WRONG_LENGTH);
	        selectedDpId = buf[do80Offset+2];
		} else if (lc==3) {
			// Tag for the private key:
			if (buf[offset]!=(byte)0x84) ISOException.throwIt(SW_WRONG_DATA);
	        if (buf[offset+1]!=1) ISOException.throwIt(SW_WRONG_LENGTH);
	        selectedKeyId = buf[offset+2];			
		} else {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		
		if (selectedKeyId < 0 || selectedKeyId >= 3)
			ISOException.throwIt(SW_WRONG_DATA);
		if (selectedDpId < 10 || selectedKeyId > 14)
			ISOException.throwIt(SW_WRONG_DATA);
	}

	/**
	 * Process the PERFORM SECURITY OPERATION instruction (0x2A). ISO 7816-8
	 * Section 5.2
	 */
	private void processPerformSecurityOperation(APDU apdu) {

		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		if (p1 == (byte) 0x9E && p2 == (byte) 0x9A) {
			processComputeDigitalSignature(apdu);
		} else {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
	}

	/**
	 * Process the PSO COMPUTE DIGITAL SIGNATURE instruction (0x2A) ISO 7816-8
	 * Section 5.4
	 * 
	 */
	private void processComputeDigitalSignature(APDU apdu) {
		
        if(!pin.isValidated() && state == STATE_PERSONALISED) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        pin.reset();
        
		if (selectedKeyId == (byte) 0xFF)
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

		byte[] buffer = apdu.getBuffer();
		short lc = unsigned(buffer[OFFSET_LC]);
		if (lc == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		short readCount = apdu.setIncomingAndReceive();
		short responseLength = 0;

		try {
			sigECDSA.init(keyPair[selectedKeyId].getPrivate(), Signature.MODE_SIGN);
			short fittedLength = fitDataToKeyLength(buffer, OFFSET_CDATA, readCount, tmp);
			responseLength = sigECDSA.sign(tmp, (short)0, fittedLength, sigBuffer, (short) 0);
		} catch (CryptoException e) {
			sigBuffer[0] = (byte) 0xE7;
			sigBuffer[1] = (byte) e.getReason();
			responseLength = 2;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (SystemException se) {
			sigBuffer[0] = (byte) 0xEF;
			sigBuffer[1] = (byte) se.getReason();
			responseLength = 2;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (NullPointerException ne) {
			sigBuffer[0] = (byte) 0xEE;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (CardRuntimeException cre) {
			sigBuffer[0] = (byte) 0xED;
			sigBuffer[1] = (byte) cre.getReason();
			responseLength = 2;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (ArithmeticException ae) {
			sigBuffer[0] = (byte) 0xEC;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (ArrayIndexOutOfBoundsException aie) {
			sigBuffer[0] = (byte) 0xEB;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (ArrayStoreException ase) {
			sigBuffer[0] = (byte) 0xEA;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (ClassCastException cce) {
			sigBuffer[0] = (byte) 0xEA;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (RuntimeException re) {
			sigBuffer[0] = (byte) 0xE9;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (Exception ex) {
			sigBuffer[0] = (byte) 0xE8;
			responseLength = 1;
			ISOException.throwIt(SW_WRONG_DATA);
		} finally {
			apdu.setOutgoing();
			apdu.setOutgoingLength(responseLength);
			apdu.sendBytesLong(sigBuffer, (short) 0, responseLength);
		}
	}


	/**
	 * Generate an asymmetric ECDSA key pair according to ISO7816-8, Section
	 * 5.1. Return data in simple TLV data object: tag 86 with uncompressed public point.
	 * 
	 * Successful MSE command has to be performed prior to this one.
	 */
	private void processGenerateAsymetricKeyPair(APDU apdu) {
		
		if(state != STATE_INITIAL) {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];

		if (p1 != (byte) 0x80 || p2 != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1P2);
		if (selectedKeyId == (byte) 0xFF)
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		if (selectedDpId == (byte) 0xFF) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		switch(selectedDpId) {
			case 10: 
				keyPair[selectedKeyId] = SecP224r1DomainParameter.getKeyPairParameter();
				break;
			case 11: 
				keyPair[selectedKeyId] = BrainpoolP224r1DomainParameter.getKeyPairParameter();
				break;
			case 12: 
				keyPair[selectedKeyId] = SecP256r1DomainParameter.getKeyPairParameter();
				break;
			case 13: 
				keyPair[selectedKeyId] = BrainpoolP256r1DomainParameter.getKeyPairParameter();
				break;
			case 14: 
				keyPair[selectedKeyId] = BrainpoolP320r1DomainParameter.getKeyPairParameter();
				break;
			
		}

		keyPair[selectedKeyId].genKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey) keyPair[selectedKeyId].getPublic();

		apdu.setOutgoing();
		short len = (short) 0;
		short offset = 0;
		buf[offset++] = (byte) 0x86;
		len = ecPublicKey.getW(buf, (short) (offset + 1));
		buf[offset++] = (byte) len;
		offset += len;

		apdu.setOutgoingLength(offset);
		apdu.sendBytes((short) 0, offset);
	}

	private void processCreateFile(APDU apdu) {
		if (state != STATE_INITIAL) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		apdu.setIncomingAndReceive();
		if (lc != 5) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		short offset = OFFSET_CDATA;
		short id = Util.getShort(buf, offset);
		offset += 2;
		short len = Util.getShort(buf, offset);
		offset += 2;
		byte perm = buf[offset];
		if (!fileSystem.createFile(id, len, perm)) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
	}

	/**
	 * Process the WRITE BINARY Instruction (0xD0). ISO7816-4 Section 7.2.4
	 * 
	 */
	private void processWriteBinary(APDU apdu) throws ISOException {
		if (state != STATE_INITIAL) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		short offset = 0;
		short ef = -1;
		if ((byte) (p1 & MASK_SFI) == MASK_SFI) {
			byte sfi = (byte) (p1 | ~MASK_SFI);
			if (sfi >= 0x1F) {
				ISOException.throwIt(SW_INCORRECT_P1P2);
			}
			ef = fileSystem.findCurrentSFI(sfi);
			if (ef == -1) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			ef = fileSystem.fileStructure[ef];
			offset = unsigned(p2);
		} else {
			ef = fileSystem.getCurrentIndex();
			if (fileSystem.getFile(ef) == null) {
				ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
			}
			offset = Util.makeShort(p1, p2);
		}
		byte[] file = fileSystem.getFile(ef);
		short lc = unsigned(buf[OFFSET_LC]);
		if ((short) (offset + lc) > file.length) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, file, offset, lc);
	}

	/**
	 * Process the PUT DATA instruction (0xDA) P1 and P2 are custom
	 * 
	 */
	private void processPutData(APDU apdu) {
        byte p1 = apdu.getBuffer()[OFFSET_P1];
        if(p1 == (byte)0x67) {
            processSetHistoricalBytes(apdu);
        }else if(p1 == (byte)0x68) {
            processSetState(apdu);
        }else if(p1 == (byte)0x69) {
            processCreateFileSystemStructure(apdu);
        }else{
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
    }
	
	private void processSetHistoricalBytes(APDU apdu) {
		if (state != STATE_INITIAL) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		byte lc = buf[OFFSET_LC];
		if (lc <= 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		GPSystem.setATRHistBytes(buf, OFFSET_CDATA, lc);
	}
	
	private void processSetState(APDU apdu) throws ISOException {
		if (state == STATE_PERSONALISED) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte p2 = apdu.getBuffer()[OFFSET_P2];
		if (p2 != STATE_INITIAL && p2 != STATE_PREPERSONALISED) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		state = p2;
	}

	private void processCreateFileSystemStructure(APDU apdu) {
		if (state != STATE_INITIAL) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		apdu.setIncomingAndReceive();
		// Hack:
		// Search for a non-existing file,
		// if the structure is correct, then only the FileNotFoundException
		// would be
		// thrown.
		try {
			fileSystem.searchId(buf, OFFSET_CDATA, OFFSET_CDATA, (short) (OFFSET_CDATA + lc), (short) 0x0000);
			ISOException.throwIt(SW_WRONG_DATA);
		} catch (FileNotFoundException e) {
		} catch (ArrayIndexOutOfBoundsException aioobe) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		fileSystem.fileStructure = new byte[lc];
		Util.arrayCopy(buf, OFFSET_CDATA, fileSystem.fileStructure, (short) 0, lc);
	}

	private short unsigned(byte b) {
		return (short) (b & 0x00FF);
	}
	
    /** 
     * Search the DO in the buffer
     * Return the offset of the tag in the buffer
     */
    private short getTagOffset(byte[] buffer, short firstOffset, short lastOffset, byte tag) {
        if(firstOffset >= lastOffset || lastOffset > buffer.length) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        for (short i=firstOffset;i<lastOffset;i = (short)(i+2+buffer[i+1])) {
        	if (buffer[i]==tag) return i;
        }
        ISOException.throwIt(SW_WRONG_DATA);            
        return -1;
    }    
	
	/** Fit the data in the buffer to the length of the selected key size.
	 * If data length is shorter then key length, data will be filled up with zeros in front of data
	 * If data length is bigger then key length, the input data will will be truncated to the key lengths leftmost bytes
	 * @param in Contains the data
	 * @param inOffset offset in the buffer where the data begins
	 * @param inLen length of the data in the buffer
	 * @return number of bytes of signature output in dataBuff
	 */
	private short fitDataToKeyLength(byte[] in, byte inOffset, short inLen, byte[] dataBuff) {
		short keySize = (short) (keyPair[selectedKeyId].getPublic().getSize()/8);
		Util.arrayFillNonAtomic(dataBuff, (short)0, (short) dataBuff.length, (byte)0);
		if (inLen<keySize) {
			Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short) (keySize-inLen), inLen);
		} else if (inLen>=keySize) {
			Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short)0, keySize);
		}
		return keySize;
	}
}