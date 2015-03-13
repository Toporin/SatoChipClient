/*
 * java API for the SatoChip Bitcoin Hardware Wallet
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
 * 
 * Copyright 2015 by Toporin (https://github.com/Toporin)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.satochip.satochipclient;

import java.security.KeyPair;

public class JCconstants {
    
    	// Maximum number of keys handled by the Cardlet
	public final static byte MAX_NUM_KEYS = (byte) 16;
	// Maximum number of PIN codes
	public final static byte MAX_NUM_PINS = (byte) 8;
	// Maximum number of keys allowed for ExtAuth
	public final static byte MAX_NUM_AUTH_KEYS = (byte) 6;

	// Maximum size for the extended APDU buffer for a 2048 bit key:
	// CLA [1 byte] + INS [1 byte] + P1 [1 byte] + P2 [1 byte] +
	// LC [3 bytes] + cipher_mode[1 byte] + cipher_direction [1 byte] +
	// data_location [1 byte] + data_size [2 bytes] + data [256 bytes]
	// = 268 bytes
	public final static short EXT_APDU_BUFFER_SIZE = (short) 268;

	// Minimum PIN size
	public final static byte PIN_MIN_SIZE = (byte) 4;
	// Maximum PIN size
	public final static byte PIN_MAX_SIZE = (byte) 16;
	// PIN[0] initial value...
	public static byte[] PIN_INIT_VALUE;
	
	// Maximum external authentication tries per key
	public final static byte MAX_KEY_TRIES = (byte) 5;

	// Import/Export Object ID
	public final static short IN_OBJECT_CLA = (short) 0xFFFF;
	public final static short IN_OBJECT_ID = (short) 0xFFFE;
	public final static short OUT_OBJECT_CLA = (short) 0xFFFF;
	public final static short OUT_OBJECT_ID = (short) 0xFFFF;

	public final static byte KEY_ACL_SIZE = (byte) 6;
	public final static byte ACL_READ = (byte) 0;
	public final static byte ACL_WRITE = (byte) 2;
	public final static byte ACL_USE = (byte) 4;
	
	// code of CLA byte in the command APDU header
	public final static byte CardEdge_CLA = (byte) 0xB0;

	/****************************************
	 * Instruction codes *
	 ****************************************/

	// Applet initialization
	public final static byte INS_SETUP = (byte) 0x2A;

	// Keys' use and management
	public final static byte INS_GEN_KEYPAIR = (byte) 0x30;
        public final static byte INS_GEN_KEYSYM = (byte) 0x31;
        public final static byte INS_IMPORT_KEY = (byte) 0x32;
	public final static byte INS_EXPORT_KEY = (byte) 0x34;
        public final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;
	public final static byte INS_COMPUTE_CRYPT = (byte) 0x36;
	public final static byte INS_COMPUTE_SIGN = (byte) 0x37; // added
	
	// External authentication
	public final static byte INS_CREATE_PIN = (byte) 0x40;
	public final static byte INS_VERIFY_PIN = (byte) 0x42;
	public final static byte INS_CHANGE_PIN = (byte) 0x44;
	public final static byte INS_UNBLOCK_PIN = (byte) 0x46;
	public final static byte INS_LOGOUT_ALL = (byte) 0x60;
	public final static byte INS_GET_CHALLENGE = (byte) 0x62;
	public final static byte INS_EXT_AUTH = (byte) 0x38;

	// Objects' use and management
	public final static byte INS_CREATE_OBJ = (byte) 0x5A;
	public final static byte INS_DELETE_OBJ = (byte) 0x52;
	public final static byte INS_READ_OBJ = (byte) 0x56;
	public final static byte INS_WRITE_OBJ = (byte) 0x54;
        public final static byte INS_SIZE_OBJ = (byte) 0x57;

	// Status information
	public final static byte INS_LIST_OBJECTS = (byte) 0x58;
	public final static byte INS_LIST_PINS = (byte) 0x48;
	public final static byte INS_LIST_KEYS = (byte) 0x3A;
	public final static byte INS_GET_STATUS = (byte) 0x3C;
	
	// HD wallet
	public final static byte INS_COMPUTE_SHA512 = (byte) 0x6A;
	public final static byte INS_COMPUTE_HMACSHA512= (byte) 0x6B;
	public final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
        public final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
	public final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
	public final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
        public final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
	public final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
	public final static byte INS_BIP32_SET_EXTENDED_KEY= (byte) 0x70;
	public final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
        
        /** No error! */
	public final static short SW_OK = (short)0x9000;
	/** There have been memory problems on the card */
	public final static short SW_NO_MEMORY_LEFT = (short)0x9c01;
	/** Entered PIN is not correct */
	public final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Required operation is not allowed in actual circumstances */
	public final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
        /** Required setup is not not done */
	public final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
	/** Required feature is not (yet) supported */
	public final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
	/** Required operation was not authorized because of a lack of privileges */
	public final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Required object is missing */
	public final static short SW_OBJECT_NOT_FOUND = (short) 0x9C07;
	/** New object ID already in use */
	public final static short SW_OBJECT_EXISTS = (short) 0x9C08;
	/** Algorithm specified is not correct */
	public final static short SW_INCORRECT_ALG = (short) 0x9C09;

	/** Incorrect P1 parameter */
	public final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Incorrect P2 parameter */
	public final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** No more data available */
	public final static short SW_SEQUENCE_END = (short) 0x9C12;
	/** Invalid input parameter to command */
	public final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

	/** Verify operation detected an invalid signature */
	public final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
	/** Operation has been blocked for security reason */
	public final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** Unspecified error */
	public final static short SW_UNSPECIFIED_ERROR = (short) 0x9C0D;
	/** For debugging purposes */
	public final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
	/** For debugging purposes 2*/
	public final static short SW_DEBUG_FLAG = (short) 0x9FFF;
	/** Very low probability error */
	public final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
	/** Support only hardened key currently */
	public final static short SW_BIP32_HARDENED_KEY_ERROR = (short) 0x9C16;
	/** Incorrect initialization of method */
	public final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
	/** Bip32 seed is not initialized*/
	public final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
        /** Incorrect transaction hash */
	public final static short SW_INCORRECT_TXHASH = (short) 0x9C15;

	
	// Algorithm Type in APDUs
	public final static byte ALG_RSA = 0x01; //KeyPair.ALG_RSA;
	public final static byte ALG_RSA_CRT = 0x02; //KeyPair.ALG_RSA_CRT;
	public final static byte ALG_EC_FP = 0x05; //KeyPair.ALG_EC_FP;

	// Key Type in Key Blobs
	public final static byte TYPE_RSA_PUBLIC = 4; //KeyBuilder.TYPE_RSA_PUBLIC; 
	public final static byte TYPE_RSA_PRIVATE = 5; //KeyBuilder.TYPE_RSA_PRIVATE; 
	public final static byte TYPE_RSA_CRT_PRIVATE = 6; //KeyBuilder.TYPE_RSA_CRT_PRIVATE; 
	public final static byte TYPE_EC_FP_PUBLIC = 11; //KeyBuilder.TYPE_EC_FP_PUBLIC;
	public final static byte TYPE_EC_FP_PRIVATE = 12; //KeyBuilder.TYPE_EC_FP_PRIVATE;
        public final static byte TYPE_DES = 3; //KeyBuilder.TYPE_DES; 
	public final static byte TYPE_AES=15; //KeyBuilder.TYPE_AES;
        
	// KeyBlob Encoding in Key Blobs
	public final static byte BLOB_ENC_PLAIN = (byte) 0x00;

	// Cipher Operations admitted in ComputeCrypt()
	public final static byte OP_INIT = (byte) 0x01;
	public final static byte OP_PROCESS = (byte) 0x02;
	public final static byte OP_FINALIZE = (byte) 0x03;

	// Cipher Directions admitted in ComputeCrypt()
	public final static byte MODE_SIGN = 0x01; //Signature.MODE_SIGN;
	public final static byte MODE_VERIFY = 0x02; //Signature.MODE_VERIFY;
	public final static byte MODE_ENCRYPT = 0x02; //Cipher.MODE_ENCRYPT; 
	public final static byte MODE_DECRYPT = 0x01; //Cipher.MODE_DECRYPT; 

	// Cipher Modes admitted in ComputeCrypt()
	public final static byte ALG_RSA_NOPAD = 12; //Cipher.ALG_RSA_NOPAD; //(byte) 0x00;
	public final static byte ALG_RSA_PKCS1 = 10; //Cipher.ALG_RSA_PKCS1; //(byte) 0x01;
	public final static byte ALG_DES_CBC_NOPAD = 1; //Cipher.ALG_DES_CBC_NOPAD; //(byte) 0x20;
	public final static byte ALG_DES_ECB_NOPAD = 5; //Cipher.ALG_DES_ECB_NOPAD; //(byte) 0x21;
        public final static byte ALG_AES_BLOCK_128_CBC_NOPAD = 13; //Cipher.ALG_AES_BLOCK_128_CBC_NOPAD; 
        public final static byte ALG_AES_BLOCK_128_ECB_NOPAD = 14; //Cipher.ALG_AES_BLOCK_128_ECB_NOPAD; 
        public final static byte ALG_ECDSA_SHA = 17; //Signature.ALG_ECDSA_SHA;//(byte) 0x30;
	public final static byte ALG_ECDSA_SHA_256 = 33; //Bitcoin (Signature.ALG_ECDSA_SHA256==33) https://javacard.kenai.com/javadocs/classic/javacard/security/Signature.html#ALG_ECDSA_SHA_256 
	
        public final static byte DL_APDU = (byte) 0x01;
	public final static byte DL_OBJECT = (byte) 0x02;
	public final static byte LIST_OPT_RESET = (byte) 0x00;
	public final static byte LIST_OPT_NEXT = (byte) 0x01;

	public final static byte OPT_DEFAULT = (byte) 0x00; // Use JC defaults
	public final static byte OPT_RSA_PUB_EXP = (byte) 0x01; // RSA: provide public exponent
	public final static byte OPT_EC_SECP256k1 = (byte) 0x03; // EC: provide P, a, b, G, R, K public key parameters 
        
	// Offsets in buffer[] for key generation
	public final static short OFFSET_GENKEY_ALG = (short) 0;
	public final static short OFFSET_GENKEY_SIZE = (short) (OFFSET_GENKEY_ALG + 1);
	public final static short OFFSET_GENKEY_PRV_ACL = (short) (OFFSET_GENKEY_SIZE + 2);
	public final static short OFFSET_GENKEY_PUB_ACL = (short) (OFFSET_GENKEY_PRV_ACL + KEY_ACL_SIZE);
	public final static short OFFSET_GENKEY_OPTIONS = (short) (OFFSET_GENKEY_PUB_ACL + KEY_ACL_SIZE);
	public final static short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH = (short) (OFFSET_GENKEY_OPTIONS + 1);
	public final static short OFFSET_GENKEY_RSA_PUB_EXP_VALUE = (short) (OFFSET_GENKEY_RSA_PUB_EXP_LENGTH + 2);
	
	// JC API 2.2.2 does not define this constant:
	public final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
	public final static short LENGTH_EC_FP_256= (short) 256;
	
	//PINCOIN: default parameters for EC curve secp256k1
	public final static byte[] SECP256K1_P ={ 
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, 
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F}; 
	public final static byte[] SECP256K1_a = {
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};
	public final static byte[] SECP256K1_b = {
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07};
	public final static byte[] SECP256K1_G = {(byte)0x04, //base point, uncompressed form 
                    (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
                    (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
                    (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
                    (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
                    (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
                    (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
                    (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
                    (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8};
	public final static byte[] SECP256K1_R = {
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, // order of G
                    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
                    (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
                    (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41};
	public final static short SECP256K1_K = 0x01; // cofactor 	
}
