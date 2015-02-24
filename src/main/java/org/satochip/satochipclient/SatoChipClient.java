/*
 * java API for the SatoChip Bitcoin Hardware Wallet
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
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

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.ECKey.ECDSASignature;//import java.io.OutputStream;
import static com.google.bitcoin.core.Message.UNKNOWN_LENGTH;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.Transaction;
import static com.google.bitcoin.core.Transaction.SIGHASH_ANYONECANPAY_VALUE;
import com.google.bitcoin.core.Transaction.SigHash;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.UnsafeByteArrayOutputStream;
import com.google.bitcoin.core.Utils;
import static com.google.bitcoin.core.Utils.BITCOIN_SIGNED_MESSAGE_HEADER_BYTES;
//import static com.google.bitcoin.core.Utils.NEGATIVE_ONE;
//import static com.google.bitcoin.core.Utils.singleDigest;
import static com.google.bitcoin.core.Utils.uint32ToByteStreamLE;
import com.google.bitcoin.core.VarInt;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.script.Script;
//import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.script.ScriptOpCodes;
//import com.google.bitcoin.utils.BriefLogFormatter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
//import static java.lang.System.exit;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.CardException;
import javax.xml.bind.DatatypeConverter;
import org.spongycastle.asn1.ASN1InputStream; // used to convert hexstring to byte[]
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.crypto.digests.SHA256Digest;
//import org.spongycastle.crypto.digests.SHA512Digest;
//import org.spongycastle.crypto.macs.HMac;
//import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Base64;

public class SatoChipClient {

	/* constants declaration */
        
    // authentikey
    public static byte[] authentikey;
    public static DeterministicKey masterkey;
	
	
    /**
    * Utility function that converts a byte array into an hexadecimal string.
    * @param bytes
    */
    public static String toString(byte[] bytes) {

            final String hexChars = "0123456789ABCDEF";
            StringBuffer sbTmp = new StringBuffer();
            char[] cTmp = new char[2];

            //System.out.println(bytes);//debug
            for (int i = 0; i < bytes.length; i++) {
                    cTmp[0] = hexChars.charAt((bytes[i] & 0xF0) >>> 4);
                    cTmp[1] = hexChars.charAt(bytes[i] & 0x0F);
                    sbTmp.append(cTmp);
            }
            //System.out.println(sbTmp.toString());//debug

            return sbTmp.toString();
    }

    /* convert a DER encoded signature to compact 65-byte format
        input is hex string in DER format
        output is hex string in compact 65-byteformat
        http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
        https://bitcointalk.org/index.php?topic=215205.0            
    */
    public static byte[] toCompactSig(byte[] sigin, int recid, boolean compressed) {

        byte[] sigout= new byte[65];
        // parse input 
        byte first= sigin[0];
        if (first!= 0x30){
            System.out.println("Wrong first byte!");
            return new byte[0];
        }
        byte lt= sigin[1];
        byte check= sigin[2];
        if (check!= 0x02){
            System.out.println("Check byte should be 0x02");
            return new byte[0];
        }
        // extract r
        byte lr= sigin[3];
        for (int i= 0; i<=31; i++){
            byte tmp= sigin[4+lr-1-i];
            if (lr>=(i+1)) {
                sigout[32-i]= tmp;
            } else{ 
                sigout[32-i]=0;  
            }
        }
        // extract s
        check= sigin[4+lr];
        if (check!= 0x02){
            System.out.println("Second check byte should be 0x02");
            return new byte[0];
        }
        byte ls= sigin[5+lr];
        if (lt != (lr+ls+4)){
            System.out.println("Wrong lt value");
            return new byte[0];
        }
        for (int i= 0; i<=31; i++){
            byte tmp= sigin[5+lr+ls-i];
            if (ls>=(i+1)) {
                sigout[64-i]= tmp;
            } else{ 
                sigout[32-i]=0;  
            }
        }

        // 1 byte header
        if (recid>3 || recid<0){
            System.out.println("Wrong recid value");
            return new byte[0];
        }
        if (compressed){
            sigout[0]= (byte)(27 + recid + 4 );
        }else{
            sigout[0]= (byte)(27 + recid);                
        }

//            // change endianness (debug)
//            byte[] tmpr= new byte[32];
//            byte[] tmps= new byte[32];
//            for (int i= 0; i<=31; i++){
//                tmpr[i]= sigout[1+i];
//                tmps[i]= sigout[33+i];
//            }
//            for (int i= 0; i<=31; i++){
//                sigout[1+i]=tmpr[31-i];
//                sigout[33+i]=tmps[31-i];
//            }

        return sigout;
    }

    /* convert a DER encoded signature to Bitcoinj ECDSASignature format
        input is byte[] in DER format
        output is ECDSASignature
    */
    public static ECDSASignature toECDSASignature(byte[] sigin) {

        // unfortunately, the following returns exception:
        // java.lang.ClassCastException: org.spongycastle.asn1.ASN1Integer cannot be cast to org.spongycastle.asn1.DERInteger
        // at com.google.bitcoin.core.ECKey$ECDSASignature.decodeFromDER(ECKey.java:386)
        //return ECKey.ECDSASignature.decodeFromDER(sigin);

        try {
            ASN1InputStream decoder = new ASN1InputStream(sigin);
            DLSequence seq = (DLSequence) decoder.readObject();
            ASN1Integer r, s;
            try {
                r = (ASN1Integer) seq.getObjectAt(0);
                s = (ASN1Integer) seq.getObjectAt(1);
            } catch (ClassCastException e) {
                throw new IllegalArgumentException(e);
            }
            decoder.close();
            // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
            // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
            return new ECDSASignature(r.getPositiveValue(), s.getPositiveValue());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // sign message formating
    public static byte[] hashMagicMessage(byte[] message){

        byte[] tohash;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES.length);
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES);
            VarInt size = new VarInt(message.length);
            bos.write(size.encode());
            bos.write(message);
            tohash= bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }

        System.out.println("Message to hash: " + toString(tohash));

        Sha256Hash hash = Sha256Hash.create(tohash);
        return hash.getBytes();   
    }

    public static void TestGenerateKeyPair(CardConnector cc, byte alg_type, byte priv_key_nbr, byte pub_key_nbr, short key_size) throws CardConnectorException{

        byte[] priv_key_ACL= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] pub_key_ACL= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte gen_opt= JCconstants.OPT_DEFAULT;
        byte[] gen_opt_param={};
        String stralg="";
        if (alg_type==JCconstants.ALG_RSA)
            stralg="RSA";
        else if (alg_type==JCconstants.ALG_EC_FP)
            stralg="ECC";
        else{
            System.out.println("ERROR: algorithm not supported!");
            return;
        } 

        System.out.println("Test GenerateKey(alg="+stralg + ", priv="+ (int)priv_key_nbr+", pub="+ (int)pub_key_nbr+", keysize="+ key_size+")"); 
        cc.cardGenerateKeyPair( 
                        priv_key_nbr, pub_key_nbr, alg_type, key_size, 
                        priv_key_ACL, pub_key_ACL, gen_opt, gen_opt_param);

        // list key
        cc.cardGetStatus();
        System.out.println("*****ListKey*****");
        cc.cardListKeys();
        System.out.println("*****************\n\n");
    }

    public static void TestImportKey(CardConnector cc, byte key_type, byte key_nbr, short key_size, byte[] key_data) throws CardConnectorException{

            byte key_encoding= 0x00; //plain
            byte[] key_ACL= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            String stralg="";
            if (key_type==JCconstants.TYPE_EC_FP_PRIVATE)
                stralg="ECpriv";
            else if (key_type==JCconstants.TYPE_EC_FP_PUBLIC)
                stralg="ECpub";
            else if (key_type==JCconstants.TYPE_RSA_PUBLIC)
                stralg="RSApub";
            else if (key_type==JCconstants.TYPE_RSA_PRIVATE)
                stralg="RSApriv";
            else{
                System.out.println("ERROR: key type not supported!");
                return;
            }

            System.out.println("Test ImportKey(key="+stralg+", nb="+ (int)key_nbr+", keysize="+ key_size+")"); // jcop-ko);
            cc.cardImportKey(key_nbr, key_ACL, key_encoding, key_type, key_size, key_data); 

            // list key
            cc.cardGetStatus();
            System.out.println("*****ListKey*****");
            cc.cardListKeys();
            System.out.println("*****************\n\n");

    }

    public static void TestComputeSign(CardConnector cc, byte CM, byte key_sign, byte key_verif) throws CardConnectorException{

//              byte[] buffer= {'H','e','l','l','o',' ','w','o','r','l','d'};
//		byte[] buffer= {'H','e','l','l','o',' ','w','o','r','l','x'};
//		byte[] buffer= {'H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d','H','e','l','l','o',' ','w','o','r','l','d'};
            byte[] buffer= {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
//		byte[] buffer= {'t','e','s','t'};
            byte[] buffer_wrong= {'a','b','c','d','e'};


            String stralg="";
            if (CM==JCconstants.ALG_RSA_PKCS1)
                stralg="RSApkcs1";
            else if (CM==JCconstants.ALG_RSA_NOPAD)
                stralg="RSAnopad";
            else if (CM==JCconstants.ALG_ECDSA_SHA)
                stralg="ECDSAsha";
            else if (CM==JCconstants.ALG_ECDSA_SHA_256)
                stralg="ECDSAsha256";
            else{
                System.out.println("ERROR: mode not supported!");
                return;
            }

            // computesign
            System.out.println("Test ComputeSign(CM="+stralg+", keynb="+key_sign+")");
            byte[] signature= cc.cardComputeSign(key_sign, CM, JCconstants.MODE_SIGN, buffer, null); //  16 first bits for size
            System.out.println("Data length:" + buffer.length);
            System.out.println("signature after:" + toString(signature));

            // computeverify
            System.out.println("Test ComputeVerify(CM="+stralg+", keynb="+key_verif+")");
            byte[] response= cc.cardComputeSign(key_verif, CM, JCconstants.MODE_VERIFY, buffer, signature);

            System.out.println("Verify signature with wrong data:");
            response= cc.cardComputeSign(key_verif, CM, JCconstants.MODE_VERIFY, buffer_wrong, signature);
            System.out.println("\n\n\n");

    }

    public static void TestSHA512(CardConnector cc) throws CardConnectorException{

        System.out.println("Test SHA512");
        System.out.println("*********** Hashing Test ******************");
        byte[] msg1= new byte[0];
        String hash1= "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        byte[] response= cc.cardComputeSha512(msg1);
        System.out.println("hash expected:"+ hash1);
        System.out.println("hash computed:"+ toString(response));
        //
        byte[] msg2= {'a','b','c'};
        String hash2= "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        response= cc.cardComputeSha512(msg2);
        System.out.println("hash expected:"+ hash2);
        System.out.println("hash computed:"+ toString(response));

        String key1="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        String data1="4869205468657265"; 
        hash1= "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
        byte[] bkey1= DatatypeConverter.parseHexBinary(key1); 
        byte[] bdata1= DatatypeConverter.parseHexBinary(data1);
        response= cc.cardComputeHmacSha512(bkey1, bdata1);
        System.out.println("hash expected:"+ hash1);
        System.out.println("hash computed:"+ toString(response));

        String key2="4a656665";
        String data2="7768617420646f2079612077616e7420666f72206e6f7468696e673f"; 
        hash2="164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        byte[] bkey2= DatatypeConverter.parseHexBinary(key2); 
        byte[] bdata2= DatatypeConverter.parseHexBinary(data2);
        response= cc.cardComputeHmacSha512(bkey2, bdata2);
        System.out.println("hash expected:"+ hash2);
        System.out.println("hash computed:"+ toString(response));
        System.out.println("*******************************************");
        System.out.println("\n\n\n");

    }

    public static byte[] TestBip32ImportSeed(CardConnector cc, String strseed) throws CardConnectorException{

        // import seed to HWchip
        long startTime = System.currentTimeMillis();
        byte[] seed= DatatypeConverter.parseHexBinary(strseed); 
        byte[] seed_ACL= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] response= cc.cardBip32ImportSeed(seed_ACL, seed);
        //String masterkey, chaincode;
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Test Bip32ImportSeed");
        System.out.println("elapsed time: "+elapsedTime);

        // recover pubkey+sig
        // this is a key derived from the seed and can be used to authenticate data from wallet
        int coordx_size = ((int)(response[0] & 0xff)<<8) + ((int)(response[1] & 0xff));
        byte[] msg= new byte[2+coordx_size]; 
        System.arraycopy(response, 0, msg, 0, coordx_size+2);
        byte[] coordx= new byte[coordx_size]; 
        System.arraycopy(response, 2, coordx, 0, coordx_size);
        int sig_size = ((int)(response[coordx_size+2] & 0xff)<<8) + ((int)(response[coordx_size+3] & 0xff));  
        byte[] signature= new byte[sig_size]; 
        int nb_deleted = ((int)(response[2+coordx_size+2+sig_size] & 0xff)<<8) + ((int)(response[2+coordx_size+2+sig_size+1] & 0xff));  
        System.arraycopy(response, coordx_size+4, signature, 0, sig_size);
        ECKey.ECDSASignature ecdsasig= toECDSASignature(signature);
        Sha256Hash msghash= Sha256Hash.create(msg); // compute sha256 of message
//            System.out.println("Public key coordx size:"+ coordx_size);
//            System.out.println("Public key coordx computed:"+ toString(coordx));
//            System.out.println("Public key signature size:"+ sig_size);
//            System.out.println("Public key signature computed:"+ toString(signature));
        System.out.println("Number of Bip32 objects deleted:"+ nb_deleted);
//            System.out.println("****** compact signature ******");  
        int recid=-1;
        ECKey pkey=null;
        for (int i=0; i<4; i++){
            pkey= ECKey.recoverFromSignature(i, ecdsasig, msghash, true);
            if (pkey!=null){
                byte[] coordxkey= new byte[coordx_size];
                System.arraycopy(pkey.getPubKey(), 1, coordxkey, 0, coordx_size);
                if (Arrays.equals(coordx,coordxkey)){
                    recid=i;
                    authentikey= pkey.getPubKey();
                    System.out.println("#recid: "+i+" AuthentiKey:" + toString(authentikey));
                    break;
                }
            }      
        }

        return pkey.getPubKey();
    }

    public static DeterministicKey TestBip32ImportSeed(String strseed){

        // create SW masterkey with bitcoinj
        byte[] seed= DatatypeConverter.parseHexBinary(strseed); 
        masterkey= HDKeyDerivation.createMasterPrivateKey(seed);

        return masterkey;
    }

    public static byte[] TestBip32GetExtendedKey(CardConnector cc, byte[] bip32path, byte debug) throws CardConnectorException{

        long startTime = System.currentTimeMillis();
        byte[] response= cc.cardBip32GetExtendedKey(bip32path);
        //byte debug=0x01;
        //byte[] response = cc.exchangeAPDU(JCconstants.CardEdge_CLA, JCconstants.INS_BIP32_GET_EXTENDED_KEY, (byte)(bip32path.length/4), debug, bip32path, (byte)0x00);

        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("elapsed time: "+elapsedTime);
        System.out.println("Extended key for "+toString(bip32path));

        int coordx_size = ((int)(response[0] & 0xff)<<8) + ((int)(response[1] & 0xff));
        byte[] msg= new byte[2+coordx_size]; 
        System.arraycopy(response, 0, msg, 0, coordx_size+2);
        byte[] coordx= new byte[coordx_size]; 
        System.arraycopy(response, 2, coordx, 0, coordx_size);
        int sig_size = ((int)(response[2+coordx_size] & 0xff)<<8) + ((int)(response[2+coordx_size+1] & 0xff));  
        byte[] signature= new byte[sig_size]; 
        System.arraycopy(response, coordx_size+4, signature, 0, sig_size);
        ECKey.ECDSASignature ecdsasig= toECDSASignature(signature);
        Sha256Hash msghash= Sha256Hash.create(msg); // compute sha256 of message
        int recid=-1;
        ECKey pkey=null;
        for (int i=0; i<4; i++){
            pkey= ECKey.recoverFromSignature(i, ecdsasig, msghash, true);
            if (pkey!=null){
                byte[] coordxkey= new byte[coordx_size];
                System.arraycopy(pkey.getPubKey(), 1, coordxkey, 0, coordx_size);
                if (Arrays.equals(coordx,coordxkey)){
                    recid=i;
                    System.out.println("#recid: "+i+" PubKey:" + toString(pkey.getPubKey()));
                    break;
                }
            }
        }
        if (recid == -1)
            throw new CardConnectorException("Unable to recover public key from signature");        

        // authentikey signature
        if (authentikey==null)
            authentikey= TestBip32GetAuthentiKey(cc);

        byte[] coordx2= new byte[2+coordx_size+2+sig_size];
        System.arraycopy(response, 0, coordx2, 0, 2+coordx_size+2+sig_size);
        int sig_size2 = ((int)(response[2+coordx_size+2+sig_size] & 0xff)<<8) + ((int)(response[2+coordx_size+2+sig_size+1] & 0xff));  
        byte[] signature2= new byte[sig_size2]; 
        System.arraycopy(response, 2+coordx_size+2+sig_size+2, signature2, 0, sig_size2);
        ecdsasig= toECDSASignature(signature2);
        msghash= Sha256Hash.create(coordx2);// compute sha256 of message
        recid=-1;
        ECKey akey=null;
        for (int i=0; i<4; i++){
            akey= ECKey.recoverFromSignature(i, ecdsasig, msghash, true);
            if (akey!=null && Arrays.equals(akey.getPubKey(), authentikey)){
                recid=i;
                System.out.println("#recid: " + recid+ " Authentikey:" + toString(akey.getPubKey()));  
                break;
            }
        }
        if (recid == -1)
            throw new CardConnectorException("Unable to recover authentikey from signature");        

        return pkey.getPubKey();

    }

    public static byte[] TestBip32GetExtendedKey(byte[] bip32path){

        // create SW extendedkey with bitcoinj
        int bip32depth= bip32path.length/4;
        DeterministicKey parent= masterkey; // imported from seed
        DeterministicKey child= null;
        for (int i=0; i<bip32path.length; i+=4){
            int childNumber= ((bip32path[i]&0xff)<<24) ^ ((bip32path[i+1]&0xff)<<16) 
                    ^ ((bip32path[i+2]&0xff)<<8) ^ (bip32path[i+3]&0xff);
            child= HDKeyDerivation.deriveChildKey(parent,childNumber);
            parent= child;
            //System.out.println("Depth:"+(i/4+1)+" pubKey:" + parent.toString()); 

        }
        System.out.println("Extended pubKey:" + parent.toString());
        return parent.getPubKeyBytes();

    }
        
    public static byte[] TestBip32GetAuthentiKey(CardConnector cc) throws CardConnectorException{
        
        byte[] response= cc.cardBip32GetAuthentiKey();
        
        // extract msg & sig from response
        int coordx_size = ((int)(response[0] & 0xff)<<8) + ((int)(response[1] & 0xff));
        byte[] msg= new byte[2+coordx_size]; 
        System.arraycopy(response, 0, msg, 0, coordx_size+2);
        byte[] coordx= new byte[coordx_size]; 
        System.arraycopy(response, 2, coordx, 0, coordx_size);
        int sigsize = ((int)(response[2+coordx_size] & 0xff)<<8) + ((int)(response[2+coordx_size+1] & 0xff));  
        byte[] signature= new byte[sigsize]; 
        System.arraycopy(response, coordx_size+4, signature, 0, sigsize);
        ECKey.ECDSASignature ecdsasig= toECDSASignature(signature);
        Sha256Hash msghash= Sha256Hash.create(msg); // compute sha256 of message
        
        //recover pubkey
        int recID =-1;
        ECKey akey=null;
        for (int i=0; i<4; i++){
            akey= ECKey.recoverFromSignature(i, ecdsasig, msghash, true);
            if (akey!=null){
                byte[] coordxkey= new byte[coordx_size];
                System.arraycopy(akey.getPubKey(), 1, coordxkey, 0, coordx_size);
                if (Arrays.equals(coordx,coordxkey)){
                    recID=i;
                    authentikey= akey.getPubKey(); // better to set it after?
                    break;
                }
            }
        }
        if (recID == -1)
            throw new CardConnectorException("Unable to recover authentikey from signature");        
        
        return authentikey;
    }    
    
    public static boolean TestBip32MessageSigning(CardConnector cc, String strmsg, byte keynbr) throws CardConnectorException{

        System.out.println("Test Bip32MessageSigning");
        
        // select default extended key
        byte[] pubkey;
        if (keynbr==(byte)0xff){
            byte[] bip32path= new byte[4];
            bip32path[0]=(byte)0x80;
            bip32path[1]=0x00;
            bip32path[2]=0x00;
            bip32path[3]=0x00;
            pubkey=TestBip32GetExtendedKey(bip32path);
        }
        else{
            pubkey=cc.cardGetPublicKeyFromPrivate(keynbr);
        }
        
        // sign message
        byte[] msg= strmsg.getBytes(); 
        byte[] signature;
        if (msg.length<144)
            signature= cc.cardSignShortMessage(keynbr,msg);
        else 
            signature= cc.cardSignMessage(keynbr,msg);
        
        // verify with bitcoinj
        byte[] signature64;
        String strsignature64="";
        for (int recid=0; recid<4; recid++){
            byte[] compactsig= toCompactSig(signature, recid, true);
            signature64= Base64.encode(compactsig);
            ECKey pkey;
            try {
                strsignature64= new String(signature64, "UTF-8");
                pkey= ECKey.signedMessageToKey(strmsg, strsignature64);
                if (Arrays.equals(pubkey, pkey.getPubKey())){
                    System.out.println("recid: " + recid);  
                    System.out.println("compact signature (hex):" + toString(compactsig));  
                    System.out.println("compact signature (b64):" + strsignature64);
                    System.out.println("Public key:" + pkey.toString());
                    return true;
                }
            }
            catch (UnsupportedEncodingException ex) {
                System.out.println("Error with encoding:"+ex);
                //Logger.getLogger(MuscleCardClient.class.getName()).log(Level.SEVERE, null, ex);
            }
            catch(SignatureException e){
                System.out.println("Error verifying signature " + e); 
            }
        }
        return false;
                
    }
    
    public static void TestParseTransaction(CardConnector cc, byte keynbr) throws CardConnectorException{
    
        byte[] pubkey;
        if (keynbr==(byte)0xff){
            byte[] bip32path= new byte[4];
            bip32path[0]=(byte)0x80;
            bip32path[1]=0x00;
            bip32path[2]=0x00;
            bip32path[3]=0x00;
            pubkey=TestBip32GetExtendedKey(bip32path);
        }
        else{
            pubkey=cc.cardGetPublicKeyFromPrivate(keynbr);
        }
        
        // bitcoinj
        NetworkParameters params;
        params = RegTestParams.get();
        Transaction tx= new Transaction(params);
        ECKey serverKey= new ECKey(null, pubkey, true);
        BigInteger nanoCoins = Utils.toNanoCoins(1, 0);
        TransactionOutput outputToMe = new TransactionOutput(params, tx, nanoCoins, serverKey);
        
        // simple tx
        tx.addOutput(outputToMe);
        tx.addInput(new TransactionInput(params, tx, outputToMe.getScriptBytes()));
        
        int inputIndex=0;
        byte[] connectedScript= outputToMe.getScriptBytes();
        byte sigHashType= (byte) TransactionSignature.calcSigHashValue(SigHash.ALL, false);
        byte[] rawtxforhashing= byteArrayForSignature(tx, inputIndex, connectedScript, sigHashType);
        
        System.out.println("Raw tx for hashing:" + toString(rawtxforhashing));
        byte[] rawtxhash= new byte[32];
        SHA256Digest sha256= new SHA256Digest(); 
        sha256.reset();
        sha256.update(rawtxforhashing, 0, rawtxforhashing.length);
        sha256.doFinal(rawtxhash,0);
        //System.out.println("Raw tx singlehash:" + toString(rawtxhash));
        sha256.reset();
        sha256.update(rawtxhash, 0, rawtxhash.length);
        sha256.doFinal(rawtxhash,0);
        //System.out.println("Raw tx doublehash:" + toString(rawtxhash));
        
        Sha256Hash rawtxhash2= tx.hashForSignature(inputIndex, connectedScript, sigHashType);
        System.out.println("Tx hash Bitcoinj: " + toString(rawtxhash2.getBytes()));
        
        // send to card for parsing
        byte[] response= cc.cardParseTransaction(rawtxforhashing);
        byte[] txhash= new byte[32]; 
        System.arraycopy(response, 0, txhash, 0, 32);
        System.out.println("Tx hash SatoChip: "+ toString(txhash));
        // check signature if provided
        if (response.length>32){
            // recover authentikey from card
            byte[] akey= TestBip32GetAuthentiKey(cc);
            
            // recover key from sig
            int sig_size = ((int)(response[32] & 0xff)<<8) + ((int)(response[33] & 0xff));  
            byte[] signature= new byte[sig_size]; 
            System.arraycopy(response, 34, signature, 0, sig_size);
            ECKey.ECDSASignature ecdsasig= toECDSASignature(signature);
            Sha256Hash msghash= Sha256Hash.create(txhash); // compute sha256 of message
            //System.out.println("Public key signature size:"+ sig_size);
            //System.out.println("Public key signature computed:"+ toString(signature));
            for (int recid=0; recid<4; recid++){
                ECKey pkey= ECKey.recoverFromSignature(recid, ecdsasig, msghash, true);
                if (pkey!=null && Arrays.equals(akey, pkey.getPubKey()))
                    System.out.println("#recid: "+recid+"Public key:" + pkey.toString());        
            }
            
        }    
    }   
    
    // from Bitcoinj - com.google.bitcoin.core.Transaction
    // return a byte array of the transaction serialized data to be hashed for signing 
    public static byte[] byteArrayForSignature(Transaction tx, int inputIndex, byte[] connectedScript, byte sigHashType) {
        // The SIGHASH flags are used in the design of contracts, please see this page for a further understanding of
        // the purposes of the code in this method:
        //
        //   https://en.bitcoin.it/wiki/Contracts
        byte[] EMPTY_ARRAY = new byte[0];
        NetworkParameters params;
        params = RegTestParams.get();
        
        try {

            // This step has no purpose beyond being synchronized with the reference clients bugs. OP_CODESEPARATOR
            // is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
            // It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
            // the design we use today where scripts are executed independently but share a stack. This left the
            // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
            // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
            // do it, we could split off the main chain.
            connectedScript = Script.removeAllInstancesOfOp(connectedScript, ScriptOpCodes.OP_CODESEPARATOR);

            // Store all the input scripts and clear them in preparation for signing. If we're signing a fresh
            // transaction that step isn't very helpful, but it doesn't add much cost relative to the actual
            // EC math so we'll do it anyway.
            // Also store the input sequence numbers in case we are clearing them with SigHash.NONE/SINGLE
            byte[][] inputScripts = new byte[tx.getInputs().size()][];
            long[] inputSequenceNumbers = new long[tx.getInputs().size()];
            Transaction txcpy= new Transaction(params);
            for (int i = 0; i < tx.getInputs().size(); i++) {
                inputScripts[i] = tx.getInputs().get(i).getScriptBytes();
                inputSequenceNumbers[i] = tx.getInputs().get(i).getSequenceNumber();
                //inputs.get(i).setScriptBytes(EMPTY_ARRAY);
                if (i==inputIndex)
                    txcpy.addInput(new TransactionInput(params, txcpy, connectedScript ));
                else
                    txcpy.addInput(new TransactionInput(params, txcpy, EMPTY_ARRAY ));
                txcpy.getInputs().get(i).setSequenceNumber(tx.getInputs().get(i).getSequenceNumber());
            }
            for (int o = 0; o < tx.getOutputs().size(); o++) {
                txcpy.addOutput(tx.getOutput(o).getValue(), new Script(tx.getOutput(o).getScriptBytes()));
            }    
            
            // Set the input to the script of its output. Satoshi does this but the step has no obvious purpose as
            // the signature covers the hash of the prevout transaction which obviously includes the output script
            // already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
            //TransactionInput input = tx.getInputs().get(inputIndex);
            //input.setScriptBytes(connectedScript);

            //ArrayList<TransactionOutput> outputs = (ArrayList<TransactionOutput>) tx.getOutputs();
            if ((sigHashType & 0x1f) == (SigHash.NONE.ordinal() + 1)) {
//                // SIGHASH_NONE means no outputs are signed at all - the signature is effectively for a "blank cheque".
//                this.outputs = new ArrayList<TransactionOutput>(0);
//                // The signature isn't broken by new versions of the transaction issued by other parties.
//                for (int i = 0; i < tx.getInputs().size(); i++)
//                    if (i != inputIndex)
//                        txcpy.getInputs().get(i).setSequenceNumber(0);
                return null; // not supported
            } else if ((sigHashType & 0x1f) == (SigHash.SINGLE.ordinal() + 1)) {
//                // SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
//                if (inputIndex >= this.outputs.size()) {
//                    // The input index is beyond the number of outputs, it's a buggy signature made by a broken
//                    // Bitcoin implementation. The reference client also contains a bug in handling this case:
//                    // any transaction output that is signed in this case will result in both the signed output
//                    // and any future outputs to this public key being steal-able by anyone who has
//                    // the resulting signature and the public key (both of which are part of the signed tx input).
//                    // Put the transaction back to how we found it.
//                    //
//                    // TODO: Only allow this to happen if we are checking a signature, not signing a transactions
//                    for (int i = 0; i < inputs.size(); i++) {
//                        inputs.get(i).setScriptBytes(inputScripts[i]);
//                        inputs.get(i).setSequenceNumber(inputSequenceNumbers[i]);
//                    }
//                    this.outputs = outputs;
//                    // Satoshis bug is that SignatureHash was supposed to return a hash and on this codepath it
//                    // actually returns the constant "1" to indicate an error, which is never checked for. Oops.
//                    return new String("0100000000000000000000000000000000000000000000000000000000000000").getBytes(); // added
//                    //return new Sha256Hash("0100000000000000000000000000000000000000000000000000000000000000");
//                }
//                // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
//                // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
//                this.outputs = new ArrayList<TransactionOutput>(this.outputs.subList(0, inputIndex + 1));
//                for (int i = 0; i < inputIndex; i++)
//                    this.outputs.set(i, new TransactionOutput(params, this, NEGATIVE_ONE, new byte[] {}));
//                // The signature isn't broken by new versions of the transaction issued by other parties.
//                for (int i = 0; i < inputs.size(); i++)
//                    if (i != inputIndex)
//                        inputs.get(i).setSequenceNumber(0);
                return null; // not supported
            }

            //ArrayList<TransactionInput> inputs = (ArrayList<TransactionInput>) txcpy.getInputs();
            if ((sigHashType & SIGHASH_ANYONECANPAY_VALUE) == SIGHASH_ANYONECANPAY_VALUE) {
//                // SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
//                // of other inputs. For example, this is useful for building assurance contracts.
//                this.inputs = new ArrayList<TransactionInput>();
//                this.inputs.add(input);
                return null; // not supported
            }

            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(txcpy.getMessageSize() == UNKNOWN_LENGTH ? 256 : txcpy.getMessageSize() + 4);
            txcpy.bitcoinSerialize(bos);
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            //Sha256Hash hash = new Sha256Hash(singleDigest(bos.toByteArray(),0, bos.toByteArray().length)); // change: single digest!
            byte[] txdata= bos.toByteArray(); // added 
            bos.close();

            // Put the transaction back to how we found it.
//            this.inputs = inputs;
//            for (int i = 0; i < inputs.size(); i++) {
//                inputs.get(i).setScriptBytes(inputScripts[i]);
//                inputs.get(i).setSequenceNumber(inputSequenceNumbers[i]);
//            }
//            this.outputs = outputs;
            
            return txdata; // return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
    * @param args
     * @throws CardException 
     * @throws NoSuchAlgorithmException 
    */
    public static void main(String[] args) throws CardException, NoSuchAlgorithmException, UnsupportedEncodingException {

        try {
            // applet aid
            byte[] byteAID= {0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70}; //SatoChip
            //byte[] byteAID= {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x00}; //cardedge jcdk-222
            //byte[] byteAID= {(byte)0xFF ,0x42 ,0x54 ,0x43 ,0x48 ,0x49 ,0x50}; //BTChip
            
//            //String strresponse="00209A42486E1D26728F36A527D7E801A1AF81B7B4E07AEAA3B12FB76B40C78750F600473045022040FD266EA3792D900588D3905A766C62531B782A5B3AB714E28474FBFDA5C2C9022100B54931B1985C4E19C01703A0E319AF9A74E68D0A95D4CCAC999906458AE1B8B200483046022100FE0C49F28FAD0FF2BDBCD846D0B38DA15AB670BD96759E5FA36B261AE0E7EAE3022100AC97AD5ECCA4F60D18B4A9AB4C8836593AEA7EFAA0458BF1E0586D46E8F618FA";
//            //String strresponse="00209A42486E1D26728F36A527D7E801A1AF81B7B4E07AEAA3B12FB76B40C78750F600483046022100B372DBC1875609BA36D7160EF8228DA22C0197D78CE5CF3D635DB1C5BB0AAA170221008ED5F6204218926CC520DC412D705870FC67CE2B39881B9CFC10F68C0E0F1EE200483046022100A6616634415516B2AE65FB0DDE11E574106E1B8A58697D2997C525DA004DCA1E0221008C0418DB248723ACCE2D26099FF351092622C2528B72D8C729AF15C815F7265B";
//            //String strresponse="0020E53A6BC69086F5059A007A9DD38FDF19E7748245C6820755239E21CE6D2D418400473045022100F792CF25106F218D9F83E75D5DB2F06BCE3A3AFC3C7EF4BF853A7B1BCC48A3A0022026E334965957669EAEBD6F6AF28B9BE667625A4F0F5DE573C714EF550305C3A900483046022100BB2BE7477C8BABAF660A3AAD14C6561D0F8F967C48620AD39923946037589EFC0221009A65163AB180BA5A8D6C173E0BDAB78E32C6BC34AA63F7FB8F6B7FE594821641";
//            //TestRecoverPubkey(strresponse);
//
//            //String strmsg="18426974636F696E205369676E6564204D6573736167653A0A05617A657274";
//            //String strsig="3045022100EBB669A2006F6493A8C0A71758577F5645757D0BCDBD998684A8086C033EBBDD022046B984FA3D40A7F2FD99EF75F83C760232DDC3366701512CA7E02618B2274F4A";
//
//            String strsig="30450220682877BBB84A454ACAC5C82FA6C61625A359096920DD5661F2F2DC36CAB1A49E022100F7E96ADC389D1C3524A6F6DB8F272DA39AE0459B18CDEBF79343739B989AE75B";
//            String strmsg="18426974636F696E205369676E6564204D6573736167653A0A05617A657274";
//            byte[] msg= DatatypeConverter.parseHexBinary(strmsg);
//            byte[] sig= DatatypeConverter.parseHexBinary(strsig);
//            //debugRecoverFromSig(msg, sig);
//            //exit(0);


            // CardConnector object
            CardConnector cc= new CardConnector();

            //select applet
            byte[] response={};
            System.out.println("cardselect");
            cc.cardSelect(byteAID);

            //exit(0);
            //get status
            try{
                cc.cardGetStatus();
            }catch(CardConnectorException ex){
                System.out.println("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
            }
            //exit(0);

            // setup
            byte pin_tries_0= 0x10;
            byte ublk_tries_0= (byte) 0x10;
            byte[] pin_0={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
            byte[] ublk_0={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
            byte pin_tries_1=0x10;
            byte ublk_tries_1=(byte) 0x10;
            byte[] pin_1={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
            byte[] ublk_1={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
            short secmemsize= 0x1000;
            short memsize= 0x1000;
            byte create_object_ACL= 0x00;
            byte create_key_ACL= 0x00;
            byte create_pin_ACL= 0x00;
            try{
                cc.cardSetup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                    pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                    secmemsize, memsize, 
                    create_object_ACL, create_key_ACL, create_pin_ACL);
            }catch(CardConnectorException ex){
                System.out.println("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
            }
            //get status
            cc.cardGetStatus();

            //exit(0);

            // verifPIN
            byte pin_nbr= 0x00;
            cc.cardVerifyPIN(pin_nbr, pin_1);
            // list key
            cc.cardGetStatus();
            System.out.println("*****ListKey*****");
            cc.cardListKeys();
            System.out.println("*****************");

            // gen key
            //TestGenerateKeyPair(byte alg_type, byte priv_key_nbr, byte pub_key_nbr, short key_size);
            //TestGenerateKeyPair(cc, JCconstants.ALG_RSA, (byte)0x00, (byte)0x01, (short)1024);
            //TestGenerateKeyPair(ALG_EC_FP, (byte)0x02, (byte)0x03, (short)256);
            //TestGenerateKeyPair(cc, JCconstants.ALG_EC_FP, (byte)0x04, (byte)0x05, (short)192);

            // import private key 
            //TestImportKey(byte key_type, byte key_nbr, short key_size, byte[] key_data);
            byte[] key_priv={0x00, (byte)32, // short blob_size
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}; // (short) sizeS + (byte[]) S
            //04\79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
            byte[] key_pub={(byte)0x00, (byte)65, // (short) sizeW
                (byte)0x04, // uncompressed
                (byte)0x79,(byte)0xbe,(byte)0x66,(byte)0x7e,(byte)0xf9,(byte)0xdc,(byte)0xbb,(byte)0xac,(byte)0x55,(byte)0xa0,(byte)0x62,(byte)0x95,(byte)0xce,(byte)0x87,(byte)0x0b,(byte)0x07,
                (byte)0x02,(byte)0x9b,(byte)0xfc,(byte)0xdb,(byte)0x2d,(byte)0xce,(byte)0x28,(byte)0xd9,(byte)0x59,(byte)0xf2,(byte)0x81,(byte)0x5b,(byte)0x16,(byte)0xf8,(byte)0x17,(byte)0x98,
                (byte)0x48,(byte)0x3a,(byte)0xda,(byte)0x77,(byte)0x26,(byte)0xa3,(byte)0xc4,(byte)0x65,(byte)0x5d,(byte)0xa4,(byte)0xfb,(byte)0xfc,(byte)0x0e,(byte)0x11,(byte)0x08,(byte)0xa8,
                (byte)0xfd,(byte)0x17,(byte)0xb4,(byte)0x48,(byte)0xa6,(byte)0x85,(byte)0x54,(byte)0x19,(byte)0x9c,(byte)0x47,(byte)0xd0,(byte)0x8f,(byte)0xfb,(byte)0x10,(byte)0xd4,(byte)0xb8}; 
//                byte[] key_pub={(byte)0x00, (byte)33, // (short) sizeW
//                                  (byte)0x02, // compressed
//                                  (byte)0x79,(byte)0xbe,(byte)0x66,(byte)0x7e,(byte)0xf9,(byte)0xdc,(byte)0xbb,(byte)0xac,
//                                  (byte)0x55,(byte)0xa0,(byte)0x62,(byte)0x95,(byte)0xce,(byte)0x87,(byte)0x0b,(byte)0x07,
//                                  (byte)0x02,(byte)0x9b,(byte)0xfc,(byte)0xdb,(byte)0x2d,(byte)0xce,(byte)0x28,(byte)0xd9,
//                                  (byte)0x59,(byte)0xf2,(byte)0x81,(byte)0x5b,(byte)0x16,(byte)0xf8,(byte)0x17,(byte)0x98}; 
            //TestImportKey(cc, JCconstants.TYPE_EC_FP_PRIVATE, (byte)0x06, (short) 256, key_priv);
            //TestImportKey(cc, JCconstants.TYPE_EC_FP_PUBLIC, (byte) 0x07, (short) 256, key_pub);

            // computesign
            //TestComputeSign(byte CM, byte key_sign, byte key_verif);
            //TestComputeSign(JCconstants.ALG_RSA_PKCS1, (byte) 0, (byte) 1);
            //TestComputeSign(JCconstants.ALG_ECDSA_SHA256, (byte) 4, (byte) 5);
            //TestComputeSign(CM_ECDSA_SHA, (byte) 4, (byte) 5);
            // testing Sha512 & HmacSha512
            //TestSHA512();

            // import seed
            String strseed= "000102030405060708090a0b0c0d0e0f";
            TestBip32ImportSeed(cc, strseed);
            TestBip32ImportSeed(strseed);
            for (int val=0; val<1; val++){
                for (int depth=1; depth<2; depth++){
                    byte[] bip32path= new byte[4*depth];
                    for (int i=0; i<bip32path.length; i+=4){
                        bip32path[i]=(byte)0x80;
                        bip32path[i+1]=0x00;
                        bip32path[i+2]=0x00;
                        bip32path[i+3]=(byte)val;
                    }                
                    TestBip32GetExtendedKey(cc, bip32path, (byte)0x00);//HW
                    TestBip32GetExtendedKey(bip32path);//SW
                }
            }
            //strseed="fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
            //TestBip32ImportSeed(strseed);    
            //exit(0);


            // Message signing
            String strmsg= "abcdefghijklmnopqrstuvwxyz0123456789";
            for (int val=0; val<3; val++){
                System.out.println("Message to sign:"+strmsg);
                boolean verif=TestBip32MessageSigning(cc, strmsg, (byte)0xff);
                if (verif)
                    System.out.println("Signature verified!");
                else
                    System.out.println("Signature verification failed!");
                strmsg+=strmsg;
            }
            //exit(0);
            
            // Parse Transaction
            TestParseTransaction(cc, (byte)0xff);                

            /* Mise hors tension de la carte */
            System.out.println("Disconnect...");
            cc.disconect();
        } catch (CardConnectorException ex) {    
            System.out.println("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
        }


    } 

}
