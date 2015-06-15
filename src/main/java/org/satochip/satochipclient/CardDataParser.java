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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.toporin.bitcoincore.ECException;
import org.toporin.bitcoincore.ECKey;
import org.toporin.bitcoincore.VarInt;


public class CardDataParser {
    
    
    public static class PubKeyData{
    
        //private static final byte[] BITCOIN_SIGNED_MESSAGE_HEADER = {0x18,'B','i','t','c','o','i','n',' ','S','i','g','n','e','d',' ','M','e','s','s','a','g','e',':','\n'}; //"Bitcoin Signed Message:\n";
        protected static final String BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n";

        private static final boolean DOUBLESHA256=true;
        private static final boolean SINGLESHA256=false;
        private static final int OPTION_FLAGS_MASK= 0x8000;
        
        public byte[] msg;
        public byte[] data;
        public byte[] signature;
        public byte[] pubkey;
        public byte[] coordx;
        public byte[] authentikey;
        public byte[] authentikey_coordx;
        
        public int msg_size;
        public int data_size;
        public int sig_size;
        public int pubkey_recid;
        public int authentikey_recid;
        public int option_flags;
        
        public byte[] msg2;
        public byte[] signature2;
        public int msg2_size;
        public int sig2_size;

        public byte[] compactsig;
        public byte[] compactsig_b64;
        public String compactsig_b64_str;
        
        public PubKeyData(){
        }
        public PubKeyData(byte[] authkey){
            setAuthentikey(authkey);
        }
        public void setAuthentikey(byte[] authkey){
            authentikey= Arrays.copyOf(authkey, authkey.length);
            authentikey_coordx= Arrays.copyOfRange(authentikey, 1, 1+32); 
        }
        
        public PubKeyData parseBip32GetAuthentikey(byte[] response) throws ECException{
            // self-signed authentikey: data= coordx
            authentikey= parseSelfSignedData(response).pubkey;
            authentikey_coordx= Arrays.copyOfRange(authentikey, 1, 1+32); 
            return this;
        }
        public PubKeyData parseBip32ImportSeed(byte[] response) throws ECException{
            // self-signed authentikey: data= coordx
            parseBip32GetAuthentikey(response);
            int offset=2+data_size+2+sig_size;
            int nb_deleted = ((int)(response[offset] & 0xff)<<8) + ((int)(response[offset+1] & 0xff));  
            
            return this;
        }

        public PubKeyData parseBip32GetExtendedKey(byte[] response) throws ECException{
            
            if (authentikey==null)
                throw new ECException("Authentikey not set");
            
            // double signature: first is self-signed, second by authentikey
            // firs self-signed sig: data= coordx
            parseSelfSignedData(response);

            // second signature by authentikey
            msg2_size= msg_size+2+sig_size;
            msg2= Arrays.copyOfRange(response, 0, msg2_size); 
            sig2_size = ((int)(response[msg2_size] & 0xff)<<8) + ((int)(response[msg2_size+1] & 0xff));  
            signature2= Arrays.copyOfRange(response, msg2_size+2, msg2_size+2+sig2_size); 
            ECKey.recoverFromSignature(authentikey_coordx, msg2, signature2, SINGLESHA256);        
            
            return this;
        }

        public PubKeyData parseGetPublicKeyFromPrivate(byte[] response) throws ECException{
            // self-signed: data= coordx
            return parseSelfSignedData(response);
        }
        
        public PubKeyData parseSelfSignedData(byte[] response) throws ECException{

            // response= [data_size | data | sig_size | signature]
            data_size = ((int)(response[0] & 0xff)<<8) + ((int)(response[1] & 0xff));
            data= Arrays.copyOfRange(response, 2, 2+data_size); 
            
            msg_size= 2+data_size;
            msg= Arrays.copyOfRange(response, 0, msg_size);
            sig_size = ((int)(response[msg_size] & 0xff)<<8) + ((int)(response[msg_size+1] & 0xff));  
            signature= Arrays.copyOfRange(response, msg_size+2, msg_size+2+sig_size);
            
            if (sig_size==0)
                throw new ECException("Signature missing");
            // self-signed
            pubkey= ECKey.recoverFromSignature(data, msg, signature, SINGLESHA256);
            
            return this;
        }

        public PubKeyData parseMaybeSignedDataSafe(byte[] response) throws ECException{
            
            // if signed, data is signed by authentikey!
            // response= [data_size | data | sig_size | authentikey_signature]
            data_size = ((int)(response[0] & 0xff)<<8) + ((int)(response[1] & 0xff));
            option_flags= (data_size & OPTION_FLAGS_MASK);
            data_size &= ~OPTION_FLAGS_MASK;
            data= Arrays.copyOfRange(response, 2, 2+data_size); 
            
            msg_size= 2+data_size;
            msg= Arrays.copyOfRange(response, 0, msg_size);
            sig_size = ((int)(response[msg_size] & 0xff)<<8) + ((int)(response[msg_size+1] & 0xff));  
            signature= Arrays.copyOfRange(response, msg_size+2, msg_size+2+sig_size);
            
            return this;
            
        }        
        public PubKeyData parseMaybeSignedData(byte[] response) throws ECException{
            
            parseMaybeSignedDataSafe(response);
            
            // check signature with provided key or using data as coordx by default
            if (sig_size==0)
                return this;
            else if (authentikey==null)
                throw new ECException("Authentikey not set");
            pubkey= ECKey.recoverFromSignature(authentikey_coordx, msg, signature, SINGLESHA256);
            
            return this;
        }
        public PubKeyData parseTxHash(byte[] response) throws ECException{
            // hash signed by authentikey
            return parseMaybeSignedData(response);// coordx+key self-signature
        }
        
        
        public PubKeyData parseMessageSigning(byte[] signature, byte[] sigpubkey, String message) throws CardDataParserException, ECException{
            
            // Prepend the message for signing as done inside the card!!
            //byte[] contents;
            byte[] paddedcontents=null;
            try (ByteArrayOutputStream outStream = new ByteArrayOutputStream(message.length()*2)) {
                byte[] headerBytes = BITCOIN_SIGNED_MESSAGE_HEADER.getBytes("UTF-8");
                outStream.write(VarInt.encode(headerBytes.length));
                outStream.write(headerBytes);
                byte[] messageBytes = message.getBytes("UTF-8");
                outStream.write(VarInt.encode(messageBytes.length));
                outStream.write(messageBytes);
                paddedcontents = outStream.toByteArray();
                //contents = message.getBytes("UTF-8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(CardDataParser.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(CardDataParser.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            this.signature=signature;
            byte[] sigpubkey_coordx= Arrays.copyOfRange(sigpubkey, 1, 1+32); 
            pubkey= ECKey.recoverFromSignature(sigpubkey_coordx, paddedcontents, signature, DOUBLESHA256);
            pubkey_recid= ECKey.recidFromSignature(sigpubkey_coordx, paddedcontents, signature, DOUBLESHA256);
            
            compactsig= parseToCompactSig(signature, pubkey_recid, true);
            //int recid=0;
            //System.out.println("recid="+recid+ "  pubkey_recid:"+pubkey_recid);
            //compactsig= parseToCompactSig(signature, recid, true);//debug
            
            compactsig_b64= Base64.getEncoder().encode(compactsig);
            compactsig_b64_str= null;
            try {
                compactsig_b64_str= new String(compactsig_b64, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(CardDataParser.class.getName()).log(Level.SEVERE, null, ex);
            }
            return this;
        }    
        
        @Override
        public String toString(){
        
            String str="PubKeyData:";
            str+="\n\t data_size:"+data_size;
            str+="\n\t data:"+toHexString(data);
            str+="\n\t msg_size:"+msg_size;
            str+="\n\t msg:"+toHexString(msg);
            str+="\n\t sig_size:"+sig_size;
            str+="\n\t signature:"+toHexString(signature);
            str+="\n\t option_flags:"+option_flags+" "+Integer.toBinaryString(option_flags & 0xFFFF);
            str+="\n\t pubkey_recid:"+pubkey_recid;
            str+="\n\t pubkey:"+toHexString(pubkey);
            str+="\n\t authentikey_recid:"+authentikey_recid;
            str+="\n\t authentikey:"+toHexString(authentikey);
            str+="\n\t authentikey_coordx:"+toHexString(authentikey_coordx);
            str+="\n\t msg2_size:"+msg2_size;
            str+="\n\t msg2:"+toHexString(msg2);
            str+="\n\t sig2_size:"+sig2_size;
            str+="\n\t signature2:"+toHexString(signature2);
            str+="\n\t compactsig:"+toHexString(compactsig);
            str+="\n\t compactsig_b64:"+toHexString(compactsig_b64);
            str+="\n\t compactsig_b64_str:"+compactsig_b64_str;
            str+="\n";
            return str;
        }
        

        /* convert a DER encoded signature to compact 65-byte format
            input is hex string in DER format
            output is hex string in compact 65-byteformat
            http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
            https://bitcointalk.org/index.php?topic=215205.0            
        */
        public static byte[] parseToCompactSig(byte[] sigin, int recid, boolean compressed) throws CardDataParserException {

            byte[] sigout= new byte[65];
            // parse input 
            byte first= sigin[0];
            if (first!= 0x30){
                throw new CardDataParserException("Wrong first byte!");
            }
            byte lt= sigin[1];
            byte check= sigin[2];
            if (check!= 0x02){
                throw new CardDataParserException("Check byte should be 0x02");
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
                throw new CardDataParserException("Second check byte should be 0x02");
            }
            byte ls= sigin[5+lr];
            if (lt != (lr+ls+4)){
                throw new CardDataParserException("Wrong lt value");
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
                throw new CardDataParserException("Wrong recid value");
            }
            if (compressed){
                sigout[0]= (byte)(27 + recid + 4 );
            }else{
                sigout[0]= (byte)(27 + recid);                
            }

            return sigout;
        }
    }
    
    public static class KeyList{
    
        public ArrayList<Integer> keys_nbr;
        public ArrayList<Integer> keys_type;
        public ArrayList<Integer> keys_partner;
        public ArrayList<Integer> keys_size;
        public ArrayList<int[]>  keys_ACL;
        public int key_nbr;
        
        public KeyList(byte[] response){
            
            int capacity= response.length/10;
            keys_nbr= new ArrayList<>(capacity);
            keys_type= new ArrayList<>(capacity);
            keys_partner= new ArrayList<>(capacity);
            keys_size= new ArrayList<>(capacity);
            keys_ACL= new ArrayList<>(capacity);
            key_nbr=0;
            
            int base=0;
            key_nbr=0;
            while(base<response.length){
                keys_nbr.add((int)response[base++]);
                keys_type.add((int)response[base++]);
                keys_partner.add((int)response[base++]);
                keys_size.add(((int)(response[base++] & 0xff)<<8) + ((int)(response[base++] & 0xff)));
                        
                int[] acl= new int[JCconstants.KEY_ACL_SIZE/2];
                for (short i= 0; i<JCconstants.KEY_ACL_SIZE/2; i++){
                    acl[i]=((int)(response[base++] & 0xff)<<8) + ((int)(response[base++] & 0xff));
                }
                keys_ACL.add(acl);
                key_nbr++;
            }
        }
                
        @Override
        public String toString(){
            
            if (key_nbr==0){
                return "KeyList is empty";
            }
            
            String data= "KeyList: \n"+"\t Number of Keys:"+key_nbr;
            for (int i=0; i<key_nbr; i++){
                data+="\n\t key nbr:     " + keys_nbr.get(i);
                data+="\n\t key type:    " + keys_type.get(i);
                data+="\n\t key partner: " + keys_partner.get(i);
                data+="\n\t key size:    " + keys_size.get(i);
                data+="\n\t key ACL (RWU): ";
                data+= Integer.toBinaryString(keys_ACL.get(i)[0]);
                data+="\t " + Integer.toBinaryString(keys_ACL.get(i)[1]);
                data+="\t " + Integer.toBinaryString(keys_ACL.get(i)[2]);
                data+="\n";
            }
            return data;
        }   
    }
    
    public static class CardStatus{

        public byte protocol_version_maj;
        public byte protocol_version_min;
        public byte applet_version_maj;
        public byte applet_version_min; 
        public int sec_mem_tot;
        public int mem_tot;
        public int sec_mem_free;
        public int mem_free;
        public byte PINs_nbr;
        public byte keys_nbr;
        public short logged_in;
        
        public CardStatus(byte[] response){
            // key info
            int datasize= response.length;
            short base=0; 
            // process response (6 bytes - 2 long - 1 short)
            if (datasize>0){// datasize ==15// 16?
                protocol_version_maj= response[base++];
                protocol_version_min= response[base++];
                applet_version_maj= response[base++];
                applet_version_min= response[base++];
                sec_mem_tot= ((response[base++]&0xff)<<8)+(response[base++]&0xff);
                mem_tot= ((response[base++]&0xff)<<8)+(response[base++]&0xff);
                sec_mem_free= ((response[base++]&0xff)<<8)+(response[base++]&0xff);
                mem_free= ((response[base++]&0xff)<<8)+(response[base++]&0xff);
                PINs_nbr= response[base++];
                keys_nbr= response[base++];
                logged_in= (short) (((response[base++]&0xff)<<8)+(response[base++]&0xff));
            }		
        }
        
        @Override
        public String toString(){
        
            String data= "CardStatus:";
            data+="\n\t Protocol major version: "+protocol_version_maj;
            data+="\n\t Protocol minor version: "+protocol_version_min;
            data+="\n\t Applet major version: "+applet_version_maj;
            data+="\n\t Applet  minor version: "+applet_version_min;
            data+="\n\t Total secure memory: "+ sec_mem_tot;
            data+="\n\t Total object memory: "+ mem_tot;
            data+="\n\t Free secure memory: "+ sec_mem_free;
            data+="\n\t Free object memory: "+ mem_free;
            data+="\n\t Number of used PIN: "+ PINs_nbr;
            data+="\n\t Number of used keys: "+ keys_nbr;
            data+="\n\t Currently logged in identities: "+ logged_in + " " + Integer.toBinaryString(logged_in & 0xffff);
            return data;
        }
    }
    
    /**
    * Utility function that converts a byte array into an hexadecimal string.
    * @param bytes
    * @return String
    */
    public static String toHexString(byte[] bytes) {
        if (bytes==null)
            return "null";
        return toHexString(bytes, 0, bytes.length, 0);
    }
    public static String toHexString(byte[] bytes, int off, int size, int blocksize) {
            
        if (bytes==null)
            return "null";
        final String hexChars = "0123456789ABCDEF";
        StringBuffer sbTmp = new StringBuffer();
        char[] cTmp = new char[2];

        for (int i = off; i < (off+size); i++) {
                cTmp[0] = hexChars.charAt((bytes[i] & 0xF0) >>> 4);
                cTmp[1] = hexChars.charAt(bytes[i] & 0x0F);
                sbTmp.append(cTmp);
                if (blocksize!=0 && ((i+1)%blocksize)==0)
                   sbTmp.append(' '); 
        }
        
        return sbTmp.toString();
    }
    
    public static class CardDataParserException extends Exception{
        CardDataParserException(String msg){
            super(msg);
        }
    }
    
}
