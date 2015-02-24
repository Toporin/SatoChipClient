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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


/**
 *
 * @author Toporin
 */
public class CardConnector {
   
    /* constants declaration */
    private Card card; 
    private CardChannel channel; 
    private TerminalFactory terminalfactory;
    private List<CardTerminal> listterminal;
    private CardTerminal terminal = null;
    private byte[] ATR= null;
    private short sw12=-1;
    private ResponseAPDU r;
    private CommandAPDU c;

    // constructor
    public CardConnector(){
        
        terminalfactory = TerminalFactory.getDefault();
        try {
            listterminal = terminalfactory.terminals().list();
            System.out.println("Terminals: " + listterminal);
            if (listterminal.isEmpty()) {
                    System.out.println("No terminals found.");
                    return;
            }
            // Get the first terminal in the list
            terminal = listterminal.get(0);
            // Establish connection with the card using "T=0","T=1","T=CL" or "*"
            card = terminal.connect("*");	
        } catch (CardException e) {
            e.printStackTrace();
        }

        System.out.println("Card: " + card);
        ATR = card.getATR().getBytes();
        System.out.println("ATR: " + toString(ATR));
        channel = card.getBasicChannel();
    }

    public void disconect() throws CardException{
        card.disconnect(true);
    }
    
    public byte[] getATR(){
        return ATR;
    }
    
    /**
    * Utility function that converts a byte array into an hexadecimal string.
    * @param bytes
    */
    public static String toString(byte[] bytes) {
            
            if (bytes==null)
                return "null";
        
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
    
    // Exchange APDU with javacard 
    public byte[] exchangeAPDU(byte cla, byte ins, byte p1, byte p2, byte[] data, byte le) throws CardConnectorException{
            
        c= new CommandAPDU(cla, ins, p1, p2, data, le);
        try {
            r = channel.transmit(c);
        } catch (CardException ex) {
            throw new CardConnectorException("CardException during connection", c, r);
        }
        System.out.println("SW12 <<<: "	+ Integer.toHexString(r.getSW1()&0xFF) + " " + Integer.toHexString(r.getSW2()&0xFF) );		
        sw12= (short)r.getSW();
        if (sw12!=JCconstants.SW_OK){
            throw new CardConnectorException("exchangeAPDU error", c, r);
        }
        return r.getData();
    }
    
    public short getLastSW12(){
        return sw12;
    }
    public ResponseAPDU getLastResponse(){
        return r;
    }
    public CommandAPDU getLastCommand(){
        return c;
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

        return sigout;
    }
    
//    public static byte[] recoverPublicKeyFromSig(int recID, byte[] msg, byte[] sig, boolean doublehash){
//        
//        //if (true)
//        //    throw new CardConnectorException("debug bitcoinj", (byte)0, (short)0 );
//        
//        ECKey.ECDSASignature ecdsasig= toECDSASignature(sig);
//        Sha256Hash msghash= Sha256Hash.create(msg); // compute sha256 of message
//        if (doublehash){
//            msghash= Sha256Hash.create(msghash.getBytes());
//        }
//        com.google.bitcoin.core.ECKey pkey= ECKey.recoverFromSignature(recID, ecdsasig, msghash, true);
//        if (pkey!=null)
//            return pkey.getPubKey();
//        else
//            return null;
//            
//    }
    
    // SELECT Command
    public byte[] cardSelect(byte[] AID) throws CardConnectorException {
            // See GlobalPlatform Card Specification (e.g. 2.2, section 11.9)
            byte cla= 0x00;
            byte ins= (byte)0xA4;
            byte p1= 0x04;
            byte p2=0x00;
            byte le= 0x00;
            System.out.println("CardSelect");
            System.out.println("APDU >>>: "	+ toString(AID));	
            byte[] response;
            response = exchangeAPDU(cla, ins, p1, p2, AID, le);
            System.out.println("APDU <<<: "	+ toString(response));
            
            return response;
    }

    /**
     * Card Setup (API not clear)
     * 
     * **/
    public byte[] cardSetup( 
                    byte pin_tries_0, byte ublk_tries_0, 
                    byte[] pin_0, byte[] ublk_0,
                    byte pin_tries_1, byte ublk_tries_1, 
                    byte[] pin_1, byte[] ublk_1,
                    short memsize, short memsize2, 
                    byte create_object_ACL, byte create_key_ACL, byte create_pin_ACL) throws CardConnectorException {

        // to do: check pin sizes < 256
        byte[] pin={0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30}; // default pin

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SETUP;
        byte p1= 0;
        byte p2=0;
        // data=[pin_length(1) | pin | 
        //       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 | 
        //       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 | 
        //       memsize(2) | memsize2(2) | ACL(3) ]
        byte[] data= new byte[16+pin.length+pin_0.length+pin_1.length+ublk_0.length+ublk_1.length]; 
        byte le= 0x00;
        short base=0;
        //initial PIN check
        data[base++]=(byte)pin.length; 

        for (int i=0; i<pin.length; i++){
                data[base++]=pin[i]; // default PIN
        }
        //pin0+ublk0
        data[base++]=pin_tries_0;
        data[base++]=ublk_tries_0;
        data[base++]=(byte)pin_0.length;
        for (int i=0; i<pin_0.length; i++){
                data[base++]=pin_0[i]; 
        }
        data[base++]=(byte)ublk_0.length;
        for (int i=0; i<ublk_0.length; i++){
                data[base++]=ublk_0[i]; 
        }
        //pin1+ublk1
        data[base++]=pin_tries_1;
        data[base++]=ublk_tries_1;
        data[base++]=(byte)pin_1.length;
        for (int i=0; i<pin_1.length; i++){
                data[base++]=pin_1[i]; 
        }
        data[base++]=(byte)ublk_1.length;
        for (int i=0; i<ublk_1.length; i++){
                data[base++]=ublk_1[i]; 
        }
        // 2bytes unused?
        data[base++]= (byte)(memsize>>8);
        data[base++]= (byte)(memsize&0x00ff);
        // mem_size
        data[base++]= (byte)(memsize2>>8);
        data[base++]= (byte)(memsize2&0x00ff);
        // acl
        data[base++]= create_object_ACL;
        data[base++]= create_key_ACL;
        data[base++]= create_pin_ACL;

        // send apdu
        System.out.println("cardSetup");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response = null;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        return response;
            
    }

    public byte[] cardBip32ImportSeed(byte[] keyACL, byte[] seed) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_BIP32_IMPORT_SEED;
        byte p1= 0x00; 
        byte p2= 0x00;
        byte[] data= new byte[keyACL.length+1+seed.length]; 
        byte le= 0x00;
        short base=0;

        System.arraycopy(keyACL, 0, data, base, keyACL.length);
        base+=keyACL.length;
        data[base++]= (byte)seed.length;
        System.arraycopy(seed, 0, data, base, seed.length);

        // send apdu
        System.out.println("ImportBIP32Seed");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response)); 

        return response;
    }

    public byte[] cardBip32GetAuthentiKey() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_BIP32_GET_AUTHENTIKEY;
        byte p1= 0x00; 
        byte p2= 0x00;
        byte[] data= null; 
        byte le= 0x00;
        short base=0;

        // send apdu
        System.out.println("GetBip32AuthentiKey");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response)); 

        return response;
    }

    public byte[] cardBip32GetExtendedKey(byte[] path) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_BIP32_GET_EXTENDED_KEY;
        byte p1= (byte)(path.length/4); 
        byte p2= 0x00;
        byte[] data= new byte[path.length]; 
        byte le= 0x00;
        short base=0;

        System.arraycopy(path, 0, data, base, path.length);
        base+=path.length;

        // send apdu
        System.out.println("GetBip32ExtendedKey");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response=null;
        try{
            response = exchangeAPDU(cla, ins, p1, p2, data, le);
            System.out.println("APDU <<<: "	+ toString(response)); 
        }
        catch(CardConnectorException ex){
            // if there is no more memory available, erase cache...
            if (ex.getIns()==JCconstants.INS_BIP32_GET_EXTENDED_KEY && ex.getSW12()==JCconstants.SW_NO_MEMORY_LEFT){
                System.out.println("GetBip32ExtendedKey - out of memory: reset internal memory");
                response = exchangeAPDU(cla, ins, p1, (byte)0xFF, data, le);
            }
            else{
                throw ex;
            }    
        }
        
        return response;
    }

    public byte[] cardSignMessage(byte keynbr, byte[] message) throws CardConnectorException{

        // return signature as byte array
        // data is cut into chunks, each processed in a different APDU call
        int chunk= 160; // max APDU data=256 = chunk<=255-(4+2)
        int buffer_offset=0;
        int buffer_left=message.length;

        // CIPHER_INIT - no data processed
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SIGN_MESSAGE;
        byte p1= keynbr; // 0xff=>BIP32 otherwise STD
        byte p2= JCconstants.OP_INIT;
        byte[] data= new byte[4]; 
        byte le= 0x00;
        short base=0;
        data[base++]=(byte) ((buffer_left>>24) & 0xff); 
        data[base++]=(byte) ((buffer_left>>16) & 0xff); 
        data[base++]=(byte) ((buffer_left>>8) & 0xff); 
        data[base++]=(byte) ((buffer_left) & 0xff); 

        // send apdu
        System.out.println("cardSignBIP32Message - INIT");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        // CIPHER PROCESS/UPDATE (optionnal)
        while(buffer_left>chunk){

                //cla= JCconstants.CardEdge_CLA;
                //ins= INS_COMPUTE_CRYPT;
                //p1= key_nbr;
                p2= JCconstants.OP_PROCESS;
                data= new byte[2+chunk]; 
                base=0;
                data[base++]=(byte) ((chunk>>8) & 0xFF); //msb
                data[base++]=(byte) (chunk & 0xFF); //lsb
                System.arraycopy(message, buffer_offset, data, base, chunk);
                base+=chunk;
                buffer_offset+=chunk;
                buffer_left-=chunk;

                // send apdu
                System.out.println("cardSignBIP32Message - PROCESS");
                System.out.println("APDU data >>>: " + toString(data));
                System.out.println("APDU datasize >>>: " + data.length);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                System.out.println("APDU <<<: "	+ toString(response));
        }		

        // CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left; //following while condition, buffer_left<=chunk
        System.out.println("chunk value= "	+ chunk);
        //cla= JCconstants.CardEdge_CLA;
        //ins= INS_COMPUTE_CRYPT;
        //p1= key_nbr;
        p2= JCconstants.OP_FINALIZE;
        data= new byte[2+chunk]; 
        base=0;
        data[base++]=(byte) ((chunk>>8) & 0xFF); //msb
        data[base++]=(byte) (chunk & 0xFF); //lsb
        System.arraycopy(message, buffer_offset, data, base, chunk);
        base+=chunk;
        buffer_offset+=chunk;
        buffer_left-=chunk;

        // send apdu
        System.out.println("cardSignBIP32Message - FINALIZE");
        System.out.println("APDU >>>: "	+ toString(data));
        response= exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        return response;

    }

    public byte[] cardSignShortMessage(byte keynbr, byte[] message) throws CardConnectorException{

        // for message less than one chunk in size
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SIGN_SHORT_MESSAGE;
        byte p1= keynbr; // oxff=>BIP32 otherwise STD
        byte p2= 0x00;
        byte[] data= new byte[message.length+2]; 
        byte le= 0x00;
        short base=0;

        data[0]= (byte)(message.length>>8 & 0xFF);
        data[1]= (byte)(message.length & 0xFF);
        base+=2;
        System.arraycopy(message, 0, data, base, message.length);
        base+=message.length;

        // send apdu
        System.out.println("SignShortBip32Message:");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response)); 
        return response;

    }

    public byte[] cardParseTransaction(byte[] transaction) throws CardConnectorException{
        
        //Logger.getLogger(CardConnector.class.getName()).log(Level.SEVERE, "cardParseTranaction: begin rawtx:"+CardConnector.toString(transaction));
            
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_PARSE_TRANSACTION;
        byte p1= JCconstants.OP_INIT;
        byte p2= 0x00;
        byte[] data; 
        byte le= 0x00; 
        byte[] response=null;
        
        // init transaction data and context
        TransactionParser.resetTransaction(transaction);
        byte result= TransactionParser.RESULT_MORE;
        MessageDigest digestFull=null;
        try {
            digestFull= MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CardConnector.class.getName()).log(Level.SEVERE, "No SHA-256 algorithm available");
        }
        digestFull.reset();
        byte[] hashFull= new byte[digestFull.getDigestLength()];

        while (result==TransactionParser.RESULT_MORE){
            
            //Logger.getLogger(CardConnector.class.getName()).log(Level.SEVERE, "cardParseTranaction: while result:"+result);
            
            result= TransactionParser.parseTransaction(transaction);
            if (result== TransactionParser.RESULT_ERROR){
                System.out.println("Error during parsing");
                return null;
            }
            data= TransactionParser.getDataChunk();
            digestFull.update(data, 0, data.length);

            // send apdu
            if (result== TransactionParser.RESULT_FINISHED){
                le= 52; // [nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8) | hash(32) | sig?] 
                System.out.println("cardParseTransaction - FINISH");
            }
            else if (p1== JCconstants.OP_INIT)
                System.out.println("cardParseTransaction - INIT");
            else if (p1== JCconstants.OP_PROCESS)
                System.out.println("cardParseTransaction - PROCESS");
            System.out.println("APDU >>>: "	+ toString(data));
            response= exchangeAPDU(cla, ins, p1, p2, data, le);
            System.out.println("APDU <<<: "	+ toString(response));
            Logger.getLogger(CardConnector.class.getName()).log(Level.SEVERE, "cardParseTranaction: while apdu response:"+CardConnector.toString(response));
            
            // switch to process mode after initial call to parse
            p1= JCconstants.OP_PROCESS;

            if (result== TransactionParser.RESULT_FINISHED){
                break;
            }    
        }

        // parsing response data from javacard
//        if (response.length<52)
//            System.out.println("Wrong output size: " + response.length);		
//        else {
//            int nbInput= (int)(response[0]<<24)+(int)(response[1]<<16)+(int)(response[2]<<8)+(int)(response[3]);
//            int nbOutput= (int)(response[4]<<24)+(int)(response[5]<<16)+(int)(response[6]<<8)+(int)(response[7]);
//            int coordInput= (int)(response[8]<<24)+(int)(response[9]<<16)+(int)(response[10]<<8)+(int)(response[11]);
//            long amount= ((long)(response[12]&0xFF)<<56)+((long)(response[13]&0xFF)<<48)+
//                        ((long)(response[14]&0xFF)<<40)+((long)(response[15]&0xFF)<<32)+
//                        ((long)(response[16]&0xFF)<<24)+((long)(response[17]&0xFF)<<16)+
//                        ((long)(response[18]&0xFF)<<8)+((long)(response[19]&0xFF));
//            byte[] hash= new byte[32]; System.arraycopy(response, 46, hash, 0, 32);
//            System.out.println("    Nb inputs: "+nbInput + "    (" + TransactionParser.getNbInput() + ")");
//            System.out.println("    Nb outputs: "+nbOutput+ "   (" + TransactionParser.getNbOutput() + ")");
//            System.out.println("    Coord of active input: "+coordInput + " (" + TransactionParser.getCoordInput() + ")");
//            System.out.println("    Amount: "+ amount + " Satoshis" + " (" + TransactionParser.getAmount() + ")");
//            System.out.println("    Hash to sign: " + toString(hash)  + " (" + toString(TransactionParser.getHash()) + ")");
//            digestFull.doFinal(hashFull,0);
//            //System.out.println("    Hash to sign: " + toString(TransactionParser.getHash()) + " " + toString(hashFull));
//        }
        return response;
    }

    public byte[] cardSignTransaction(byte keynbr, byte[] txhash, byte[] chalresponse) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SIGN_TRANSACTION;
        byte p1= keynbr;
        byte p2= 0x00;
        byte le= 0x00; 
        byte[] response=null;
        byte[] data;
        if (txhash.length!=32)
            throw new CardConnectorException("Wrong txhash length", null, null);    
        if (chalresponse==null)
            data= txhash; 
        else{
            if (chalresponse.length!=20)
                throw new CardConnectorException("Wrong Challenge response length", null, null);
            data= new byte[txhash.length+chalresponse.length];
            System.arraycopy(txhash, 0, data, 0, txhash.length);
            System.arraycopy(chalresponse, 0, data, txhash.length, chalresponse.length);
        }
        
        System.out.println("cardSignTransaction");
        System.out.println("APDU >>>: "	+ toString(data));
        response= exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        
        return response;
    }
    
    public byte[] cardImportKey(
            byte key_nbr, byte[] key_ACL, 
            byte key_encoding, byte key_type, short key_size, byte[] key_blob) throws CardConnectorException{

        if (key_blob.length>242){
            System.out.println("Invalid data size (>242)");
            return null;
        }

        //data=[ key_encoding(1) | key_type(1) | key_size(2) | key_ACL(6) | key_blob(n)]
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_IMPORT_KEY;
        byte p1= key_nbr; 
        byte p2= 0x00;
        byte[] data= new byte[1+1+2+6+key_blob.length]; 
        byte le= 0x00;
        short base=0;

        data[base++]= key_encoding;
        data[base++]= key_type;
        data[base++]=(byte)(key_size>>8);//most significant byte
        data[base++]=(byte)(key_size & 0x00FF);//least significant byte
        System.arraycopy(key_ACL, 0, data, base, JCconstants.KEY_ACL_SIZE);
        base+=JCconstants.KEY_ACL_SIZE;
        System.arraycopy(key_blob, 0, data, base, key_blob.length);
        base+=key_blob.length;

        // import key command (data taken from imported object)
        System.out.println("cardImportKey");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        
        return response;
    }

    public byte[] cardGetPublicKeyFromPrivate(byte priv_key_nbr) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_GET_PUBLIC_FROM_PRIVATE;
        byte p1= priv_key_nbr; 
        byte p2= 0x00;
        byte[] data= null; 
        byte le= 0x00;
        
        // send apdu
        System.out.println("cardGetPublicKeyFromPrivate");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        
        return response;
    }
    
    public byte[] cardGenerateKeyPair( 
                    byte priv_key_nbr, byte pub_key_nbr, byte alg_type, short key_size, 
                    byte[] priv_key_ACL, byte[] pub_key_ACL, byte gen_opt, byte[] gen_opt_param) throws CardConnectorException{

        // to do: check ACL sizes ==6
        // to do: check bounds on key nbr
        // to do: check key size
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_GEN_KEYPAIR;
        byte p1= priv_key_nbr; 
        byte p2= pub_key_nbr;
        byte[] data= new byte[1+2+6+6+1+gen_opt_param.length]; 
        byte le= 0x00;
        short base=0;
        //key gen data
        data[base++]=alg_type;
        data[base++]=(byte)(key_size>>8);//most significant byte
        data[base++]=(byte)(key_size & 0x00FF);//least significant byte
        for (int i=0; i<JCconstants.KEY_ACL_SIZE; i++){
                data[base++]=priv_key_ACL[i]; 
        }
        for (int i=0; i<JCconstants.KEY_ACL_SIZE; i++){
                data[base++]=pub_key_ACL[i]; 
        }
        data[base++]=gen_opt;
        System.arraycopy(gen_opt_param, 0, data, base, gen_opt_param.length);
        base+=gen_opt_param.length;

        // send apdu
        System.out.println("cardGenKeyPair");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        return response;

    }

    public byte[] cardComputeSign(byte key_nbr, byte CM, byte CD, byte[] buffer, byte[] signature) throws CardConnectorException{

        // return either signature as byte array, or bool value as byte array
        // data is cut into chunks, each processed in a different APDU call
        int chunk= 160; // max APDU data=256 = chunk>=255-(1+2+2)-signature size
        int buffer_offset=0;
        int buffer_left=buffer.length;

        // CIPHER_INIT - no data processed
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_COMPUTE_SIGN;
        byte p1= key_nbr;
        byte p2= JCconstants.OP_INIT;
        byte[] data= new byte[3+2]; 
        byte le= 0x00;
        short base=0;
        data[base++]=(byte) CM; // cipher mode: elliptic curve or RSA: to check?
        data[base++]=(byte) CD; // cipher direction: sign or verify
        data[base++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
        data[base++]=(byte) 0; // size==0 for RSA sig in OP_INIT
        data[base++]=(byte) 0; // size!=0 for DES macing with IV

        // send apdu
        System.out.println("cardComputeSign - INIT");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        // CIPHER PROCESS/UPDATE (optionnal)
        while(buffer_left>chunk){

                //cla= JCconstants.CardEdge_CLA;
                //ins= INS_COMPUTE_CRYPT;
                //p1= key_nbr;
                p2= JCconstants.OP_PROCESS;
                data= new byte[1+2+chunk]; 
                base=0;
                data[base++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
                data[base++]=(byte) (chunk>>8); //msb
                data[base++]=(byte) (chunk&0xFF); //lsb
                System.arraycopy(buffer, buffer_offset, data, base, chunk);
                base+=chunk;
                buffer_offset+=chunk;
                buffer_left-=chunk;

                // send apdu
                System.out.println("cardComputeSign - PROCESS");
                System.out.println("APDU data >>>: " + toString(data));
                System.out.println("APDU datasize >>>: " + data.length);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                System.out.println("APDU <<<: "	+ toString(response));
        }		

        // CIPHER FINAL/SIGN (last chunk)
        if (CD == JCconstants.MODE_SIGN){
                chunk= buffer_left; //following while condition, buffer_left<=chunk
                System.out.println("chunk value= "	+ chunk);
                //cla= JCconstants.CardEdge_CLA;
                //ins= INS_COMPUTE_CRYPT;
                //p1= key_nbr;
                p2= JCconstants.OP_FINALIZE;
                data= new byte[1+2+chunk]; 
                base=0;
                data[base++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
                data[base++]=(byte) (chunk>>8); //msb
                data[base++]=(byte) (chunk&0xFF); //lsb
                System.arraycopy(buffer, buffer_offset, data, base, chunk);
                base+=chunk;
                buffer_offset+=chunk;
                buffer_left-=chunk;

                // send apdu
                System.out.println("cardComputeSign - FINALIZE");
                System.out.println("APDU >>>: "	+ toString(data));
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                System.out.println("APDU <<<: "	+ toString(response));
                //signature= new byte[response.length-2]; // datachunk is 1 short + data
                //System.arraycopy(response, 2, signature, 0, response.length-2);
                return response;
        }
        else { // MODE_VERIFY
                chunk= buffer_left; //following while condition, buffer_left<=chunk
                //cla= JCconstants.CardEdge_CLA;
                //ins= INS_COMPUTE_CRYPT;
                //p1= key_nbr;
                p2= JCconstants.OP_FINALIZE;
                short sign_length= (short)signature.length;
                data= new byte[1+2+chunk+2+sign_length]; //data+signature
                base=0;
                data[base++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
                data[base++]=(byte) (chunk>>8); //msb
                data[base++]=(byte) (chunk&0xFF); //lsb
                System.arraycopy(buffer, buffer_offset, data, base, chunk);
                base+=chunk;
                buffer_offset+=chunk;
                buffer_left-=chunk;
                data[base++]=(byte) (sign_length >> 8); //msb
                data[base++]=(byte) (sign_length & 0xFF); //lsb
                System.arraycopy(signature, 0, data, base, sign_length);
                base+=sign_length;

                // send apdu
                System.out.println("cardComputeVerify - FINALIZE");
                System.out.println("APDU >>>: "	+ toString(data));
                System.out.println("LE= " + le);//debug
                System.out.println("data length= " + data.length);//debug
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                System.out.println("APDU <<<: "	+ toString(response));			
        }

        return response;
    }	

    public byte[] cardComputeSha512(byte[] msg) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_COMPUTE_SHA512;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[msg.length]; 
        byte le= 64;
        short base=0;
        for (int i=0; i<msg.length; i++){
                data[base++]=msg[i]; 
        }

        System.out.println("cardComputeSha512");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        return response;
    }

    public byte[] cardComputeHmacSha512(byte[] key, byte[] msg) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_COMPUTE_HMACSHA512;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[key.length+msg.length+4]; 
        byte le= 64;
        short base=0;
        data[base++]=(byte) (key.length>>8); //msb
        data[base++]=(byte) (key.length&0xFF); //lsb
        for (int i=0; i<key.length; i++){
                data[base++]=key[i]; 
        }
        data[base++]=(byte) (msg.length>>8); //msb
        data[base++]=(byte) (msg.length&0xFF); //lsb
        for (int i=0; i<msg.length; i++){
                data[base++]=msg[i]; 
        }
        System.out.println("cardComputeHmacSha512");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        return response;
    }

    public byte[] cardCreatePIN(byte pin_nbr, byte pin_tries, byte[] pin, byte[] ublk) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_CREATE_PIN;
        byte p1= pin_nbr;
        byte p2= pin_tries;
        byte[] data= new byte[1+pin.length+1+ublk.length]; 
        byte le= 0x00;
        short base=0;
        data[base++]=(byte)pin.length;
        for (int i=0; i<pin.length; i++){
                data[base++]=pin[i]; 
        }
        data[base++]=(byte)ublk.length;
        for (int i=0; i<ublk.length; i++){
                data[base++]=ublk[i]; 
        }
        // send apdu
        System.out.println("cardCreatePIN");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        return response;
    }

    public byte[] cardVerifyPIN(byte pin_nbr, byte[] pin) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_VERIFY_PIN;
        byte p1= pin_nbr;
        byte p2= 0x00;
        byte[] data= new byte[pin.length]; 
        byte le= 0x00;
        short base=0;
        for (int i=0; i<pin.length; i++){
                data[base++]=pin[i]; 
        }
        // send apdu
        System.out.println("cardVerifyPIN");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        return response;
}

    public byte[] cardChangePIN(byte pin_nbr, byte[] old_pin, byte[] new_pin) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_CHANGE_PIN;
        byte p1= pin_nbr;
        byte p2= 0x00;
        byte[] data= new byte[1+old_pin.length+1+new_pin.length]; 
        byte le= 0x00;
        short base=0;
        data[base++]=(byte)old_pin.length;
        for (int i=0; i<old_pin.length; i++){
                data[base++]=old_pin[i]; 
        }
        data[base++]=(byte)new_pin.length;
        for (int i=0; i<new_pin.length; i++){
                data[base++]=new_pin[i]; 
        }
        // send apdu
        System.out.println("cardChangePIN");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        System.out.println("SW12 <<<: "	+ Integer.toHexString(response[response.length-2]&0xFF) + " " + Integer.toHexString(response[response.length-1]&0xFF) );		

        return response;
    }

    public byte[] cardUnblockPIN(byte pin_nbr, byte[] ublk) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_UNBLOCK_PIN;
        byte p1= pin_nbr;
        byte p2= 0x00;
        byte[] data= new byte[ublk.length]; 
        byte le= 0x00;
        short base=0;
        for (int i=0; i<ublk.length; i++){
                data[base++]=ublk[i]; 
        }
        // send apdu
        System.out.println("cardUnblockPIN");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        System.out.println("SW12 <<<: "	+ Integer.toHexString(response[response.length-2]&0xFF) + " " + Integer.toHexString(response[response.length-1]&0xFF) );				

        return response;
    }

    public byte[] cardLogoutAll() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_LOGOUT_ALL;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= null;
        byte le= 0x00;
        
        // send apdu
        System.out.println("cardLogoutAll");
        System.out.println("APDU >>>: "	+ toString(data));
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));
        System.out.println("SW12 <<<: "	+ Integer.toHexString(response[response.length-2]&0xFF) + " " + Integer.toHexString(response[response.length-1]&0xFF) );				

        return response;
    }
        
    public byte[] cardListPINs() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_LIST_PINS;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data=null;
        byte le= 0x02;

        // send apdu
        System.out.println("cardCreatePIN");
        System.out.println("APDU >>>: ");
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("Data <<<: "	+ response[0] +  response[0]);
        System.out.println("APDU <<<: "	+ toString(response));
        System.out.println("SW12 <<<: "	+ Integer.toHexString(response[response.length-2]&0xFF) + " " + Integer.toHexString(response[response.length-1]&0xFF) );		

        return response;
    }

    public byte[] cardListKeys() throws CardConnectorException{

        byte seq_opt=0x00;
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_LIST_KEYS;
        byte p1= seq_opt;
        byte p2= 0x00;
        byte[] data= null;
        byte le=0x0B; // 11 bytes expected?

        int datasize= 0;
        byte[] response;
        System.out.println("cardListKeys");
        System.out.println("APDU >>>: ");

        do{
            p1=seq_opt;

            response= exchangeAPDU(cla, ins, p1, p2, data, le);
            System.out.println("APDU <<<: "	+ toString(response));
            // key info
            datasize= response.length;
            short base=0; 
            if (datasize>0){// datasize==11 
                byte key_nbr= response[base++];
                byte key_type= response[base++];
                byte key_partner= response[base++];
                short key_size= (short) (((short)response[base++])<<8 +  ((short)response[base++])); // to check order?
                int[] key_ACL= new int[JCconstants.KEY_ACL_SIZE];
                for (short i= 0; i<JCconstants.KEY_ACL_SIZE; i++){
                        key_ACL[i]=(int)response[base++];
                }
                System.out.println("datasize(11?) <<<: " + datasize );
                System.out.println("key nbr <<<: " + (int)key_nbr );
                System.out.println("key type <<<: " + key_type );
                System.out.println("key partner <<<: " + (int)key_partner );
                System.out.println("key size <<<: " + (int)key_size );
                System.out.println("key ACL RWU <<<: " + 
                        Integer.toBinaryString( key_ACL[1]+(key_ACL[0]<<8) ) +" "+
                        Integer.toBinaryString( key_ACL[3]+(key_ACL[2]<<8) ) +" "+
                        Integer.toBinaryString( key_ACL[5]+(key_ACL[4]<<8) )); // to check order?
            }

            // "get next entry" option
            seq_opt=0x01;
        }
        while (datasize>0); // while there are key entries

        return response;
    }

    public byte[] cardGetStatus() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_GET_STATUS;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= null;
        byte le= 0x10; // 16 bytes expected? 

        // send apdu
        System.out.println("cardGetStatus");
        System.out.println("APDU >>>: ");
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        System.out.println("APDU <<<: "	+ toString(response));

        // key info
        int datasize= response.length;
        short base=0; 
        // process response (6 bytes - 2 long - 1 short)
        if (datasize>0){// datasize ==15// 16?
            byte CE_version_maj= response[base++];
            byte CE_version_min= response[base++];
            byte soft_version_maj= response[base++];
            byte soft_version_min= response[base++];
            int sec_mem_tot= (response[base++]<<8)+response[base++];
            int mem_tot= (response[base++]<<8)+response[base++];
            int sec_mem_free= (response[base++]<<8)+response[base++];
            int mem_free= (response[base++]<<8)+response[base++];
            byte PINs_nbr= response[base++];
            byte keys_nbr= response[base++];
            short logged_in= (short) ((response[base++]<<8)+response[base++]);
            System.out.println("	datasize(15?) <<<: " + datasize );
            System.out.println("	card Edge major version: "+CE_version_maj);
            System.out.println("	card Edge minor version: "+CE_version_min);
            System.out.println("	Applet major version: "+soft_version_maj);
            System.out.println("	Applet minor version: "+soft_version_min);
            System.out.println("	Total secure memory: "+ sec_mem_tot);
            System.out.println("	Total object memory: "+ mem_tot);
            System.out.println("	Free secure memory: "+ sec_mem_free);
            System.out.println("	Free object memory: "+ mem_free);
            System.out.println("	Number of used PIN: "+ PINs_nbr);
            System.out.println("	Number of used keys: "+ keys_nbr);
            System.out.println("	Currently logged in identities: "+ logged_in + " " + Integer.toBinaryString(logged_in));
        }		
        
        return response;
    }
    
}
