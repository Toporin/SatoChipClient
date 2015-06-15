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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
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
   
    private final static Logger logger = Logger.getLogger(CardConnector.class.getName());
    
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
        //default log data to console
        this(new ConsoleHandler(), Level.INFO);
    }
    
    public CardConnector(Handler handle, Level level){
        
        //default log data
        logger.addHandler(handle);
        logger.setLevel(level);
        
        terminalfactory = TerminalFactory.getDefault();
        try {
            listterminal = terminalfactory.terminals().list();
            logger.log(Level.INFO, "Terminals: {0}", listterminal);
            if (listterminal.isEmpty()) {
                    logger.log(Level.SEVERE, "No terminals found.");
                    return;
            }
            // Get the first terminal in the list
            terminal = listterminal.get(0);
            // Establish connection with the card using "T=0","T=1","T=CL" or "*"
            card = terminal.connect("*");	
        } catch (CardException e) {
            e.printStackTrace();
        }

        ATR = card.getATR().getBytes();
        channel = card.getBasicChannel();
    }
    
    public void disconnect() throws CardException{
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

        //logger.log(Level.FINE,bytes);//debug
        for (int i = 0; i < bytes.length; i++) {
                cTmp[0] = hexChars.charAt((bytes[i] & 0xF0) >>> 4);
                cTmp[1] = hexChars.charAt(bytes[i] & 0x0F);
                sbTmp.append(cTmp);
        }
        //logger.log(Level.FINE,sbTmp.toString());//debug

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
        sw12= (short)r.getSW();
        if (sw12!=JCconstants.SW_OK){
            logger.log(Level.WARNING, "SW12 <<<: {0}", Integer.toHexString(sw12&0xFFFF));
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
    public void logCommandAPDU(String name, byte cla, byte ins, byte p1, byte p2, byte[] data, byte le){
        logger.log(
                Level.FINE, 
                name+"\n\t APDU>> cla:{0} ins:{1} p1:{2} p2:{3} le:{4} data:{5}",
                new Object[]{
                    Integer.toHexString(cla & 0xFF), 
                    Integer.toHexString(ins & 0xFF), 
                    Integer.toHexString(p1 & 0xFF), 
                    Integer.toHexString(p2 & 0xFF), 
                    Integer.toHexString(le & 0xFF), 
                    toString(data)}
        );
    }
    public void logResponseAPDU(byte[] response){
        if (response!=null && response.length>0)
            logger.log(Level.FINE, "\t APDU<< {0}", toString(response));
    }
    
//    /* convert a DER encoded signature to compact 65-byte format
//        input is hex string in DER format
//        output is hex string in compact 65-byteformat
//        http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
//        https://bitcointalk.org/index.php?topic=215205.0            
//    */
//    public static byte[] toCompactSig(byte[] sigin, int recid, boolean compressed) {
//
//        byte[] sigout= new byte[65];
//        // parse input 
//        byte first= sigin[0];
//        if (first!= 0x30){
//            System.out.println("Wrong first byte!");
//            return new byte[0];
//        }
//        byte lt= sigin[1];
//        byte check= sigin[2];
//        if (check!= 0x02){
//            System.out.println("Check byte should be 0x02");
//            return new byte[0];
//        }
//        // extract r
//        byte lr= sigin[3];
//        for (int i= 0; i<=31; i++){
//            byte tmp= sigin[4+lr-1-i];
//            if (lr>=(i+1)) {
//                sigout[32-i]= tmp;
//            } else{ 
//                sigout[32-i]=0;  
//            }
//        }
//        // extract s
//        check= sigin[4+lr];
//        if (check!= 0x02){
//            System.out.println("Second check byte should be 0x02");
//            return new byte[0];
//        }
//        byte ls= sigin[5+lr];
//        if (lt != (lr+ls+4)){
//            System.out.println("Wrong lt value");
//            return new byte[0];
//        }
//        for (int i= 0; i<=31; i++){
//            byte tmp= sigin[5+lr+ls-i];
//            if (ls>=(i+1)) {
//                sigout[64-i]= tmp;
//            } else{ 
//                sigout[32-i]=0;  
//            }
//        }
//
//        // 1 byte header
//        if (recid>3 || recid<0){
//            System.out.println("Wrong recid value");
//            return new byte[0];
//        }
//        if (compressed){
//            sigout[0]= (byte)(27 + recid + 4 );
//        }else{
//            sigout[0]= (byte)(27 + recid);                
//        }
//
//        return sigout;
//    }
    
    // SELECT Command
    public byte[] cardSelect(byte[] AID) throws CardConnectorException {
        // See GlobalPlatform Card Specification (e.g. 2.2, section 11.9)
        byte cla= 0x00;
        byte ins= (byte)0xA4;
        byte p1= 0x04;
        byte p2=0x00;
        byte le= 0x00;
        
        byte[] response= exchangeAPDU(cla, ins, p1, p2, AID, le);
        return response;
    }

    /**
     * Card Setup (todo: clarify API)
     * 
     * **/
    public byte[] cardSetup( 
                    byte pin_tries_0, byte ublk_tries_0, 
                    byte[] pin_0, byte[] ublk_0,
                    byte pin_tries_1, byte ublk_tries_1, 
                    byte[] pin_1, byte[] ublk_1,
                    short memsize, short memsize2, 
                    byte create_object_ACL, byte create_key_ACL, byte create_pin_ACL,
                    short option_flags,
                    byte[] hmacsha160_key, long amount_limit) throws CardConnectorException {

        // to do: check pin sizes < 256
        byte[] pin={0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30}; // default pin

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SETUP;
        byte p1= 0;
        byte p2=0;
        // data=[pin_length(1) | pin | 
        //       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 | 
        //       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 | 
        //       memsize(2) | memsize2(2) | ACL(3) |
        //       option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        int optionsize= ((option_flags==0)?0:2) + (((option_flags&0x8000)==0x8000)?28:0);
        int datasize= 16+pin.length+pin_0.length+pin_1.length+ublk_0.length+ublk_1.length+optionsize;
        byte[] data= new byte[datasize]; 
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
        // 2bytes 
        data[base++]= (byte)(memsize>>8);
        data[base++]= (byte)(memsize&0x00ff);
        // mem_size
        data[base++]= (byte)(memsize2>>8);
        data[base++]= (byte)(memsize2&0x00ff);
        // acl
        data[base++]= create_object_ACL;
        data[base++]= create_key_ACL;
        data[base++]= create_pin_ACL;
        // option_flags
        if (option_flags!=0){
            data[base++]= (byte)(option_flags>>8);
            data[base++]= (byte)(option_flags&0x00ff);
            // hmacsha1_key
            System.arraycopy(hmacsha160_key, 0, data, base, 20);
            base+=20;
            // amount_limit
            for (int i=56; i>=0; i-=8){
                data[base++]=(byte)((amount_limit>>i)&0xff);
            }
        }
        // send apdu (contains sensitive data!)
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
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
        
        return cardSetup( 
                    pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                    pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                    memsize, memsize2, create_object_ACL, create_key_ACL, create_pin_ACL,
                    (short)0, null, 0);     
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

        // send apdu (contains sensitive data!)
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
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
        logCommandAPDU("cardBip32GetAuthentiKey", cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        byte[] response=null;
        try{
            // send apdu
            logCommandAPDU("GetBip32ExtendedKey",cla, ins, p1, p2, data, le);        
            response = exchangeAPDU(cla, ins, p1, p2, data, le);
            logResponseAPDU(response);
        }
        catch(CardConnectorException ex){
            // if there is no more memory available, erase cache...
            if (ex.getIns()==JCconstants.INS_BIP32_GET_EXTENDED_KEY && ex.getSW12()==JCconstants.SW_NO_MEMORY_LEFT){
                logger.log(Level.INFO,"GetBip32ExtendedKey - out of memory: reset internal memory");
                logCommandAPDU("GetBip32ExtendedKey-reset",cla, ins, p1, p2, data, le);        
                response = exchangeAPDU(cla, ins, p1, (byte)0xFF, data, le);
                logResponseAPDU(response);
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
        logCommandAPDU("cardSignBIP32Message - INIT",cla, ins, p1, p2, data, le);        
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        
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
                logCommandAPDU("cardSignBIP32Message - PROCESS",cla, ins, p1, p2, data, le);        
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                logResponseAPDU(response);
        }		

        // CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left; //following while condition, buffer_left<=chunk
        logger.log(Level.FINE, "chunk value= {0}", chunk);
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
        logCommandAPDU("cardSignBIP32Message-FINALIZE",cla, ins, p1, p2, data, le);        
        response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        logCommandAPDU("SignShortBip32Message",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
                logger.log(Level.WARNING,"Error during parsing");
                return null;
            }
            data= TransactionParser.getDataChunk();
            digestFull.update(data, 0, data.length);

            // log state & send apdu
            if (result== TransactionParser.RESULT_FINISHED){
                le= 52; // [nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8) | hash(32) | sig?] 
                logCommandAPDU("cardParseTransaction-FINISH",cla, ins, p1, p2, data, le);
            }
            else if (p1== JCconstants.OP_INIT)
                logCommandAPDU("cardParseTransaction-INIT",cla, ins, p1, p2, data, le);
            else if (p1== JCconstants.OP_PROCESS)
                logCommandAPDU("cardParseTransaction-PROCESS",cla, ins, p1, p2, data, le);
            response= exchangeAPDU(cla, ins, p1, p2, data, le);
            logResponseAPDU(response);
            
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

    public byte[] cardParseTx(byte[] transaction) throws CardConnectorException{
            
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_PARSE_TRANSACTION;
        byte p1= JCconstants.OP_INIT;
        byte p2= 0x00;
        byte[] data; 
        byte le= 0x00; 
        byte[] response=null;
        
        // init transaction data and context
        TxParser txparser= new TxParser(transaction);
        while(!txparser.isParsed()){
            
            data= txparser.parseTransaction();
            
            // log state & send apdu
            if (txparser.isParsed()){
                le= 86; // [hash(32) | sigsize(2) | sig | nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8)] 
                logCommandAPDU("cardParseTransaction - FINISH",cla, ins, p1, p2, data, le);
            }
            else if (p1== JCconstants.OP_INIT)
                logCommandAPDU("cardParseTransaction-INIT",cla, ins, p1, p2, data, le);    
            else if (p1== JCconstants.OP_PROCESS)
                logCommandAPDU("cardParseTransaction - PROCESS",cla, ins, p1, p2, data, le); 
            response= exchangeAPDU(cla, ins, p1, p2, data, le);
            logResponseAPDU(response);
            
            // switch to process mode after initial call to parse
            p1= JCconstants.OP_PROCESS; 
        }
        logger.log(Level.INFO, "Single transaction hash:{0}", toString(txparser.getTxHash()));
        logger.log(Level.INFO, "Double transaction hash:{0}", toString(txparser.getTxDoubleHash()));
        
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
        
        logCommandAPDU("cardSignTransaction",cla, ins, p1, p2, data, le);
        response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    public byte[] cardImportKey(
            byte key_nbr, byte[] key_ACL, 
            byte key_encoding, byte key_type, short key_size, byte[] key_blob) throws CardConnectorException{

        if (key_blob.length>242){
            logger.log(Level.WARNING,"Invalid data size (>242)");
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
        logCommandAPDU("cardImportKey",cla, ins, p1, p2, null, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        logCommandAPDU("cardGetPublicKeyFromPrivate", cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        logCommandAPDU("cardGenKeyPair",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }

    public byte[] cardGenerateSymmetricKey( 
                    byte keynbr, byte alg_type, short key_size, byte[] key_ACL) throws CardConnectorException{

        // to do: check ACL sizes ==6
        // to do: check bounds on key nbr
        // to do: check key size
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_GEN_KEYSYM;
        byte p1= keynbr; 
        byte p2= 0x00;
        byte[] data= new byte[1+2+6]; 
        byte le= 0x00;
        short base=0;
        //key gen data
        data[base++]=alg_type;
        data[base++]=(byte)(key_size>>8);//most significant byte
        data[base++]=(byte)(key_size & 0x00FF);//least significant byte
        for (int i=0; i<JCconstants.KEY_ACL_SIZE; i++){
                data[base++]=key_ACL[i]; 
        }
        
        // send apdu
        logCommandAPDU("cardGenSymmetricKey",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        logCommandAPDU("cardComputeSign-INIT",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        
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
                logCommandAPDU("cardComputeSign-PROCESS",cla, ins, p1, p2, data, le);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                logResponseAPDU(response);
        }		

        // CIPHER FINAL/SIGN (last chunk)
        if (CD == JCconstants.MODE_SIGN){
                chunk= buffer_left; //following while condition, buffer_left<=chunk
                logger.log(Level.FINE, "chunk value= {0}", chunk);
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
                logCommandAPDU("cardComputeSign-FINALIZE",cla, ins, p1, p2, data, le);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                logResponseAPDU(response);
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
                logCommandAPDU("cardComputeVerify-FINALIZE",cla, ins, p1, p2, data, le);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                logResponseAPDU(response);
        }

        return response;
    }	

    public byte[] cardComputeCrypt(byte key_nbr, byte CM, byte CD, byte[] buffer) throws CardConnectorException{
        
        // buffer may contain IV nonce (in case of decryption operation in CBC mode for DES/AES)
        // output data may contain IV nonce (in case of encryption operation in CBC mode for DES/AES)
        // buffer will be padded in case of encryption mode for DES/AES
        // output will be unpadded in case of decryption mode for DES/AES
        int blocksize= 0;
        byte algtype=0;
        if (CM==JCconstants.ALG_DES_CBC_NOPAD || 
                CM==JCconstants.ALG_DES_ECB_NOPAD){
            blocksize=8;
            algtype= JCconstants.TYPE_DES;
        }
        else if (CM==JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD ||
                CM==JCconstants.ALG_AES_BLOCK_128_ECB_NOPAD){
            blocksize=16;
            algtype= JCconstants.TYPE_AES;
        }
        
        // padding
        if (CD==JCconstants.MODE_ENCRYPT && 
                (algtype==JCconstants.TYPE_DES || 
                algtype==JCconstants.TYPE_AES)){
            int paddedlength= (buffer.length/blocksize)*blocksize+blocksize;
            int paddinglength= paddedlength-buffer.length;
            byte[] paddedbuffer= new byte[paddedlength];
            Arrays.fill(paddedbuffer, (byte)paddinglength);
            System.arraycopy(buffer, 0, paddedbuffer, 0, buffer.length);
//            logger.log(Level.FINE,"PADDING:");
//            logger.log(Level.FINE,"length:"+buffer.length);
//            logger.log(Level.FINE,"paddedlength:"+paddedlength);
//            logger.log(Level.FINE,"paddinglength:"+paddinglength);
//            logger.log(Level.FINE,"paddedbuffer:"+toString(paddedbuffer));
            buffer=paddedbuffer;
        }
        
        // data is cut into chunks, each processed in a different APDU call
        int chunk= 128; // max APDU data=256 = chunk>=255-(1+2+2)-signature size
        int bufferOffset=0;
        int bufferLeft=buffer.length;
        
        // CIPHER_INIT - no data processed
        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_COMPUTE_CRYPT;
        byte p1= key_nbr;
        byte p2= JCconstants.OP_INIT;
        byte le= 0x00;
        byte[] data;
        int dataOffset=0;
        int IVlength=0;
        if (CD==JCconstants.MODE_DECRYPT){
            if (CM==JCconstants.ALG_DES_CBC_NOPAD)
                IVlength=8;
            else if (CM==JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD)
                IVlength=16;
        }
        data= new byte[3+2+IVlength]; 
        data[dataOffset++]=(byte) CM; // cipher mode: elliptic curve or RSA: to check?
        data[dataOffset++]=(byte) CD; // cipher direction: sign or verify
        data[dataOffset++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
        data[dataOffset++]=(byte) 0;
        data[dataOffset++]=(byte) IVlength;
        System.arraycopy(buffer, 0, data, dataOffset, IVlength);
        dataOffset+=IVlength;
        bufferOffset+=IVlength;
        bufferLeft-=IVlength;

        // send apdu
        logCommandAPDU("cardComputeCrypt-INIT",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        // recover IV from card (for CD=ENCRYPT && CM=CBC)
        ByteArrayOutputStream bos= new ByteArrayOutputStream(buffer.length+IVlength);
        bos.write(response,0,response.length);
        logResponseAPDU(response);
        
        // CIPHER PROCESS/UPDATE (optionnal)
        while(bufferLeft>chunk){
                //cla= JCconstants.CardEdge_CLA;
                //ins= INS_COMPUTE_CRYPT;
                //p1= key_nbr;
                p2= JCconstants.OP_PROCESS;
                data= new byte[1+2+chunk]; 
                dataOffset=0;
                data[dataOffset++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
                data[dataOffset++]=(byte) (chunk>>8); //msb
                data[dataOffset++]=(byte) (chunk&0xFF); //lsb
                System.arraycopy(buffer, bufferOffset, data, dataOffset, chunk);
                dataOffset+=chunk;
                bufferOffset+=chunk;
                bufferLeft-=chunk;

                // send apdu
                logCommandAPDU("cardComputeCrypt - PROCESS",cla, ins, p1, p2, data, le);
                response= exchangeAPDU(cla, ins, p1, p2, data, le);
                logResponseAPDU(response);
        
                // update output
                bos.write(response,2,response.length-2);                               
        }		

        // CIPHER FINAL (last chunk)
        chunk= bufferLeft; //following while condition, buffer_left<=chunk
        logger.log(Level.FINE, "chunk value= {0}", chunk);
        //cla= JCconstants.CardEdge_CLA;
        //ins= INS_COMPUTE_CRYPT;
        //p1= key_nbr;
        p2= JCconstants.OP_FINALIZE;
        data= new byte[1+2+chunk]; 
        dataOffset=0;
        data[dataOffset++]=(byte) JCconstants.DL_APDU; // data location: in apdu	
        data[dataOffset++]=(byte) (chunk>>8); //msb
        data[dataOffset++]=(byte) (chunk&0xFF); //lsb
        System.arraycopy(buffer, bufferOffset, data, dataOffset, chunk);
        dataOffset+=chunk;
        bufferOffset+=chunk;
        bufferLeft-=chunk;

        // send apdu
        logCommandAPDU("cardComputeCrypt-FINALIZE",cla, ins, p1, p2, data, le);
        response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        
        // update output
        bos.write(response,2,response.length-2);                               
        byte[] output;
        
        // unpadding
        if (CD==JCconstants.MODE_DECRYPT && 
                (algtype==JCconstants.TYPE_DES || 
                algtype==JCconstants.TYPE_AES)){
            byte[] paddedoutput= bos.toByteArray();
            int paddinglength= paddedoutput[paddedoutput.length-1];
            output= new byte[paddedoutput.length-paddinglength];
            System.arraycopy(paddedoutput, 0, output, 0, output.length);
//            logger.log(Level.FINE,"UNPADDING");
//            logger.log(Level.FINE,"paddedlength:"+paddedoutput.length);
//            logger.log(Level.FINE,"paddinglength:"+paddinglength);
//            logger.log(Level.FINE,"paddedoutput:"+toString(paddedoutput));
        }
        else{
            output= bos.toByteArray();
        }
        
        return output;
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

        logCommandAPDU("cardComputeSha512",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    public byte[] cardComputeHmac(byte sha, byte[] key, byte[] msg) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_COMPUTE_HMACSHA512;
        byte p1= sha;
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
        
        logCommandAPDU("cardComputeHmac",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    /* PIN Management*/
    
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
        logCommandAPDU("cardCreatPIN",cla, ins, p1, p2, null, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
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
        logCommandAPDU("cardVerifyPIN",cla, ins, p1, p2, null, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
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
        logCommandAPDU("cardChangePIN",cla, ins, p1, p2, null, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        
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
        logCommandAPDU("cardUnblockPIN",cla, ins, p1, p2, null, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
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
        logCommandAPDU("cardLogoutAll",cla, ins, p1, p2, data, le);
        byte[] response= exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
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
        logger.log(Level.FINE,"cardListPIN");
        logger.log(Level.FINE,"APDU >>>: ");
        byte[] response;
        response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }

    public byte[] cardListKeys() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_LIST_KEYS;
        byte p1= 0x00; // "get first entry" option
        byte p2= 0x00;
        byte[] data= null;
        byte le=0x0B; // 11 bytes expected?

        int datasize= 0;
        byte[] response;
        ByteArrayOutputStream baos= new ByteArrayOutputStream(200); 
        
        do{
            response= exchangeAPDU(cla, ins, p1, p2, data, le);
            baos.write(response, 0, response.length);
            
            p1=0x01; // "get next entry" option
        }
        while (datasize>0); // while there are key entries

        return baos.toByteArray();
    }
    
    /**
    * This function creates an object that will be identified by the provided object ID.
    * The objectâ€™s space and name will be allocated until deleted using MSCDeleteObject.
    * The object will be allocated upon the card's memory heap. 
    * Object creation is only allowed if the object ID is available and logged in
    * identity(-ies) have sufficient privileges to create objects.
    *  
    * ins: 0x5A
    * p1: 0x00
    * p2: 0x00
    * data: [object_id(4b) | object_size(4b) | object_ACL(6b)] 
    * 		where ACL is Read-Write-Delete
    * return: none
    */
    public byte[] cardCreateObject(int objId, int objSize, byte[] objACL) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_CREATE_OBJ;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[14];
        byte le= 0x00; 
        
        int offset=0;
        data[offset++]= (byte)((objId>>>24) & 0xff);
        data[offset++]= (byte)((objId>>>16) & 0xff);
        data[offset++]= (byte)((objId>>>8) & 0xff);
        data[offset++]= (byte)((objId) & 0xff);
        data[offset++]= (byte)((objSize>>>24) & 0xff);
        data[offset++]= (byte)((objSize>>>16) & 0xff);
        data[offset++]= (byte)((objSize>>>8) & 0xff);
        data[offset++]= (byte)((objSize) & 0xff);
        System.arraycopy(objACL, 0, data, 8, JCconstants.KEY_ACL_SIZE);
        
        // send apdu
        logCommandAPDU("cardCreateObject",cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    /**
    * This function deletes the object identified by the provided object ID. The objectâ€™s
    * space and name will be removed from the heap and made available for other objects.
    * The zero flag denotes whether the objectâ€™s memory should be zeroed after
    * deletion. This kind of deletion is recommended if object was storing sensitive data.
    *   
    * ins: 0x52
    * p1: 0x00
    * p2: 0x00 or 0x01 for secure erasure 
    * data: [object_id(4b)] 
    * return: none
    */
    public byte[] cardDeleteObject(int objId, byte secureErasure) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_DELETE_OBJ;
        byte p1= 0x00;
        byte p2= secureErasure;
        byte[] data= new byte[4];
        byte le= 0x00; 
        
        int offset=0;
        data[offset++]= (byte)((objId>>>24) & 0xff);
        data[offset++]= (byte)((objId>>>16) & 0xff);
        data[offset++]= (byte)((objId>>>8) & 0xff);
        data[offset++]= (byte)((objId) & 0xff);
        
        // send apdu
        logCommandAPDU("cardDeleteObject",cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    /**
    * This function (over-)writes data to an object that has been previously created with
    * CreateObject. Provided Object Data is stored starting from the byte specified
    * by the Offset parameter. The size of provided object data must be exactly (Data
    * Length â€“ 8) bytes. Provided offset value plus the size of provided Object Data
    * must not exceed object size. 
    * Up to 246 bytes can be transferred with a single APDU. If more bytes need to be
    * transferred, then multiple WriteObject commands must be used with different offsets.
    * 
    * ins: 0x54
    * p1: 0x00
    * p2: 0x00 
    * data: [object_id(4b) | object_offset(4b) | data_size(1b) | data] 
    * return: none
    */
    public byte[] cardWriteObject(int objId, byte[] objData) throws CardConnectorException{

        int objOffset=0;
        int objRemaining= objData.length;
        int chunkSize;
        byte[] response=null;
        
        while(objRemaining>0){
            chunkSize=(objRemaining>160)?160:objRemaining;
            response=cardWriteObject(objId, objData, objOffset, chunkSize);
            objOffset+=chunkSize;
            objRemaining-=chunkSize;
        }
        
        return response;
    }

    public byte[] cardWriteObject(int objId, byte[] objData, int objOffset, int objLength) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_WRITE_OBJ;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[4+4+1+objLength];
        byte le= 0x00; 
        
        int offset=0;
        data[offset++]= (byte)((objId>>>24) & 0xff);
        data[offset++]= (byte)((objId>>>16) & 0xff);
        data[offset++]= (byte)((objId>>>8) & 0xff);
        data[offset++]= (byte)((objId) & 0xff);
        data[offset++]= (byte)((objOffset>>>24) & 0xff);
        data[offset++]= (byte)((objOffset>>>16) & 0xff);
        data[offset++]= (byte)((objOffset>>>8) & 0xff);
        data[offset++]= (byte)((objOffset) & 0xff);
        data[offset++]= (byte) objLength;
        System.arraycopy(objData, objOffset, data, offset, objLength);
        
        // send apdu
        logCommandAPDU("cardWriteObject-offset",cla, ins, p1, p2, null, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    /**
    * This function reads data from an object that has been previously created with 
    * MSCCreateObject. Object data is read starting from the byte specified by the
    * Offset parameter. Up to 255 bytes can be transferred with a single APDU. 
    * If more bytes need to be transferred, then multiple ReadObject commands must 
    * be used with different offsets. 
    * Object data will be effectively read only if logged in identity(ies) have 
    * sufficient privileges for the operation, according to the objectâ€™s ACL.
    *   
    * ins: 0x56
    * p1: 0x00
    * p2: 0x00 
    * data: [object_id(4b) | object_offset(4b) | chunk_length(1b)] 
    * return: [object_data(chunk_length)]
    */
    public byte[] cardReadObject(int objId) throws CardConnectorException{

        int objOffset=0;
        int objRemaining= cardGetObjectSize(objId);
        int chunkSize;
        byte[] response=new byte[objRemaining];
        byte[] responseChunk;
        
        while(objRemaining>0){
            chunkSize=(objRemaining>160)?160:objRemaining;
            responseChunk=cardReadObject(objId, objOffset, chunkSize);
            if (responseChunk.length!=chunkSize){
                throw new CardConnectorException("CardException when reading object "+objId
                        +" at offset "+objOffset
                        +" chunksize expected "+chunkSize
                        +" chunksize receveid "+responseChunk.length , null, null); 
            }
            System.arraycopy(responseChunk, 0, response, objOffset, chunkSize);
            objOffset+=chunkSize;
            objRemaining-=chunkSize;
        }
        
        return response;
    }    
    public byte[] cardReadObject(int objId, int objOffset, int objLength) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_READ_OBJ;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[4+4+1];
        byte le= 0x00; 
        
        int offset=0;
        data[offset++]= (byte)((objId>>>24) & 0xff);
        data[offset++]= (byte)((objId>>>16) & 0xff);
        data[offset++]= (byte)((objId>>>8) & 0xff);
        data[offset++]= (byte)((objId) & 0xff);
        data[offset++]= (byte)((objOffset>>>24) & 0xff);
        data[offset++]= (byte)((objOffset>>>16) & 0xff);
        data[offset++]= (byte)((objOffset>>>8) & 0xff);
        data[offset++]= (byte)((objOffset) & 0xff);
        data[offset++]= (byte) objLength;
        
        // send apdu
        logCommandAPDU("cardReadObject-offset",cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
    /**
    * This function returns the size of an object that has been previously created with 
    * MSCCreateObject.  
    *   
    * ins: 0x57
    * p1: 0x00
    * p2: 0x00 
    * data: [object_id(4b)] 
    * return: [object_size(2b)]
    */
    public short cardGetObjectSize(int objId) throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_SIZE_OBJ;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= new byte[4];
        byte le= 0x02; 
        
        int offset=0;
        data[offset++]= (byte)((objId>>>24) & 0xff);
        data[offset++]= (byte)((objId>>>16) & 0xff);
        data[offset++]= (byte)((objId>>>8) & 0xff);
        data[offset++]= (byte)((objId) & 0xff);
        
        // send apdu
        logCommandAPDU("cardGetObjectSize",cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        short objSize= (short) (((response[0]&0xff)<<8)+(response[1]&0xff));
        return objSize;
    }
    
    public byte[] cardGetStatus() throws CardConnectorException{

        byte cla= JCconstants.CardEdge_CLA;
        byte ins= JCconstants.INS_GET_STATUS;
        byte p1= 0x00;
        byte p2= 0x00;
        byte[] data= null;
        byte le= 0x10; // 16 bytes expected? 

        // send apdu
        logCommandAPDU("cardGetStatus",cla, ins, p1, p2, data, le);
        byte[] response = exchangeAPDU(cla, ins, p1, p2, data, le);
        logResponseAPDU(response);
        return response;
    }
    
}
