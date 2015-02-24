/*
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Java Card implementation
*   (c) 2013 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Affero General Public License as
*   published by the Free Software Foundation, either version 3 of the
*   License, or (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Affero General Public License for more details.
*
*   You should have received a copy of the GNU Affero General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************   
*/    

package org.satochip.satochipclient;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Bitcoin transaction parsing
 * @author BTChip
 *
 */
public class TransactionParser {
    
//    public static void init() {
//        h = new int[2];
//        datachunk= new byte[MAX_CHUNK_SIZE];
//        d= new  int[2];
//        ctx = new byte[TX_CONTEXT_SIZE];
//        digestFull = new SHA256Digest();
//        
//        //ctxP = new byte[P_TX_CONTEXT_SIZE]; // removed
//        //digestAuthorization = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false); // removed
//    }
    
//    public static void clear() {
//        Util.arrayFillNonAtomic(ctx, (short)0, (short)ctx.length, (byte)0x00);
//        // removed
//        //if (ctxP[P_TX_Z_USED] == TRUE) {
//        //    ctxP[P_TX_Z_USED] = FALSE;
//        //}
//    }
    
    private static void consumeTransaction(byte[] buffer, short length) {
        
        System.arraycopy(buffer, h[CURRENT], datachunk, d[CURRENT], length);
        //if ((ctx[TX_B_HASH_OPTION] & HASH_FULL) != 0) {
            digestFull.update(buffer, h[CURRENT], length);
        //}
        // removed
        //if ((ctx[TX_B_HASH_OPTION] & HASH_AUTHORIZATION) != 0) {
        //    digestAuthorization.update(buffer, h[CURRENT], length);
        //}
        h[REMAINING] -= length;
        h[CURRENT] += length;
        d[REMAINING] -= length;
        d[CURRENT] += length;
    }
    
    private static boolean parseVarint(byte[] buffer, byte[] target, short targetOffset) {
        if (h[REMAINING] < (short)1) {
            return false;
        }
        short firstByte = (short)(buffer[h[CURRENT]] & 0xff);
        if (firstByte < (short)0xfd) {
            Uint32Helper.setByte(target, targetOffset, (byte)firstByte);
            consumeTransaction(buffer, (short)1);            
        }
        else if (firstByte == (short)0xfd) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)2) {
                return false;
            }
            Uint32Helper.setShort(target, targetOffset, buffer[(short)(h[CURRENT] + 1)], buffer[h[CURRENT]]);
            consumeTransaction(buffer, (short)2);
        }
        else if (firstByte == (short)0xfe) {
            consumeTransaction(buffer, (short)1);
            if (h[REMAINING] < (short)4) { // original: (h[REMAINING] < (short)2): bug??
                return false;
            }
            Uint32Helper.setInt(target, targetOffset, buffer[(short)(h[CURRENT] + 3)], buffer[(short)(h[CURRENT] + 2)], buffer[(short)(h[CURRENT] + 1)], buffer[h[CURRENT]]);
            consumeTransaction(buffer, (short)4);
        }
        else {
            return false;
        }
        return true;
    }
    
    public static void resetTransaction(byte[] buffer){
            
        h = new short[2];
        datachunk= new byte[MAX_CHUNK_SIZE];
        d= new  short[2];
        ctx = new byte[TX_CONTEXT_SIZE];
        try {
            digestFull = MessageDigest.getInstance("SHA-256");//new SHA256Digest();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TransactionParser.class.getName()).log(Level.SEVERE, "MessageDigest: no such algorithm");
        }
        digestFull.reset();
        
        if (buffer.length>32767)
            System.out.println("Transaction data is to long! max 32767 bytes allowed!!");
        
        h[CURRENT]=0;
        h[REMAINING]=(short)buffer.length; 
        ctx[TX_B_TRANSACTION_STATE] = STATE_NONE;
        Uint32Helper.clear(ctx, TX_I_REMAINING_I);
        Uint32Helper.clear(ctx, TX_I_CURRENT_I);
        Uint32Helper.clear(ctx, TX_I_REMAINING_O);
        Uint32Helper.clear(ctx, TX_I_CURRENT_O);
        Uint32Helper.clear(ctx, TX_I_SCRIPT_REMAINING);
        Uint64Helper.clear(ctx, TX_A_TRANSACTION_AMOUNT);
        Uint64Helper.clear(ctx, TX_TMP_BUFFER);
        Uint32Helper.clear(ctx, TX_I_SCRIPT_COORD);
        ctx[TX_I_SCRIPT_ACTIVE] = INACTIVE;
    }
    
    public static byte parseTransaction(byte[] buffer) {
        d[CURRENT] = 0;
        d[REMAINING] = MAX_CHUNK_SIZE;
        for (;;) {
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_NONE) {

                // Parse the beginning of the transaction
                // run resetTransaction() first
                // Version
                if (h[REMAINING] < (short)4 ) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // Number of inputs
                if (!parseVarint(buffer, ctx, TX_I_REMAINING_I)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_INPUT) {
                if (Uint32Helper.isZero(ctx, TX_I_REMAINING_I)) {
                    if (ctx[TX_I_SCRIPT_ACTIVE]== INACTIVE){
                            // there should be exactly one input script active at this point
                            System.out.println("ParseError: No active script in any input!");
                            return RESULT_ERROR;
                    }
                    // No more inputs to hash, move forward
                    ctx[TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_DONE;
                    continue;
                }
                if (d[REMAINING] < (short)36) {
                    // Not enough memory in chunk => send APDU and restart parsing from this point
                    return RESULT_MORE;
                }
                // Proceed with the next input
                //if (parseMode == PARSE_TRUSTED_INPUT) {
                if (h[REMAINING] < (short)36) { // prevout : 32 hash + 4 index
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)36);
                if (!parseVarint(buffer, ctx, TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                else if (!Uint32Helper.isZero(ctx,TX_I_SCRIPT_REMAINING)){
                    // check if a script was already present
                    if (ctx[TX_I_SCRIPT_ACTIVE]== INACTIVE){
                        ctx[TX_I_SCRIPT_ACTIVE]= ACTIVE;
                        System.arraycopy(ctx, TX_I_CURRENT_I, ctx, TX_I_SCRIPT_COORD, SIZEOF_U32); 
                    }
                    else { // there should be only one input script active
                        return RESULT_ERROR;
                    }
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;                
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT) {
                // if script size is zero or script is already consumed 
                if (Uint32Helper.isZero(ctx,TX_I_SCRIPT_REMAINING)) { 
                    // Sequence
                    if (h[REMAINING] < 4) {
                        return RESULT_ERROR;
                    }
                    if (d[REMAINING] < 4) {
                        // No more data to read, ok
                        return RESULT_MORE;
                    }
                    // TODO : enforce sequence
                    consumeTransaction(buffer, (short)4);
                    // Move to next input
                    Uint32Helper.decrease(ctx, TX_I_REMAINING_I);
                    Uint32Helper.increase(ctx, TX_I_CURRENT_I);
                    ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_INPUT;
                    return RESULT_MORE;
                }
                short  scriptRemaining = Uint32Helper.getU8(ctx, TX_I_SCRIPT_REMAINING); // what happens if script is size is >= 0xff
                short dataAvailable = (((short)d[REMAINING]) > scriptRemaining ? scriptRemaining : ((short)d[REMAINING]));
                if (dataAvailable == 0 ) {
                    return RESULT_MORE;
                }
                if (h[REMAINING] < dataAvailable) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, dataAvailable);
                Uint32Helper.setByte(ctx, TX_TMP_BUFFER, (byte)dataAvailable);
                Uint32Helper.sub(ctx, TX_I_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER);
                // at this point the program loop until either the script or the buffer is consumed
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_INPUT_HASHING_DONE) {
                // Number of outputs
                if (!parseVarint(buffer, ctx, TX_I_REMAINING_O)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_DEFINED_WAIT_OUTPUT) {
                if (Uint32Helper.isZero(ctx, TX_I_REMAINING_O)) {
                    // No more outputs to hash, move forward
                    ctx[TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_DONE;
                    continue;
                }
                // Amount
                if (h[REMAINING] < (short)8) {
                    return RESULT_ERROR;
                }
                Uint64Helper.swap(ctx, TX_TMP_BUFFER, buffer, h[CURRENT]);
                Uint64Helper.add(ctx, TX_A_TRANSACTION_AMOUNT, ctx, TX_TMP_BUFFER);
                consumeTransaction(buffer, (short)8);
                // Read the script length
                if (!parseVarint(buffer, ctx, TX_I_SCRIPT_REMAINING)) {
                    return RESULT_ERROR;
                }
                ctx[TX_B_TRANSACTION_STATE] = STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT) {
                if (Uint32Helper.isZero(ctx,TX_I_SCRIPT_REMAINING)) {
                    // Move to next output
                    Uint32Helper.decrease(ctx, TX_I_REMAINING_O);
                    Uint32Helper.increase(ctx, TX_I_CURRENT_O);
                    ctx[TX_B_TRANSACTION_STATE] = STATE_DEFINED_WAIT_OUTPUT;
                    return RESULT_MORE;
                    //continue;
                }
                short scriptRemaining = Uint32Helper.getU8(ctx, TX_I_SCRIPT_REMAINING);
                short dataAvailable = (((short)d[REMAINING]) > scriptRemaining ? scriptRemaining : ((short)d[REMAINING]));
                if (dataAvailable == 0) {
                    return RESULT_MORE;
                }
                if (h[REMAINING] < dataAvailable) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, dataAvailable);
                Uint32Helper.setByte(ctx, TX_TMP_BUFFER, (byte)dataAvailable);
                Uint32Helper.sub(ctx, TX_I_SCRIPT_REMAINING, ctx, TX_TMP_BUFFER);
            }
            if (ctx[TX_B_TRANSACTION_STATE] == STATE_OUTPUT_HASHING_DONE) {
                if (d[REMAINING] < (short)4) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                // Locktime
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                // sighash: 01000000
                if (d[REMAINING] < (short)4) {
                    // No more data to read, ok
                    return RESULT_MORE;
                }
                if (h[REMAINING] < (short)4) {
                    return RESULT_ERROR;
                }
                consumeTransaction(buffer, (short)4);
                ctx[TX_B_TRANSACTION_STATE] = STATE_PARSED;
                return RESULT_FINISHED;
            }                       
        }
    }
    
    public static int getNbInput(){
        return ((int)(ctx[TX_I_CURRENT_I]&0xFF)<<24)+((int)(ctx[TX_I_CURRENT_I+1]&0xFF)<<16)+
               ((int)(ctx[TX_I_CURRENT_I+2]&0xFF)<<8)+((int)(ctx[TX_I_CURRENT_I+3]&0xFF));
    }
    public static int getNbOutput(){
        return ((int)(ctx[TX_I_CURRENT_O]&0xFF)<<24)+((int)(ctx[TX_I_CURRENT_O+1]&0xFF)<<16)+
               ((int)(ctx[TX_I_CURRENT_O+2]&0xFF)<<8)+((int)(ctx[TX_I_CURRENT_O+3]&0xFF));
    }
    public static int getCoordInput(){
        return ((int)(ctx[TX_I_SCRIPT_COORD]&0xFF)<<24)+((int)(ctx[TX_I_SCRIPT_COORD+1]&0xFF)<<16)+
               ((int)(ctx[TX_I_SCRIPT_COORD+2]&0xFF)<<8)+((int)(ctx[TX_I_SCRIPT_COORD+3]&0xFF));
    }
    public static long getAmount(){
        //byte[] amnt= new byte[8];
        //System.arraycopy(ctx, TX_A_TRANSACTION_AMOUNT, amnt, 0, 8);
        //System.out.println("Amount buffer: "+ javax.xml.bind.DatatypeConverter.printHexBinary(amnt));
        return ((long)(ctx[TX_A_TRANSACTION_AMOUNT]&0xFF)<<56)+((long)(ctx[TX_A_TRANSACTION_AMOUNT+1]&0xFF)<<48)+
                ((long)(ctx[TX_A_TRANSACTION_AMOUNT+2]&0xFF)<<40)+((long)(ctx[TX_A_TRANSACTION_AMOUNT+3]&0xFF)<<32)+
                ((long)(ctx[TX_A_TRANSACTION_AMOUNT+4]&0xFF)<<24)+((long)(ctx[TX_A_TRANSACTION_AMOUNT+5]&0xFF)<<16)+
                ((long)(ctx[TX_A_TRANSACTION_AMOUNT+6]&0xFF)<<8)+((long)(ctx[TX_A_TRANSACTION_AMOUNT+7]&0xFF));
    }
    public static byte[] getHash(){
        byte[] hash= digestFull.digest(); // single hash
        return hash; 
    }
    public static byte[] getDataChunk(){
        byte[] chunk= new byte[d[CURRENT]];
        System.arraycopy(datachunk, 0, chunk, 0, chunk.length);
        System.out.println("Data chunk: "+ javax.xml.bind.DatatypeConverter.printHexBinary(chunk));
        return chunk; 
    }
   
    private static short[] h;
    private static short[] d;
    
    private static final byte CURRENT = (byte)0;
    private static final byte REMAINING = (byte)1;
    
    public static final byte STATE_NONE = (byte)0x00;
    public static final byte STATE_DEFINED_WAIT_INPUT = (byte)0x01;
    public static final byte STATE_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT = (byte)0x02;
    public static final byte STATE_INPUT_HASHING_DONE = (byte)0x03;
    public static final byte STATE_DEFINED_WAIT_OUTPUT = (byte)0x04;
    public static final byte STATE_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT = (byte)0x05;
    public static final byte STATE_OUTPUT_HASHING_DONE = (byte)0x06;
    public static final byte STATE_PARSED = (byte)0x07;
    public static final byte STATE_PRESIGN_READY = (byte)0x08;
    public static final byte STATE_SIGN_READY = (byte)0x09;
    
//    public static final byte HASH_NONE = (byte)0x00;
//    public static final byte HASH_FULL = (byte)0x01;
//    public static final byte HASH_AUTHORIZATION = (byte)0x02;
//    public static final byte HASH_BOTH = (byte)0x03;
    
//    public static final byte PARSE_TRUSTED_INPUT = (byte)0x01;
//    public static final byte PARSE_SIGNATURE = (byte)0x02;
    
    public static final byte RESULT_FINISHED = (byte)0x13;
    public static final byte RESULT_ERROR = (byte)0x79;
    public static final byte RESULT_MORE = (byte)0x00;

    // Transaction context
    protected static final byte SIZEOF_U32 = 4;
    protected static final byte SIZEOF_U8 = 1;
    protected static final byte SIZEOF_AMOUNT = 8;
    protected static final byte SIZEOF_NONCE = 8;
    protected static final byte SIZEOF_SHA256 = 32;
    protected static final byte SIZEOF_RIPEMD = 20;
    protected static final byte SIZEOF_ENCODED_PRIVATEKEY = 40;
    
    protected static final byte TRUE = (byte)0x37;
    protected static final byte FALSE = (byte)0xda;
    
    protected static final byte INACTIVE = (byte)0x00;
    protected static final byte ACTIVE = (byte)0x01;
    
    // context data
    protected static final short TX_B_HASH_OPTION = (short)0;
    protected static final short TX_I_REMAINING_I = (short)(TX_B_HASH_OPTION + SIZEOF_U8);
    protected static final short TX_I_CURRENT_I = (short)(TX_I_REMAINING_I + SIZEOF_U32);
    protected static final short TX_I_REMAINING_O = (short)(TX_I_CURRENT_I + SIZEOF_U32);
    protected static final short TX_I_CURRENT_O = (short)(TX_I_REMAINING_O + SIZEOF_U32);
    protected static final short TX_I_SCRIPT_REMAINING = (short)(TX_I_CURRENT_O + SIZEOF_U32);
    protected static final short TX_B_TRANSACTION_STATE = (short)(TX_I_SCRIPT_REMAINING + SIZEOF_U32);
    protected static final short TX_A_TRANSACTION_AMOUNT = (short)(TX_B_TRANSACTION_STATE + SIZEOF_U8);
    protected static final short TX_I_SCRIPT_ACTIVE = (short)(TX_A_TRANSACTION_AMOUNT + SIZEOF_AMOUNT);
    protected static final short TX_I_SCRIPT_COORD = (short)(TX_I_SCRIPT_ACTIVE + SIZEOF_U8);
    protected static final short TX_TMP_BUFFER = (short)(TX_I_SCRIPT_COORD + SIZEOF_U32);
    protected static final short TX_CONTEXT_SIZE = (short)(TX_TMP_BUFFER + SIZEOF_AMOUNT);  
            
    protected static byte[] ctx;
    protected static byte[] datachunk;
    protected static final int MAX_CHUNK_SIZE=160;
    
    // Message Digest
    public static MessageDigest digestFull;
    
}
