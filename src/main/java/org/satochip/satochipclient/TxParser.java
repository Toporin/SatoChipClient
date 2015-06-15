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
import java.util.logging.Level;
import java.util.logging.Logger;


public class TxParser {
    
    
    public enum TxState {
        TX_START,
        TX_PARSE_INPUT,
        TX_PARSE_INPUT_SCRIPT,
        TX_PARSE_OUTPUT,
        TX_PARSE_OUTPUT_SCRIPT,
        TX_PARSE_FINALIZE,
        TX_END
    }    
    public static final int CHUNK_SIZE=128; // max chunk size of a script
    
    //private byte txState;
    private ByteArrayOutputStream baos; 
    private byte[] txData;
    private TxState txState;

    public long txRemainingInput=0;
    public long txCurrentInput=0;
    public long txRemainingOutput=0;
    public long txCurrentOutput=0;
    public long txAmount=0;
    public long txScriptRemaining=0;
    public int txOffset;
    public int txRemaining;
    
    MessageDigest txDigest=null;
    byte[] singleHash=null;
    byte[] doubleHash=null;
    
    public TxParser(byte[] rawTx){
        txData= Arrays.copyOf(rawTx, rawTx.length);
        baos= new ByteArrayOutputStream(rawTx.length);
        txState= TxState.TX_START;
        
        txRemainingInput=0;
        txCurrentInput=0;
        txRemainingOutput=0;
        txCurrentOutput=0;
        txAmount=0;
        txScriptRemaining=0;
        txOffset=0;
        txRemaining=rawTx.length;
        
        try {
            txDigest= MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CardConnector.class.getName()).log(Level.SEVERE, "No SHA-256 algorithm available");
        }
    }
    
    public boolean isParsed(){
        return (txRemaining==0);
    }
    public byte[] getTxHash(){
        return singleHash;
    }
    public byte[] getTxDoubleHash(){
        return doubleHash;
    }
    
    public byte[] parseTransaction(){
        
        int chunkSize=0;
        baos.reset();

        switch(txState){

            // max 4+9 bytes accumulated
            case TX_START:
                parseByte(4); // version
                txRemainingInput= parseVarInt(); 
                txState= TxState.TX_PARSE_INPUT;
                //break;

            // max 36+9 bytes accumulated
            case TX_PARSE_INPUT:
                if (txRemainingInput==0){
                    txRemainingOutput= parseVarInt();
                    txState= TxState.TX_PARSE_OUTPUT;
                    break;
                }
                parseByte(32); // txOutHash
                parseByte(4); // txOutIndex
                txScriptRemaining= parseVarInt();
                txState= TxState.TX_PARSE_INPUT_SCRIPT;
                txRemainingInput--;
                txCurrentInput++;
                break;

            // max MAX_CHUNK_SIZE+4 bytes accumulated
            case TX_PARSE_INPUT_SCRIPT:
                chunkSize= (int)((txScriptRemaining<CHUNK_SIZE)?txScriptRemaining:CHUNK_SIZE);
                parseByte(chunkSize);
                txScriptRemaining-=chunkSize;

                if (txScriptRemaining==0){
                    parseByte(4); // sequence
                    txState= TxState.TX_PARSE_INPUT;
                }
                break;

            // max 8+9 bytes accumulated    
            case TX_PARSE_OUTPUT:
                if (txRemainingOutput==0){
                    parseByte(4); //locktime
                    parseByte(4); //sighash
                    txState= TxState.TX_END;
                    break;
                }
                parseByte(8); // amount
                txScriptRemaining= parseVarInt();
                txState= TxState.TX_PARSE_OUTPUT_SCRIPT;
                txRemainingOutput--;
                txCurrentOutput++;
                //break;                    

            // max MAX_CHUNK_SIZE bytes accumulated    
            case TX_PARSE_OUTPUT_SCRIPT:
                chunkSize= (int)((txScriptRemaining<CHUNK_SIZE)?txScriptRemaining:CHUNK_SIZE);
                parseByte(chunkSize);
                txScriptRemaining-=chunkSize;

                if (txScriptRemaining==0){
                    txState= TxState.TX_PARSE_OUTPUT;
                }
                break;

            case TX_END:
                break;
        }// end switch
        
        byte[] txChunk=baos.toByteArray();
        if (txDigest!=null)
            txDigest.update(txChunk, 0, txChunk.length);
        
        if (txState==TxState.TX_END && txDigest!=null){
            singleHash= txDigest.digest(); 
            txDigest.reset();
            txDigest.update(singleHash, 0, singleHash.length);
            doubleHash= txDigest.digest(); 
        }
        
        return txChunk;
    }
    
    public void parseByte(int length){
        baos.write(txData, txOffset, length);
        txOffset+=length;
        txRemaining-=length;
    }
    
    public long parseVarInt(){
        
        int first = 0xFF & txData[txOffset];
        long val=0;
        int le=0;
        if (first < 253) {
            // 8 bits.
            val = first;
            le=1;
        } else if (first == 253) {
            // 16 bits.
            val = (0xFF & txData[txOffset+1]) | ((0xFF & txData[txOffset+2]) << 8);
            le=3;
        } else if (first == 254) {
            // 32 bits.
            val = readUint32(txData, txOffset + 1);
            le=5;
        } else {
            // 64 bits.
            val = readInt64(txData, txOffset + 1);
            le=9;
        }
        baos.write(txData, txOffset, le);
        txOffset+=le;
        txRemaining-=le;
        
        return val;
    }
    public static long readUint32(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL) << 0) |
                ((bytes[offset++] & 0xFFL) << 8) |
                ((bytes[offset++] & 0xFFL) << 16) |
                ((bytes[offset] & 0xFFL) << 24);
    }
    public static long readInt64(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL) << 0) |
               ((bytes[offset++] & 0xFFL) << 8) |
               ((bytes[offset++] & 0xFFL) << 16) |
               ((bytes[offset++] & 0xFFL) << 24) |
               ((bytes[offset++] & 0xFFL) << 32) |
               ((bytes[offset++] & 0xFFL) << 40) |
               ((bytes[offset++] & 0xFFL) << 48) |
               ((bytes[offset] & 0xFFL) << 56);
    }
    
}// end of class
