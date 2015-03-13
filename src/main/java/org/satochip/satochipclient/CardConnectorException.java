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

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * A CardConnectorException is thrown when a APDU command returns a response different from 0x9000
 */
public class CardConnectorException extends Exception{
    
    /** Block or transaction hash */
    private CommandAPDU c;
    private ResponseAPDU r;
    
    /**
     * Creates a new exception with a detail message
     *
     * @param       msg             Detail message    
     */
    public CardConnectorException(String msg, CommandAPDU c, ResponseAPDU r) {
        super(msg);
        //only for debug purpose as it may contains sensitive data! 
        //this.c= c;
        //this.r= r;
        
        // safer to remove sensitive information
        this.c= new CommandAPDU(c.getCLA(), c.getINS(), c.getP1(), c.getP2(), null);
        byte[] sw12=new byte[2];
        sw12[0]=(byte)r.getSW1();
        sw12[1]=(byte)r.getSW2();
        this.r= new ResponseAPDU(sw12);
    }

    CardConnectorException(String unable_to_recover_public_key_from_signatu) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
     /**
     * Returns the SW12 code associated with this exception
     *
     * @return              SW12
     */
    public short getSW12() {
        return (short)r.getSW();
    }
    
         /**
     * Returns the SW12 code associated with this exception
     *
     * @return              SW12
     */
    public short getIns() {
        return (short)c.getINS();
    }
    
    public ResponseAPDU getResponse(){
        return r;
    }

    public CommandAPDU getCommand(){
        return c;
    }
}



