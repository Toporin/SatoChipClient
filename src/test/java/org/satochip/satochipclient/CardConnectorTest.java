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

import com.google.bitcoin.core.ECKey;
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
import static com.google.bitcoin.core.Utils.uint32ToByteStreamLE;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptOpCodes;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.satochip.satochipclient.CardDataParser.toHexString;
import org.toporin.bitcoincore.ECException;
import org.toporin.yubikey4java.YubikeyConnector;

public class CardConnectorTest {
    
    public static final byte[] BYTE_AID= {0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70}; //SatoChip
    
    // setup params done only once
    public static byte pin_tries_0= 0x10;
    public static byte ublk_tries_0= 0x10;
    public static byte[] pin_0={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    public static byte[] ublk_0={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    public static byte pin_tries_1= 0x10;
    public static byte ublk_tries_1= 0x10;
    public static byte[] pin_1={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    public static byte[] ublk_1={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    public static short secmemsize= 0x1000;
    public static short memsize= 0x1000;
    public static byte create_object_ACL= 0x01;
    public static byte create_key_ACL= 0x01;
    public static byte create_pin_ACL= 0x01;
    public static short option_flags= (short)0x8000; // activate 2fa with hmac challenge-response
    public static byte[] key= new byte[20];
    public static long amount_limit= 0;
    
    // static test
    public static CardConnector cc;
    public static byte std_keynbr=0x00;
    public static byte bip32_keynbr=(byte)0xff;
    
    // test PIN
    public static byte pin2_nbr = 2;
    public static byte pin2_tries = 3;
    public static byte[] pin2 = {30,30,30,30};
    public static byte[] ublk2 = {31,31,31,31};

    // test object
    public static final byte[] DEFAULT_ACL={0x00,0x01, 0x00,0x01, 0x00,0x01};
    
    // test BIP32
    public static String strseed= "31323334353637383132333435363738";// ascii for 1234567812345678
    public static byte[] authentikey= null;
    public static DeterministicKey masterkey;
    
    // test message signing
    public String strmsg= "abcdefghijklmnopqrstuvwxyz0123456789";
    public String strmsg_long="";
    public byte[] default_bip32path={(byte)0x80, 0x00, 0x00, 0x00};
    
    public CardConnectorTest() {
    }
    
    @BeforeClass
    public static void setUpClass() throws ECException, Exception {
        System.out.println("* CardConnectorTest: @BeforeClass method");
        
        ConsoleHandler handler= new ConsoleHandler();
        handler.setLevel(Level.INFO);
        cc= new CardConnector(handler, Level.INFO);
        try {
            System.out.println("cardSelect:");
            cc.cardSelect(BYTE_AID);
            
            try {
                System.out.println("cardSetup:");
                cc.cardSetup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                            pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                            secmemsize, memsize, 
                            create_object_ACL, create_key_ACL, create_pin_ACL
                            //,option_flags, key, amount_limit
                    );
            }catch (CardConnectorException ex) {
                if (ex.getSW12()!=0x6d00)
                    fail("Unable to set up applet");
                else
                    System.out.println("setup already done");
            }
            
            // required for other tests
            cc.cardVerifyPIN((byte)0, pin_0);
            testCardBip32ImportSeed();
            testCardGenerateKeyPair(JCconstants.ALG_EC_FP, std_keynbr, (byte)0xff, (short)256);
            
        } catch (CardConnectorException ex) {
            System.out.println("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
        }
    }
    
    @AfterClass
    public static void tearDownClass() {
        System.out.println("* CardConnectorTest: @AfterClass method");
        
        /* Mise hors tension de la carte */
        System.out.println("Disconnect...");
        try {
            cc.disconnect();
        } catch (CardException ex) {
            //Logger.getLogger(CardConnectorTest.class.getName()).log(Level.SEVERE, null, ex);
            fail("Unable to disconnect card");
        }
    }
    
    @Before
    public void setUp() {
//        try {
//            System.out.println("* CardConnectorTest: @Before method");
//            cc.cardGetStatus();
//        } catch (CardConnectorException ex) {
//            Logger.getLogger(CardConnectorTest.class.getName()).log(Level.SEVERE, null, ex);
//            fail("Unable to get card status");
//        }       
    }
    
    @After
    public void tearDown() {
//        try {
//            System.out.println("* CardConnectorTest: @After method");
//            cc.cardGetStatus();
//            
//        } catch (CardConnectorException ex) {
//            Logger.getLogger(CardConnectorTest.class.getName()).log(Level.SEVERE, null, ex);
//            fail("Unable to get card status");
//        }
    }
    
    /**
     * Test of cardBip32ImportSeed method, of class CardConnector.
     */
    public static void testCardBip32ImportSeed() throws Exception {
        System.out.println("cardBip32ImportSeed");
        
        // import seed to HWchip
        long startTime = System.currentTimeMillis();
        byte[] seed= DatatypeConverter.parseHexBinary(strseed); 
        byte[] seed_ACL= DEFAULT_ACL; //{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] response= cc.cardBip32ImportSeed(seed_ACL, seed);
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("elapsed time: "+elapsedTime);
        
        org.satochip.satochipclient.CardDataParser.PubKeyData parser = new CardDataParser.PubKeyData();
        authentikey= parser.parseBip32ImportSeed(response).authentikey;
        System.out.println("authentikey: "+CardDataParser.toHexString(authentikey));
        
        // create SW masterkey equivalent with bitcoinj
        masterkey= HDKeyDerivation.createMasterPrivateKey(seed);       
    }
    
    /**
     * Test of cardBip32GetAuthentiKey method, of class CardConnector.
     */
    @Test
    public void testCardBip32GetAuthentiKey() throws Exception {
        System.out.println("cardBip32GetAuthentiKey");
        byte[] response= cc.cardBip32GetAuthentiKey();
        
        org.satochip.satochipclient.CardDataParser.PubKeyData pubkeydata = new CardDataParser.PubKeyData();
        byte[] recoveredkey= pubkeydata.parseBip32GetAuthentikey(response).authentikey;
        System.out.println("recoveredkey: "+CardDataParser.toHexString(recoveredkey));
        assertArrayEquals(recoveredkey, authentikey);
    }
   
    /**
     * Test of cardBip32GetExtendedKey method, of class CardConnector.
     */
    @Test
    public void testCardBip32GetExtendedKey() throws Exception {
        System.out.println("cardBip32GetExtendedKey");
        
        int valmax=0;
        int depthmax=3;
        byte[] keyhw, keysw;
        for (int val=0; val<=valmax; val++){
            for (int depth=1; depth<=depthmax; depth++){
                byte[] bip32path= new byte[4*depth];
                // normal child
                for (int i=0; i<bip32path.length; i+=4){
                    bip32path[i]=0x00;
                    bip32path[i+1]=0x00;
                    bip32path[i+2]=0x00;
                    bip32path[i+3]=(byte)val;
                }
                keyhw=testCardBip32GetExtendedKey(bip32path);//HW
                keysw=testCardBip32GetExtendedKey_bitcoinj(bip32path);//SW
                assertArrayEquals(keyhw, keysw);
                
                // hardened child
                for (int i=0; i<bip32path.length; i+=4){
                    bip32path[i]=(byte)0x80;
                    bip32path[i+1]=0x00;
                    bip32path[i+2]=0x00;
                    bip32path[i+3]=(byte)val;
                }
                keyhw=testCardBip32GetExtendedKey(bip32path);//HW
                keysw=testCardBip32GetExtendedKey_bitcoinj(bip32path);//SW
                assertArrayEquals(keyhw, keysw);
                
            }
        }
    }
    public byte[] testCardBip32GetExtendedKey(byte[] bip32path) throws Exception {
        
        long startTime = System.currentTimeMillis();
        byte[] response= cc.cardBip32GetExtendedKey(bip32path);
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("elapsed time: "+elapsedTime);
        System.out.println("Extended key for "+toHexString(bip32path));

        org.satochip.satochipclient.CardDataParser.PubKeyData pubkeydata = new CardDataParser.PubKeyData(authentikey);
        byte[] recoveredkey= pubkeydata.parseBip32GetExtendedKey(response).pubkey;
        System.out.println("extendedkey: "+CardDataParser.toHexString(recoveredkey));
        return recoveredkey;
    }
    public byte[] testCardBip32GetExtendedKey_bitcoinj(byte[] bip32path) throws Exception {
        // create SW extendedkey with bitcoinj
        int bip32depth= bip32path.length/4;
        DeterministicKey parent= masterkey; // imported from seed
        DeterministicKey child= null;
        for (int i=0; i<bip32path.length; i+=4){
            int childNumber=((bip32path[i]&0xff)<<24) ^ 
                            ((bip32path[i+1]&0xff)<<16)^ 
                            ((bip32path[i+2]&0xff)<<8) ^ 
                            (bip32path[i+3]&0xff);
            child= HDKeyDerivation.deriveChildKey(parent,childNumber);
            parent= child;
            //System.out.println("Depth:"+(i/4+1)+" pubKey:" + parent.toString()); 
        }
        System.out.println("Extended pubKey:" + parent.toString());
        return parent.getPubKeyBytes();
    }
    
    /**
     * Test of cardSignMessage method, of class CardConnector.
     */
    @Test
    public void testCardSignMessage() throws Exception {
        System.out.println("cardSignMessage");
        
        testCardSignMessage(strmsg, bip32_keynbr);
        testCardSignMessage(strmsg, std_keynbr);
        testCardSignMessage(strmsg_long, bip32_keynbr);
        testCardSignMessage(strmsg_long, std_keynbr);
        
    }
    public void testCardSignMessage(String strmsg, byte keynbr) throws Exception {
        
        // recover pubkey
        byte[] pubkey;
        if (keynbr==bip32_keynbr)
            pubkey=testCardBip32GetExtendedKey(default_bip32path);
        else
            pubkey=testGetPublicKeyFromPrivate(keynbr);
        System.out.println("signing pubkey: "+toHexString(pubkey));
        
        // sign message
        byte[] msg= strmsg.getBytes(); 
        byte[] signature;
        if (msg.length<144)
            signature= cc.cardSignShortMessage(keynbr,msg);
        else 
            signature= cc.cardSignMessage(keynbr,msg);
        
        // parse signature 
        System.out.println("signature: "+toHexString(signature));
        org.satochip.satochipclient.CardDataParser.PubKeyData pubkeydata = new CardDataParser.PubKeyData();
        String strsignature64= pubkeydata.parseMessageSigning(signature, pubkey, strmsg).compactsig_b64_str;
        System.out.println("signature in base64: "+strsignature64);
        
        // verify with bitcoinj
        ECKey eckey= ECKey.signedMessageToKey(strmsg, strsignature64);
        System.out.println("recovered pubkey: "+toHexString(eckey.getPubKey()));
        assertArrayEquals(pubkey, eckey.getPubKey());        
    }
    
    
//    /**
//     * Test of cardParseTransaction method, of class CardConnector.
//     */
//    @Test
//    public void testCardParseTransaction() throws Exception {
//        System.out.println("cardParseTransaction");
//        
//        testCardParseTransaction(bip32_keynbr);  
//        testCardParseTransaction(std_keynbr);  
//        
//        
//    }
    /**
     * Test of cardParseTx method, of class CardConnector.
     */
    @Test
    public void testCardParseTx() throws Exception {
        System.out.println("cardParseTx");
        testCardParseTransaction(bip32_keynbr);  
        testCardParseTransaction(std_keynbr);  
    }
    public void testCardParseTransaction(byte keynbr) throws CardConnectorException, ECException{
        
        // recover pubkey
        byte[] pubkey, response;
        CardDataParser.PubKeyData dataparser= new CardDataParser.PubKeyData(authentikey); 
        if (keynbr==bip32_keynbr){
            response=cc.cardBip32GetExtendedKey(default_bip32path);
            authentikey= dataparser.parseBip32GetExtendedKey(response).authentikey;
            pubkey= dataparser.pubkey; 
        }
        else{
            response=cc.cardGetPublicKeyFromPrivate(keynbr);
            pubkey= dataparser.parseGetPublicKeyFromPrivate(response).pubkey;
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
        
        // unused
        System.out.println("Raw tx for hashing:" + toHexString(rawtxforhashing));
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
        byte[] txhash_sw= rawtxhash2.getBytes();
        System.out.println("Tx hash Bitcoinj: " + toHexString(txhash_sw));
        
        // send to card for parsing
        //byte[] response= cc.cardParseTransaction(rawtxforhashing);
        response= cc.cardParseTx(rawtxforhashing);
        CardDataParser.PubKeyData txparser = new CardDataParser.PubKeyData(authentikey);
        byte[] txhash_hw= txparser.parseTxHash(response).data; //Arrays.copyOfRange(response, 2, 2+32);
        System.out.println("Tx hash SatoChip: "+ toHexString(txhash_hw));
        System.out.println(txparser.toString());
        assertArrayEquals(txhash_hw, txhash_sw);
        
        // check if 2fa is required
        boolean need_2fa_chalresp= ((txparser.option_flags& 0x8000)==0x8000)?true:false; // if msb is set, a challenge-response 2nd factor authentification is needed
        byte[] txhmac=null;
        if (need_2fa_chalresp){
            try {
                System.out.println("Second factor authentication required for challenge response...");
                System.out.println("Please insert a configured yubikey!");
                MILLISECONDS.sleep(2000);
            } catch (InterruptedException ex) {}
            YubikeyConnector yubikey= new YubikeyConnector(false);
            yubikey.findYubikey(YubikeyConnector.PRODUCT_ID_NEO);
            yubikey.openYubikey();
            yubikey.attachYubikeyInterface();
            txhmac= yubikey.challenge_response(txhash_hw, YubikeyConnector.MODE_HMAC, YubikeyConnector.SLOT_2, false, true);
            yubikey.releaseYubikeyInterface();
            yubikey.closeYubikey();
            System.out.println("txhmac: "+toHexString(txhmac));
            // test with wrong hmac:
            //txhmac[0]=0;
        }
        byte[] txsign = cc.cardSignTransaction(keynbr, txhash_hw, txhmac);
        System.out.println("txsign: "+toHexString(txsign));
        
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
     * Test of cardGenerateSymmetricKey method, of class CardConnector.
     */
    @Test
    public void testCardGenerateSymmetricKey() throws Exception {
        
        System.out.println("cardGenerateSymmetricKey");        
        testCardGenerateSymmetricKey(JCconstants.TYPE_DES, (byte)0x0A, (short)64);
        testCardGenerateSymmetricKey(JCconstants.TYPE_DES, (byte)0x0B, (short)128);
        testCardGenerateSymmetricKey(JCconstants.TYPE_DES, (byte)0x0C, (short)192);
        testCardGenerateSymmetricKey(JCconstants.TYPE_AES, (byte)0x0D, (short)128);
        testCardGenerateSymmetricKey(JCconstants.TYPE_AES, (byte)0x0E, (short)192);
        testCardGenerateSymmetricKey(JCconstants.TYPE_AES, (byte)0x0F, (short)256);
        
        System.out.println("cardComputeCrypt");
        //TestComputeCrypt(cc, JCconstants.ALG_RSA_PKCS1, (byte)0x01, (byte)0x00); // 
        //TestComputeCrypt(cc, JCconstants.ALG_RSA_NOPAD, (byte)0x01, (byte)0x00); // to do: padding
        testComputeCrypt(JCconstants.ALG_DES_CBC_NOPAD, (byte)0x0A, (byte)0x0A);
        testComputeCrypt(JCconstants.ALG_DES_ECB_NOPAD, (byte)0x0B, (byte)0x0B);
        testComputeCrypt(JCconstants.ALG_DES_CBC_NOPAD, (byte)0x0C, (byte)0x0C);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD, (byte)0x0D, (byte)0x0D);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_ECB_NOPAD, (byte)0x0E, (byte)0x0E);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD, (byte)0x0F, (byte)0x0F);

        // list key
        byte[] response;
        response= cc.cardGetStatus();
        CardDataParser.CardStatus cardstatus = new CardDataParser.CardStatus(response);
        System.out.println(cardstatus.toString());
        response=cc.cardListKeys();
        CardDataParser.KeyList keylist = new CardDataParser.KeyList(response);
        System.out.println(keylist.toString());
        
    }
    public void testCardGenerateSymmetricKey(byte algtype, byte keynbr, short keysize) throws Exception {
        byte[] keyACL=DEFAULT_ACL;
            
        String stralg="";
        if (algtype==JCconstants.TYPE_DES)
            stralg="DES";
        else if (algtype==JCconstants.TYPE_AES)
            stralg="AES";
        else{
            System.out.println("ERROR: algorithm not supported!");
            return;
        } 

        System.out.println("Test GenerateKey(alg="+stralg + ", keynbr="+ (int)keynbr+", keysize="+ keysize+")"); 
        cc.cardGenerateSymmetricKey(keynbr, algtype, keysize, keyACL);
    }
    public static void testComputeCrypt(byte CM, byte keynbr, byte keynbrdecrypt) throws Exception{
        
        String stralg="";
        if (CM==JCconstants.ALG_RSA_PKCS1)
            stralg="RSApkcs1";
        else if (CM==JCconstants.ALG_RSA_NOPAD)
            stralg="RSAnopad";
        else if (CM==JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD)
            stralg="AES-128-CBC";
        else if (CM==JCconstants.ALG_AES_BLOCK_128_ECB_NOPAD)
            stralg="AES-128-ECB";
        else if (CM==JCconstants.ALG_DES_CBC_NOPAD)
            stralg="DES-128-CBC";
        else if (CM==JCconstants.ALG_DES_ECB_NOPAD)
            stralg="DES-128-ECB";
        else{
            System.out.println("ERROR: mode not supported!");
            return;
        }
            
        String strmsg="abcdef";
        byte[] msg;
        byte[] msgcrypt;
        byte[] msgdecrypt;
        for (int i=0; i<6; i++){
            msg= strmsg.getBytes();
            
            System.out.println("\t TestComputeCrypt(CM="+stralg+", keynbr="+keynbr+"-"+keynbrdecrypt+")");
            msgcrypt= cc.cardComputeCrypt(keynbr, CM, JCconstants.MODE_ENCRYPT, msg);
            msgdecrypt= cc.cardComputeCrypt(keynbrdecrypt, CM, JCconstants.MODE_DECRYPT, msgcrypt);
            //System.out.println("msg:"+toString(msg));
            //System.out.println("msgcrypt:"+toString(msgcrypt));
            //System.out.println("msgdecrypt:"+toString(msgdecrypt));
            
            assertArrayEquals(msg,msgdecrypt);
            strmsg+=strmsg;
        }
    }
    /**
     * Test of cardImportKey method, of class CardConnector.
     */
    @Test
    public void testCardImportKey() throws Exception {
        System.out.println("cardImportKey");
        
        //testImportKey(JCconstants.TYPE_RSA_CRT_PRIVATE, (byte)0x00, (short)512);
        testImportKey(JCconstants.TYPE_RSA_PUBLIC, (byte)0x01, (short)512);
        testImportKey(JCconstants.TYPE_RSA_PRIVATE, (byte)0x02, (short)512);
        testImportKey(JCconstants.TYPE_RSA_PUBLIC, (byte)0x03, (short)512);
        testImportKey(JCconstants.TYPE_EC_FP_PRIVATE, (byte)0x06, (short)256);
        testGetPublicKeyFromPrivate((byte)0x06);
        //TestImportKey(cc, JCconstants.TYPE_EC_FP_PUBLIC, (byte)0x07, (short)256); // doesn't work?
        testImportKey(JCconstants.TYPE_DES, (byte)0x0A, (short)64);
        testImportKey(JCconstants.TYPE_DES, (byte)0x0B, (short)128);
        testImportKey(JCconstants.TYPE_DES, (byte)0x0C, (short)192);
        testImportKey(JCconstants.TYPE_AES, (byte)0x0D, (short)128);
        testImportKey(JCconstants.TYPE_AES, (byte)0x0E, (short)192);
        testImportKey(JCconstants.TYPE_AES, (byte)0x0F, (short)256);
        
        System.out.println("cardComputeCrypt");
        //TestComputeCrypt(cc, JCconstants.ALG_RSA_PKCS1, (byte)0x01, (byte)0x02); //doesn't work? 
        //TestComputeCrypt(cc, JCconstants.ALG_RSA_PKCS1, (byte)0x01, (byte)0x00); //doesn't work?
        //TestComputeCrypt(cc, JCconstants.ALG_RSA_NOPAD, (byte)0x01, (byte)0x00); // to do: padding
        testComputeCrypt(JCconstants.ALG_DES_CBC_NOPAD, (byte)0x0A, (byte)0x0A);
        testComputeCrypt(JCconstants.ALG_DES_ECB_NOPAD, (byte)0x0B, (byte)0x0B);
        testComputeCrypt(JCconstants.ALG_DES_CBC_NOPAD, (byte)0x0C, (byte)0x0C);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD, (byte)0x0D, (byte)0x0D);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_ECB_NOPAD, (byte)0x0E, (byte)0x0E);
        testComputeCrypt(JCconstants.ALG_AES_BLOCK_128_CBC_NOPAD, (byte)0x0F, (byte)0x0F);
        
        // list key
        byte[] response;
        response= cc.cardGetStatus();
        CardDataParser.CardStatus cardstatus = new CardDataParser.CardStatus(response);
        System.out.println(cardstatus.toString());
        response=cc.cardListKeys();
        CardDataParser.KeyList keylist = new CardDataParser.KeyList(response);
        System.out.println(keylist.toString());
        
    }
    public static void testImportKey(byte key_type, byte key_nbr, short key_size) throws Exception{

            byte key_encoding= 0x00; //plain
            byte[] key_ACL= DEFAULT_ACL; //{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            String stralg="";
            String strkey="";
            short keysize= key_size;
            if (key_type==JCconstants.TYPE_EC_FP_PRIVATE){
                stralg="ECpriv";
                keysize=256;
                strkey="0020"+"7bb8bfeb2ebc1401f9a14585032df07126ddf634ca641b7fa223b44b1e861548";//pycoin ku P:toporin
            }
            else if (key_type==JCconstants.TYPE_EC_FP_PUBLIC){
                stralg="ECpub";
                keysize=256;
                strkey="0041" //short blob size (0x41=65)
                        +"04" //uncompressed 
                        +"8d68936ac800d3fc1cf999bfe0a3af4ead4cf9ad61d3cb377c3e5626b5bfa9e8" // coordx
                        +"d682abeb1337c9b97d114f757bdd81e0207ad673d736eb6b4a84890be5f92335";// coordy
            }
            else if (key_type==JCconstants.TYPE_RSA_PUBLIC){
                stralg="RSApub";
                keysize=512;
                strkey="0040"// 0x40=64 modsize (byte) 
                        +"88d8b1c3ac39311ac82af63d6aeb3ea9cd05a28975cbc30203be81339f1341dac60e8afda1130e25e83e64e3112b9fb43c2e1ee47b8f6e164204c526bd7621e5" //mod
                        +"0003" // expsize
                        +"010001"; // exponent
            }
            else if (key_type==JCconstants.TYPE_RSA_PRIVATE){
                stralg="RSApriv";
                keysize=512;
                strkey="0040"// 0x40=64 modsize (byte) 
                        +"88d8b1c3ac39311ac82af63d6aeb3ea9cd05a28975cbc30203be81339f1341dac60e8afda1130e25e83e64e3112b9fb43c2e1ee47b8f6e164204c526bd7621e5" //mod
                        +"0040" // expsize
                        +"60da7d762ffe8a729a194e0e4a0e155bb86fb489f585318fcb76999b1f8b519fa41e55ba3c6294b5eaf1dc333191299ea10f5ca8507c3f120111396686554641";
            }
            else if (key_type==JCconstants.TYPE_RSA_CRT_PRIVATE){
                stralg="RSA-CRTpriv";
                keysize=512;
                strkey="0020"
                        +"f07c528f200b28b8e8ff4d73079730179bcec63b61a3012b849434ee4de389af"//P
                        +"0020"
                        +"91acbf0d2dc68b213b6dad87cddc580901f646401eee8c1946d395d44c45f6ab"//Q
                        +"0020"
                        +"264034c60f9b06db8721d655eacb8708ae68533f310b31cc879c16227857abdb"//Qinv
                        +"0020"
                        +"b6350bfc8343d133e0dd66da0bdb4245f0f846fbc0eb573c98b40e32ac7304e3"//DP1
                        +"0020"
                        +"1907511bf68d7242176fd4accc95db1a5117fb21f12e932b949badd677f45d59";//DQ1
            }
            else if (key_type==JCconstants.TYPE_AES && key_size==128){
                stralg="AES-128";
                keysize=128;
                strkey="0010"+"000102030405060708090a0b0c0d0e0f";//0x10=16
            }
            else if (key_type==JCconstants.TYPE_AES && key_size==192){
                stralg="AES-192";
                keysize=192;
                strkey="0018"+"000102030405060708090a0b0c0d0e0f0001020304050607";//0x18=24
            }
            else if (key_type==JCconstants.TYPE_AES && key_size==256){
                stralg="AES-256";
                keysize=256;
                strkey="0020"+"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";//0x20=32
            }
            else if (key_type==JCconstants.TYPE_DES && key_size==64){
                stralg="DES-64";
                keysize=64;
                strkey="0008"+"0001020304050607";//0x08=8
            }
            else if (key_type==JCconstants.TYPE_DES && key_size==128){
                stralg="DES-128";
                keysize=128;
                strkey="0010"+"000102030405060708090a0b0c0d0e0f";//0x10=16
            }
            else if (key_type==JCconstants.TYPE_DES && key_size==192){
                stralg="DES-192";
                keysize=192;
                strkey="0018"+"000102030405060708090a0b0c0d0e0f0001020304050607";//0x18=24
            }
            else{
                System.out.println("ERROR: key type not supported!");
                return;
            }
            
            byte[] keyblob= DatatypeConverter.parseHexBinary(strkey); 

            System.out.println("TestImportKey(key="+stralg+", nb="+ (int)key_nbr+", keysize="+ keysize+")"); // jcop-ko);
            cc.cardImportKey(key_nbr, key_ACL, key_encoding, key_type, keysize, keyblob); 

            // list key
            cc.cardGetStatus();
            System.out.println("*****ListKey*****");
            cc.cardListKeys();
            System.out.println("*****************\n\n");
    }

    /**
     * Test of cardGenerateKeyPair method, of class CardConnector.
     */
    @Test
    public void testCardGenerateKeyPair() throws Exception {
        System.out.println("cardGenerateKeyPair");
        //testCardGenerateKeyPair(JCconstants.ALG_RSA_CRT, (byte)0x00, (byte)0x01, (short)512);// doesn't work?
        testCardGenerateKeyPair(JCconstants.ALG_RSA, (byte)0x02, (byte)0x03, (short)512);
        //testCardGenerateKeyPair(JCconstants.ALG_RSA, (byte)0x04, (byte)0x05, (short)1024);
        testCardGenerateKeyPair(JCconstants.ALG_EC_FP, (byte)0x06, (byte)0xff, (short)256);
        System.out.println("cardGenerateKeyPair");
        testGetPublicKeyFromPrivate((byte)0x06);

        System.out.println("cardComputeSign");
        // to do
        //TestComputeSign(byte CM, byte key_sign, byte key_verif);
        //testComputeSign(JCconstants.ALG_RSA_PKCS1, (byte) 2, (byte) 3);
        //TestComputeSign(JCconstants.ALG_ECDSA_SHA256, (byte) 4, (byte) 5);
        //TestComputeSign(JCconstants.CM_ECDSA_SHA, (byte) 4, (byte) 5);
        
        // list key
        byte[] response;
        response= cc.cardGetStatus();
        CardDataParser.CardStatus cardstatus = new CardDataParser.CardStatus(response);
        System.out.println(cardstatus.toString());
        response=cc.cardListKeys();
        CardDataParser.KeyList keylist = new CardDataParser.KeyList(response);
        System.out.println(keylist.toString());
        
    }
    public static void testCardGenerateKeyPair(byte alg_type, byte priv_key_nbr, byte pub_key_nbr, short key_size) throws CardConnectorException{

        byte[] priv_key_ACL= DEFAULT_ACL; // {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] pub_key_ACL= DEFAULT_ACL; //{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte gen_opt= JCconstants.OPT_DEFAULT;
        byte[] gen_opt_param={};
        String stralg="";
        if (alg_type==JCconstants.ALG_RSA)
            stralg="RSA";
        else if (alg_type==JCconstants.ALG_RSA_CRT)
            stralg="RSA-CRT";
        else if (alg_type==JCconstants.ALG_EC_FP){
            stralg="ECC";
            gen_opt= JCconstants.OPT_EC_SECP256k1;
        }
        else{
            System.out.println("\t ERROR: algorithm not supported!");
            return;
        } 

        System.out.println("\t Test GenerateKey(alg="+stralg + 
                            ", priv="+ (int)priv_key_nbr+
                            ", pub="+ (int)pub_key_nbr+
                            ", keysize="+ key_size+")"); 
        cc.cardGenerateKeyPair( 
                        priv_key_nbr, pub_key_nbr, alg_type, key_size, 
                        priv_key_ACL, pub_key_ACL, gen_opt, gen_opt_param);        
    }
    public static byte[] testGetPublicKeyFromPrivate(byte keynbr) throws Exception{

        byte[] response= cc.cardGetPublicKeyFromPrivate(keynbr);
        
        CardDataParser.PubKeyData parser = new CardDataParser.PubKeyData();
        byte[] pubkey= parser.parseGetPublicKeyFromPrivate(response).pubkey;
        return pubkey;
    }
    public static void testComputeSign(byte CM, byte key_sign, byte key_verif) throws CardConnectorException{
        byte[] buffer= new byte[512];
        Arrays.fill(buffer, (byte)30);
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
        System.out.println("\t Test ComputeSign(CM="+stralg+", keynb_sign="+key_sign+")");
        byte[] signature= cc.cardComputeSign(key_sign, CM, JCconstants.MODE_SIGN, buffer, null); //  16 first bits for size
        System.out.println("Data length:" + buffer.length);
        System.out.println("signature after:" + toHexString(signature));

        // computeverify
        System.out.println("\t Test ComputeVerify(CM="+stralg+", keynb="+key_verif+")");
        byte[] response= cc.cardComputeSign(key_verif, CM, JCconstants.MODE_VERIFY, buffer, signature);

        System.out.println("\t Verify signature with wrong data:");
        response= cc.cardComputeSign(key_verif, CM, JCconstants.MODE_VERIFY, buffer_wrong, signature);
        System.out.println("\n\n");
    }

    /**
     * Test of cardComputeSha512 method, of class CardConnector.
     */
    @Test
    public void testCardComputeSha512() throws Exception {
        System.out.println("cardComputeSha512");
        
        ArrayList<byte[]> msg_list= new ArrayList<>();
        ArrayList<String> hash_list= new ArrayList<>();
        
        msg_list.add(new byte[0]);
        hash_list.add("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        msg_list.add(new byte[] {'a','b','c'});
        hash_list.add("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        
        for (int i= 0; i<msg_list.size(); i++){
            byte[] response=null;
            try{
                response= cc.cardComputeSha512(msg_list.get(i));   
                assertArrayEquals(response, hash_list.get(i).getBytes());
                //System.out.println("hash expected:"+hash_list.get(i));
                //System.out.println("hash computed:"+toHexString(response));            
            }
            catch (CardConnectorException ex) {
                System.out.println("CardConnectorException: "+ex.getMessage()+" "+Integer.toHexString(ex.getIns() & 0xff)+" "+Integer.toHexString(ex.getSW12() & 0xffff));
                if (ex.getSW12()!=0x6d00) // sha512 may be unsupported (only for debugging)
                    fail("Wrong sha512");
            }            
        }
    }

    /**
     * Test of cardComputeHmac method, of class CardConnector.
     */
    @Test
    public void testCardComputeHmac() throws Exception {
        System.out.println("cardComputeHmac");
        
        ArrayList<String> msg_list= new ArrayList<>();
        ArrayList<String> key_list= new ArrayList<>();
        
        key_list.add("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        key_list.add("4a656665");
        msg_list.add("4869205468657265"); 
        msg_list.add("7768617420646f2079612077616e7420666f72206e6f7468696e673f"); 
        msg_list.add("53616D706C6520233200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        
        for (int i= 0; i<msg_list.size(); i++){
            for (int j= 0; j<key_list.size(); j++){
                byte[] bmsg= DatatypeConverter.parseHexBinary(msg_list.get(i));
                byte[] bkey= DatatypeConverter.parseHexBinary(key_list.get(j)); 
                
                // sw
                byte[] hmac160_sw, hmac512_sw;
                // get an hmac_sha1 key from the raw key bytes
                SecretKeySpec key160 = new SecretKeySpec(bkey, "HmacSHA1");
                SecretKeySpec key512 = new SecretKeySpec(bkey, "HmacSHA512");
                // get an hmac_sha1 Mac instance and initialize with the signing key
                Mac mac160 = Mac.getInstance("HmacSHA1");
                mac160.init(key160);
                Mac mac512 = Mac.getInstance("HmacSHA512");
                mac512.init(key512);
                // compute the hmac on input data bytes
                hmac160_sw = mac160.doFinal(bmsg);
                hmac512_sw = mac512.doFinal(bmsg);

                //hw
                byte[] hmac160_hw= cc.cardComputeHmac((byte)20, bkey, bmsg); 
                byte[] hmac512_hw= cc.cardComputeHmac((byte)64, bkey, bmsg); 

                assertArrayEquals(hmac160_sw, hmac160_hw);
                assertArrayEquals(hmac512_sw, hmac512_hw);
                //System.out.println("hash expected:"+hmac_list.get(i));
                //System.out.println("hash computed:"+toHexString(response));
            }
        }    
//        byte[] msg=DatatypeConverter.parseHexBinary("53616D706C6520233200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
//        byte[] key= new byte[20];
//        byte[] expResult = DatatypeConverter.parseHexBinary("C2462735FF0C2C7BE828E7947DADE721AB291BF5");
    }

    /**
     * Test of cardCreatePIN method, of class CardConnector.
     */
    @Test
    public void testCardPIN() throws Exception {
        
        System.out.println("cardCreatePIN");
        byte[] response;
        try {
            response = cc.cardCreatePIN(pin2_nbr, pin2_tries, pin2, ublk2);
        } catch (CardConnectorException ex) {
            if (ex.getSW12()==JCconstants.SW_INCORRECT_P1)
                System.out.println("PIN exists already!");
            else
                throw ex;
        }
        
        System.out.println("cardVerifyPIN");
        response = cc.cardVerifyPIN(pin2_nbr, pin2);
        
        System.out.println("cardChangePIN");
        byte[] new_pin = {33,33,33,33};
        response = cc.cardChangePIN(pin2_nbr, pin2, new_pin);
        
        System.out.println("cardVerifyPIN (new PIN)");
        response = cc.cardVerifyPIN(pin2_nbr, new_pin);
        
        System.out.println("cardChangePIN (back to old PIN)");
        response = cc.cardChangePIN(pin2_nbr, new_pin, pin2);
        
    }

    /**
     * Test of cardCreateObject method, of class CardConnector.
     */
    @Test
    public void testCardCreateObject() throws Exception {
        System.out.println("cardCreateObject");
        System.out.println("cardWriteObject");
        System.out.println("cardReadObject");
        System.out.println("cardDeleteObject");
        byte[] objACL= DEFAULT_ACL;//{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int objId=123456;
        
        for (int size=1; size<65536; size=size*2){
            System.out.println("\t size:"+size);
            byte[] objData= new byte[size];
            Arrays.fill(objData, (byte)0x00);

            try{
                cc.cardCreateObject(objId, size, objACL);
            }
            catch (CardConnectorException ex) {
                if (ex.getSW12()==JCconstants.SW_OBJECT_EXISTS){
                    System.out.println("TestObject - delete existing object!");
                    cc.cardDeleteObject(objId, (byte)0x01);
                }
                if (ex.getSW12()==JCconstants.SW_NO_MEMORY_LEFT){
                    System.out.println("TestObject - out of memory!");
                    //cc.cardDeleteObject(objId, (byte)0x01);
                    return;
                }
            }
            cc.cardWriteObject(objId, objData);
            byte[] objCopy= cc.cardReadObject(objId);
            assertArrayEquals(objData,objCopy);    
            int objSize= cc.cardGetObjectSize(objId);
            assertEquals(objSize,objCopy.length);    
            cc.cardDeleteObject(objId, (byte)0x01);
        }      
    }

    /**
     * Test of cardGetStatus method, of class CardConnector.
     */
    @Test
    public void testCardGetStatus() throws Exception {
        System.out.println("cardGetStatus");
        byte[] response= cc.cardGetStatus();
        CardDataParser.CardStatus parser= new CardDataParser.CardStatus(response);
        System.out.println(parser.toString());
    }
    
}
