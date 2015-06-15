/**
 * Copyright 2011 Google Inc.
 * Copyright 2013-2014 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.toporin.bitcoincore;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve; 
import static org.satochip.satochipclient.CardDataParser.toHexString;

/**
 * ECKey supports elliptic curve cryptographic operations using a public/private
 * key pair.  A private key is required to create a signature and a public key is
 * required to verify a signature.  The private key is always encrypted using AES
 * when it is serialized for storage on external media.
 */
public class ECKey {

    /** Half-curve order for generating canonical S */
    public static final BigInteger HALF_CURVE_ORDER;

    /** Elliptic curve parameters (secp256k1 curve) */
    private static final ECDomainParameters ecParams;
    static {
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        HALF_CURVE_ORDER = params.getN().shiftRight(1);
    }

    /** Signed message header */
    protected static final String BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n";

    /** Key label */
    private String label = "";

    /** Public key */
    protected byte[] pubKey;

    /** Public key hash */
    protected byte[] pubKeyHash;

    /** Key creation time (seconds) */
    protected long creationTime;

    /** Compressed public key */
    protected boolean isCompressed;

    /** Change key */
    private boolean isChange;

    /**
     * Creates an ECKey with the supplied public key. The 'compressed' parameter
     * determines the type of public key created
     *
     * @param       pubKey              Public key or null
     * @param       compressed          TRUE to create a compressed public key
     */
    public ECKey(byte[] pubKey) {
        if (pubKey != null) {
            this.pubKey = pubKey;
            isCompressed = (pubKey.length==33);
        } else {
            throw new IllegalArgumentException("You must provide a public key");
        }
        creationTime = System.currentTimeMillis()/1000;
    }
    
    /**
     * Checks if the public key is canonical
     *
     * @param       pubKeyBytes         Public key
     * @return                          TRUE if the key is canonical
     */
    public static boolean isPubKeyCanonical(byte[] pubKeyBytes) {
        boolean isValid = false;
        if (pubKeyBytes.length == 33 && (pubKeyBytes[0] == (byte)0x02 || pubKeyBytes[0] == (byte)0x03)) {
            isValid = true;
        } else if (pubKeyBytes.length == 65 && pubKeyBytes[0] == (byte)0x04) {
            isValid = true;
        }
        return isValid;
    }

    /**
     * Checks if the signature is DER-encoded
     *
     * @param       encodedSig          Encoded signature
     * @return                          TRUE if the signature is DER-encoded
     */
    public static boolean isSignatureCanonical(byte[] encodedSig) {
        //
        // DER-encoding requires that there is only one representation for a given
        // encoding.  This means that no pad bytes are inserted for numeric values.
        //
        // An ASN.1 sequence is identified by 0x30 and each primitive by a type field.
        // An integer is identified as 0x02.  Each field type is followed by a field length.
        // For valid R and S values, the length is a single byte since R and S are both
        // 32-byte or 33-byte values (a leading zero byte is added to ensure a positive
        // value if the sign bit would otherwise bet set).
        //
        // Bitcoin appends that hash type to the end of the DER-encoded signature.  We require
        // this to be a single byte for a canonical signature.
        //
        // The length is encoded in the lower 7 bits for lengths between 0 and 127 and the upper bit is 0.
        // Longer length have the upper bit set to 1 and the lower 7 bits contain the number of bytes
        // in the length.
        //

        //
        // An ASN.1 sequence is 0x30 followed by the length
        //
        if (encodedSig.length<2 || encodedSig[0]!=(byte)0x30 || (encodedSig[1]&0x80)!=0)
            return false;
        //
        // Get length of sequence
        //
        int length = ((int)encodedSig[1]&0x7f) + 2;
        int offset = 2;
        //
        // Check R
        //
        if (offset+2>length || encodedSig[offset]!=(byte)0x02 || (encodedSig[offset+1]&0x80)!=0)
            return false;
        int rLength = (int)encodedSig[offset+1]&0x7f;
        if (offset+rLength+2 > length)
            return false;
        if (encodedSig[offset+2]==0x00 && (encodedSig[offset+3]&0x80)==0)
            return false;
        offset += rLength + 2;
        //
        // Check S
        //
        if (offset+2>length || encodedSig[offset]!=(byte)0x02 || (encodedSig[offset+1]&0x80)!=0)
            return false;
        int sLength = (int)encodedSig[offset+1]&0x7f;
        if (offset+sLength+2 > length)
            return false;
        if (encodedSig[offset+2]==0x00 && (encodedSig[offset+3]&0x80)==0)
            return false;
        offset += sLength + 2;
        //
        // There must be a single byte appended to the signature
        //
        return (offset == encodedSig.length-1);
    }

    /**
     * Returns the key creation time
     *
     * @return      Key creation time (seconds)
     */
    public long getCreationTime() {
        return creationTime;
    }

    /**
     * Sets the key creation time
     *
     * @param       creationTime        Key creation time (seconds)
     */
    public void setCreationTime(long creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * Returns the key label
     *
     * @return      Key label
     */
    public String getLabel() {
        return label;
    }

    /**
     * Sets the key label
     *
     * @param       label               Key label
     */
    public void setLabel(String label) {
        this.label = label;
    }

    /**
     * Checks if this is a change key
     *
     * @return                          TRUE if this is a change key
     */
    public boolean isChange() {
        return isChange;
    }

    /**
     * Sets change key status
     *
     * @param       isChange            TRUE if this is a change key
     */
    public void setChange(boolean isChange) {
        this.isChange = isChange;
    }

    /**
     * Returns the public key (as used in transaction scriptSigs).  A compressed
     * public key is 33 bytes and starts with '02' or '03' while an uncompressed
     * public key is 65 bytes and starts with '04'.
     *
     * @return                          Public key
     */
    public byte[] getPubKey() {
        return pubKey;
    }

    /**
     * Returns the public key hash as used in addresses.  The hash is 20 bytes.
     *
     * @return                          Public key hash
     */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256Hash160(pubKey);
        return pubKeyHash;
    }

    /**
     * Checks if the public key is compressed
     *
     * @return                          TRUE if the public key is compressed
     */
    public boolean isCompressed() {
        return isCompressed;
    }

    /**
     * Verifies a signature for the signed contents using the public key
     *
     * @param       contents            The signed contents
     * @param       signature           DER-encoded signature
     * @return                          TRUE if the signature if valid, FALSE otherwise
     * @throws      ECException         Unable to verify the signature
     */
    public boolean verifySignature(byte[] contents, byte[] signature) throws ECException {
        boolean isValid = false;
        //
        // Decode the DER-encoded signature and get the R and S values
        //
        ECDSASignature sig = new ECDSASignature(signature);
        //
        // Get the double SHA-256 hash of the signed contents
        //
        // A null contents will result in a hash with the first byte set to 1 and
        // all other bytes set to 0.  This is needed to handle a bug in the reference
        // client where it doesn't check for an error when serializing a transaction
        // and instead uses the error code as the hash.
        //
        byte[] contentsHash;
        if (contents != null) {
            contentsHash = Utils.doubleDigest(contents);
        } else {
            contentsHash = new byte[32];
            contentsHash[0] = 0x01;
        }
        //
        // Verify the signature
        //
        try {
            ECDSASigner signer = new ECDSASigner();
            ECPublicKeyParameters params = new ECPublicKeyParameters(
                                                ecParams.getCurve().decodePoint(pubKey), ecParams);
            signer.init(false, params);
            isValid = signer.verifySignature(contentsHash, sig.getR(), sig.getS());
        } catch (RuntimeException exc) {
            throw new ECException("Exception while verifying signature: "+exc.getMessage());
        }
        return isValid;
    }

    /**
     * <p>Given the components of a signature and a selector value, recover and return the public key
     * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.</p>
     *
     * <p>The recID is an index from 0 to 3 which indicates which of the 4 possible keys is the correct one.
     * Because the key recovery operation yields multiple potential keys, the correct key must either be
     * stored alongside the signature, or you must be willing to try each recId in turn until you find one
     * that outputs the key you are expecting.</p>
     *
     * <p>If this method returns null, it means recovery was not possible and recID should be iterated.</p>
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from 0 to 3, and if the
     * output is null OR a key that is not the one you expect, you try again with the next recID.</p>
     *
     * @param       recID               Which possible key to recover.
     * @param       sig                 R and S components of the signature
     * @param       e                   The double SHA-256 hash of the original message
     * @param       compressed          Whether or not the original public key was compressed
     * @return      An ECKey containing only the public part, or null if recovery wasn't possible
     */
    protected static ECKey recoverFromSignature(int recID, ECDSASignature sig, BigInteger e, boolean compressed) {
        BigInteger n = ecParams.getN();
        BigInteger i = BigInteger.valueOf((long)recID / 2);
        BigInteger x = sig.getR().add(i.multiply(n));
        //
        //   Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs 'invalid', then
        //        do another iteration.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        //
        SecP256K1Curve curve = (SecP256K1Curve)ecParams.getCurve();
        BigInteger prime = curve.getQ();
        if (x.compareTo(prime) >= 0) {
            return null;
        }
        //
        // Compressed keys require you to know an extra bit of data about the y-coordinate as
        // there are two possibilities.  So it's encoded in the recID.
        //
        ECPoint R = decompressKey(x, (recID & 1) == 1);
        if (!R.multiply(n).isInfinity())
            return null;
        //
        //   For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
        //     Compute a candidate public key as:
        //       Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
        // In the above equation, ** is point multiplication and + is point addition (the EC group operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
        //
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.getR().modInverse(n);
        BigInteger srInv = rInv.multiply(sig.getS()).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(ecParams.getG(), eInvrInv, R, srInv);
        return new ECKey(q.getEncoded(compressed));
    }

    public static byte[] recoverFromSignature(int recID, byte[] msg, byte[] sig, boolean doublehash) throws ECException{
        
        //return CardConnector.recoverPublicKeyFromSig(recID, msg, sig, doublehash);
        
        byte[] digest= new byte[32];
        SHA256Digest sha256= new SHA256Digest();
        sha256.reset();
        sha256.update(msg, 0, msg.length);
        sha256.doFinal(digest, 0);
        if (doublehash){
            sha256.reset();
            sha256.update(digest, 0, digest.length);
            sha256.doFinal(digest, 0);
        }
        BigInteger bi= new BigInteger(1,digest);
        ECDSASignature ecdsaSig= new ECDSASignature(sig);
        ECKey k= ECKey.recoverFromSignature(recID, ecdsaSig, bi, true);
        
        if (k!=null)
            return k.getPubKey();
        else
            return null;
        
    }
    
    public static byte[] recoverFromSignature(byte[] coordx, byte[] msg, byte[] sig, boolean doublehash) throws ECException{
        byte[] pubkey= null;
        int recID =-1;
        for (int i=0; i<4; i++){
            pubkey= recoverFromSignature(i, msg, sig, doublehash);
            if (pubkey!=null){
                byte[] coordxkey= Arrays.copyOfRange(pubkey, 1, 1+coordx.length);
                if (Arrays.equals(coordx,coordxkey)){
                    recID=i;
                    return pubkey;
                }
            }
        }
        if (recID == -1)
            throw new ECException("Unable to recover public key from signature");        
        
        return pubkey;    
    }
    public static int recidFromSignature(byte[] coordx, byte[] msg, byte[] sig, boolean doublehash) throws ECException{
        
        byte[] pubkey= null;
        int recID =-1;
        for (int i=0; i<4; i++){
            pubkey= recoverFromSignature(i, msg, sig, doublehash);
            if (pubkey!=null){
                byte[] coordxkey= Arrays.copyOfRange(pubkey, 1, 1+coordx.length);
                if (Arrays.equals(coordx,coordxkey)){
                    recID=i;
                    return recID;
                }
            }
        }
        if (recID == -1)
            throw new ECException("Unable to recover public key from signature");        
        
        return recID;    
    }
    
    
    /**
     * Decompress a compressed public key (x coordinate and low-bit of y-coordinate).
     *
     * @param       xBN                 X-coordinate
     * @param       yBit                Sign of Y-coordinate
     * @return                          Uncompressed public key
     */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        SecP256K1Curve curve = (SecP256K1Curve)ecParams.getCurve();
        ECFieldElement x = curve.fromBigInteger(xBN);
        ECFieldElement alpha = x.multiply(x.square().add(curve.getA())).add(curve.getB());
        ECFieldElement beta = alpha.sqrt();
        if (beta == null)
            throw new IllegalArgumentException("Invalid point compression");
        ECPoint ecPoint;
        BigInteger nBeta = beta.toBigInteger();
        if (nBeta.testBit(0) == yBit) {
            ecPoint = curve.createPoint(x.toBigInteger(), nBeta);
        } else {
            ECFieldElement y = curve.fromBigInteger(curve.getQ().subtract(nBeta));
            ecPoint = curve.createPoint(x.toBigInteger(), y.toBigInteger());
        }
        return ecPoint;
    }

    /**
     * Checks if two objects are equal
     *
     * @param       obj             The object to check
     * @return                      TRUE if the object is equal
     */
    @Override
    public boolean equals(Object obj) {
        return (obj!=null && (obj instanceof ECKey) && Arrays.equals(pubKey, ((ECKey)obj).pubKey));
    }

    /**
     * Returns the hash code for this object
     *
     * @return                      Hash code
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(pubKey);
    }
}
