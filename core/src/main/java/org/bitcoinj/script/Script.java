/*
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2018 the bitcoinj-cash developers
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
 *
 * This file has been modified by the bitcoinj-cash developers for the bitcoinj-cash project.
 * The original file was from the bitcoinj project (https://github.com/bitcoinj/bitcoinj).
 */

package org.bitcoinj.script;

import org.bitcoinj.core.*;
import org.bitcoinj.core.VerificationException.*;

import org.bitcoinj.crypto.TransactionSignature;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.RIPEMD160Digest;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.bitcoinj.script.ScriptOpCodes.*;
import static com.google.common.base.Preconditions.*;

// TODO: Redesign this entire API to be more type safe and organised.

/**
 * <p>Programs embedded inside transactions that control redemption of payments.</p>
 *
 * <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.</p>
 *
 * <p>In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight
 * clients don't have that data. In full mode, this class is used to run the interpreted language. It also has
 * static methods for building scripts.</p>
 */
public class Script {

    /** Enumeration to encapsulate the type of this script. */
    public enum ScriptType {
        // Do NOT change the ordering of the following definitions because their ordinals are stored in databases.
        NO_TYPE,
        P2PKH,
        PUB_KEY,
        P2SH
    }

    /** Flags to pass to {@link Script#correctlySpends(Transaction, long, Script, Coin, Set)}.
     * Note currently only P2SH, DERSIG and NULLDUMMY are actually supported.
     */
    public enum VerifyFlag {
        P2SH, // Enable BIP16-style subscript evaluation.
        STRICTENC, // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        DERSIG, // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP66 rule 1)
        LOW_S, // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        NULLDUMMY, // Verify dummy stack item consumed by CHECKMULTISIG is of zero-length.
        SIGPUSHONLY, // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
        MINIMALDATA, // Require minimal encodings for all push operations and number encodings
        DISCOURAGE_UPGRADABLE_NOPS, // Discourage use of NOPs reserved for upgrades (NOP1-10)
        MINIMALIF,
        NULLFAIL,
        CLEANSTACK, // Require that only a single stack element remains after evaluation.
        CHECKLOCKTIMEVERIFY, // Enable CHECKLOCKTIMEVERIFY operation
        CHECKSEQUENCEVERIFY,
        SIGHASH_FORKID,
        REPLAY_PROTECTION,
        MONOLITH_OPCODES, // May 15, 2018 Hard fork
        PUBKEYTYPE, // June 26, 29018.
        MAGNETIC_OPCODES // November 15, 2018 Hard fork
    }

    // The outcome of the script execution is affected by the Verification flags used. The more verifications are
    // implemented, the more restrictions are applied on it. The ALL_VERIFY_FLAGS variable is used to store those
    // verifications that can be used as a Basis for executing and validating a Script. So this Set of Flags is used
    // through the Bitcoin-core and several tests when some script needs to be executed.
    // After the implementation of the last verification Flags, including all of them in this Set is not safe anymore,
    // since some of these flags affect the outcome of the script to a big extent, which can make other legacy tests
    // to fail.
    // For instance, the SIGHASH_FORKID Flag forces the Script engine to expect all the Signatures to have the SIGHASH
    // FORK ID bit set. The REPLAY_PROTECTION flag, on the other hand, changes the way the Transaction Hash is
    // calculated.
    // A possible solution might be to parameterize all the calls to the Script Engine, adding the Flags as a new
    // parameter, and refactor the whole project so every single call needs to acknowledge the Verification Flags used.
    // This refactoring is a possible solution. At this moment, and in order not to break the existing code and the
    // legacy tests, we remove from the SET those flags which affect the Script the most and might break the legacy code

    public static final EnumSet<VerifyFlag> ALL_VERIFY_FLAGS = EnumSet.complementOf(EnumSet.of(VerifyFlag.SIGHASH_FORKID, VerifyFlag.REPLAY_PROTECTION));


    private static final Logger log = LoggerFactory.getLogger(Script.class);
    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
    public static final int DEFAULT_MAX_NUM_ELEMENT_SIZE = 4;
    public static final int SIG_SIZE = 75;
    /** Max number of sigops allowed in a standard p2sh redeem script */
    public static final int MAX_P2SH_SIGOPS = 15;

    // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    protected List<ScriptChunk> chunks;
    // Unfortunately, scripts are not ever re-serialized or canonicalized when used in signature hashing. Thus we
    // must preserve the exact bytes that we read off the wire, along with the parsed form.
    protected byte[] program;

    // Creation time of the associated keys in seconds since the epoch.
    private long creationTimeSeconds;

    /** Creates an empty script that serializes to nothing. */
    private Script() {
        chunks = Lists.newArrayList();
    }

    // Used from ScriptBuilder.
    Script(List<ScriptChunk> chunks) {
        this.chunks = Collections.unmodifiableList(new ArrayList<ScriptChunk>(chunks));
        creationTimeSeconds = Utils.currentTimeSeconds();
    }

    /**
     * Construct a Script that copies and wraps the programBytes array. The array is parsed and checked for syntactic
     * validity.
     * @param programBytes Array of program bytes from a transaction.
     */
    public Script(byte[] programBytes) {
        program = programBytes;
        parse(programBytes);
        creationTimeSeconds = 0;
    }

    public Script(byte[] programBytes, long creationTimeSeconds) {
        program = programBytes;
        parse(programBytes);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Returns the program opcodes as a string, for example "[1234] DUP HASH160"
     */
    @Override
    public String toString() {
        return Utils.join(chunks);
    }

    /** Returns the serialized program as a newly created byte array. */
    public byte[] getProgram() {
        try {
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            if (program != null)
                return Arrays.copyOf(program, program.length);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (ScriptChunk chunk : chunks) {
                chunk.write(bos);
            }
            program = bos.toByteArray();
            return program;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns an immutable list of the scripts parsed form. Each chunk is either an opcode or data element. */
    public List<ScriptChunk> getChunks() {
        return Collections.unmodifiableList(chunks);
    }

    private static final ScriptChunk[] STANDARD_TRANSACTION_SCRIPT_CHUNKS = {
        new ScriptChunk(ScriptOpCodes.OP_DUP, null, 0),
        new ScriptChunk(ScriptOpCodes.OP_HASH160, null, 1),
        new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null, 23),
        new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null, 24),
    };

    /**
     * <p>To run a script, first we parse it which breaks it up into chunks representing pushes of data or logical
     * opcodes. Then we can run the parsed chunks.</p>
     *
     * <p>The reason for this split, instead of just interpreting directly, is to make it easier
     * to reach into a programs structure and pull out bits of data without having to run it.
     * This is necessary to render the to/from addresses of transactions in a user interface.
     * Bitcoin Core does something similar.</p>
     */
    private void parse(byte[] program) {
        chunks = new ArrayList<ScriptChunk>(5);   // Common size.
        ByteArrayInputStream bis = new ByteArrayInputStream(program);
        int initialSize = bis.available();
        while (bis.available() > 0) {
            int startLocationInProgram = initialSize - bis.available();
            int opcode = bis.read();

            long dataToRead = -1;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                dataToRead = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (bis.available() < 1)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "an illegal opcode is present in the script");
                dataToRead = bis.read();
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                if (bis.available() < 2)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");

                dataToRead = bis.read() | (bis.read() << 8);
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if (bis.available() < 4) throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");
                dataToRead = ((long)bis.read()) | (((long)bis.read()) << 8) | (((long)bis.read()) << 16) | (((long)bis.read()) << 24);
            }

            ScriptChunk chunk;
            if (dataToRead == -1) {
                chunk = new ScriptChunk(opcode, null, startLocationInProgram);
            } else {
                if (dataToRead > bis.available())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "an illegal opcode is present in the script");
                byte[] data = new byte[(int)dataToRead];
                checkState(dataToRead == 0 || bis.read(data, 0, (int)dataToRead) == dataToRead);
                chunk = new ScriptChunk(opcode, data, startLocationInProgram);
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for (ScriptChunk c : STANDARD_TRANSACTION_SCRIPT_CHUNKS) {
                if (c.equals(chunk)) chunk = c;
            }
            chunks.add(chunk);
        }
    }

    /**
     * Returns true if this script is of the form <pubkey> OP_CHECKSIG. This form was originally intended for transactions
     * where the peers talked to each other directly via TCP/IP, but has fallen out of favor with time due to that mode
     * of operation being susceptible to man-in-the-middle attacks. It is still used in coinbase outputs and can be
     * useful more exotic types of transaction, but today most payments are to addresses.
     */
    public boolean isSentToRawPubKey() {
        return chunks.size() == 2 && chunks.get(1).equalsOpCode(OP_CHECKSIG) &&
               !chunks.get(0).isOpCode() && chunks.get(0).data.length > 1;
    }

    /**
     * Returns true if this script is of the form DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG, ie, payment to an
     * address like 1VayNert3x1KzbpzMGt2qdqrAThiRovi8. This form was originally intended for the case where you wish
     * to send somebody money with a written code because their node is offline, but over time has become the standard
     * way to make payments due to the short and recognizable base58 form addresses come in.
     */
    public boolean isSentToAddress() {
        return chunks.size() == 5 &&
               chunks.get(0).equalsOpCode(OP_DUP) &&
               chunks.get(1).equalsOpCode(OP_HASH160) &&
               chunks.get(2).data.length == Address.LENGTH &&
               chunks.get(3).equalsOpCode(OP_EQUALVERIFY) &&
               chunks.get(4).equalsOpCode(OP_CHECKSIG);
    }

    /**
     * An alias for isPayToScriptHash.
     */
    @Deprecated
    public boolean isSentToP2SH() {
        return isPayToScriptHash();
    }

    /**
     * <p>If a program matches the standard template DUP HASH160 &lt;pubkey hash&gt; EQUALVERIFY CHECKSIG
     * then this function retrieves the third element.
     * In this case, this is useful for fetching the destination address of a transaction.</p>
     * 
     * <p>If a program matches the standard template HASH160 &lt;script hash&gt; EQUAL
     * then this function retrieves the second element.
     * In this case, this is useful for fetching the hash of the redeem script of a transaction.</p>
     * 
     * <p>Otherwise it throws a ScriptException.</p>
     *
     */
    public byte[] getPubKeyHash() {
        if (isSentToAddress())
            return chunks.get(2).data;
        else if (isPayToScriptHash())
            return chunks.get(1).data;
        else
            throw new ScriptException(ScriptError.SCRIPT_ERR_STANDARD, "script is not a recognized standard script");
    }

    /**
     * Returns the public key in this script. If a script contains two constants and nothing else, it is assumed to
     * be a scriptSig (input) for a pay-to-address output and the second constant is returned (the first is the
     * signature). If a script contains a constant and an OP_CHECKSIG opcode, the constant is returned as it is
     * assumed to be a direct pay-to-key scriptPubKey (output) and the first constant is the public key.
     *
     * @throws ScriptException if the script is none of the named forms.
     */
    public byte[] getPubKey() {
        if (chunks.size() != 2) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");
        }
        final ScriptChunk chunk0 = chunks.get(0);
        final byte[] chunk0data = chunk0.data;
        final ScriptChunk chunk1 = chunks.get(1);
        final byte[] chunk1data = chunk1.data;
        if (chunk0data != null && chunk0data.length > 2 && chunk1data != null && chunk1data.length > 2) {
            // If we have two large constants assume the input to a pay-to-address output.
            return chunk1data;
        } else if (chunk1.equalsOpCode(OP_CHECKSIG) && chunk0data != null && chunk0data.length > 2) {
            // A large constant followed by an OP_CHECKSIG is the key.
            return chunk0data;
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");
        }
    }

    /**
     * Retrieves the sender public key from a LOCKTIMEVERIFY transaction
     * @throws ScriptException
     */
    public byte[] getCLTVPaymentChannelSenderPubKey() {
        if (!isSentToCLTVPaymentChannel()) {
            throw new ScriptException("Script not a standard CHECKLOCKTIMVERIFY transaction: " + this);
        }
        return chunks.get(8).data;
    }

    /**
     * Retrieves the recipient public key from a LOCKTIMEVERIFY transaction
     * @throws ScriptException
     */
    public byte[] getCLTVPaymentChannelRecipientPubKey() {
        if (!isSentToCLTVPaymentChannel()) {
            throw new ScriptException("Script not a standard CHECKLOCKTIMVERIFY transaction: " + this);
        }
        return chunks.get(1).data;
    }

    public BigInteger getCLTVPaymentChannelExpiry() {
        if (!isSentToCLTVPaymentChannel()) {
            throw new ScriptException("Script not a standard CHECKLOCKTIMEVERIFY transaction: " + this);
        }
        //FIXME We may actually need to enforce minimal encoding here.  But we don't have access
        //to the verify flags
        return castToBigInteger(chunks.get(4).data, 5, false);
    }

    /**
     * For 2-element [input] scripts assumes that the paid-to-address can be derived from the public key.
     * The concept of a "from address" isn't well defined in Bitcoin and you should not assume the sender of a
     * transaction can actually receive coins on it. This method may be removed in future.
     */
    @Deprecated
    public Address getFromAddress(NetworkParameters params) {
        return new Address(params, Utils.sha256hash160(getPubKey()));
    }

    /**
     * Gets the destination address from this script, if it's in the required form (see getPubKey).
     */
    public Address getToAddress(NetworkParameters params) {
        return getToAddress(params, false);
    }

    /**
     * Gets the destination address from this script, if it's in the required form (see getPubKey).
     * 
     * @param forcePayToPubKey
     *            If true, allow payToPubKey to be casted to the corresponding address. This is useful if you prefer
     *            showing addresses rather than pubkeys.
     */
    public Address getToAddress(NetworkParameters params, boolean forcePayToPubKey) {
        if (isSentToAddress())
            return new Address(params, getPubKeyHash());
        else if (isPayToScriptHash())
            return Address.fromP2SHScript(params, this);
        else if (forcePayToPubKey && isSentToRawPubKey())
            return ECKey.fromPublicOnly(getPubKey()).toAddress(params);
        else
            throw new ScriptException("Cannot cast this script to a pay-to-address type");
    }

    ////////////////////// Interface for writing scripts from scratch ////////////////////////////////

    /**
     * Writes out the given byte buffer to the output stream with the correct opcode prefix
     * To write an integer call writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(val, false)));
     */
    public static void writeBytes(OutputStream os, byte[] buf) throws IOException {
        if (buf.length < OP_PUSHDATA1) {
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 256) {
            os.write(OP_PUSHDATA1);
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 65536) {
            os.write(OP_PUSHDATA2);
            os.write(0xFF & (buf.length));
            os.write(0xFF & (buf.length >> 8));
            os.write(buf);
        } else {
            throw new RuntimeException("Unimplemented");
        }
    }

    /** Creates a program that requires at least N of the given keys to sign, using OP_CHECKMULTISIG. */
    public static byte[] createMultiSigOutputScript(int threshold, List<ECKey> pubkeys) {
        checkArgument(threshold > 0);
        checkArgument(threshold <= pubkeys.size());
        checkArgument(pubkeys.size() <= 16);  // That's the max we can represent with a single opcode.
        if (pubkeys.size() > 3) {
            log.warn("Creating a multi-signature output that is non-standard: {} pubkeys, should be <= 3", pubkeys.size());
        }
        try {
            ByteArrayOutputStream bits = new ByteArrayOutputStream();
            bits.write(encodeToOpN(threshold));
            for (ECKey key : pubkeys) {
                writeBytes(bits, key.getPubKey());
            }
            bits.write(encodeToOpN(pubkeys.size()));
            bits.write(OP_CHECKMULTISIG);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static byte[] createInputScript(byte[] signature, byte[] pubkey) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + pubkey.length + 2);
            writeBytes(bits, signature);
            writeBytes(bits, pubkey);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] createInputScript(byte[] signature) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + 2);
            writeBytes(bits, signature);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates an incomplete scriptSig that, once filled with signatures, can redeem output containing this scriptPubKey.
     * Instead of the signatures resulting script has OP_0.
     * Having incomplete input script allows to pass around partially signed tx.
     * It is expected that this program later on will be updated with proper signatures.
     */
    public Script createEmptyInputScript(@Nullable ECKey key, @Nullable Script redeemScript) {
        if (isSentToAddress()) {
            checkArgument(key != null, "Key required to create pay-to-address input script");
            return ScriptBuilder.createInputScript(null, key);
        } else if (isSentToRawPubKey()) {
            return ScriptBuilder.createInputScript(null);
        } else if (isPayToScriptHash()) {
            checkArgument(redeemScript != null, "Redeem script required to create P2SH input script");
            return ScriptBuilder.createP2SHMultiSigInputScript(null, redeemScript);
        } else {
            throw new ScriptException("Do not understand script type: " + this);
        }
    }

    /**
     * Returns a copy of the given scriptSig with the signature inserted in the given position.
     */
    public Script getScriptSigWithSignature(Script scriptSig, byte[] sigBytes, int index) {
        int sigsPrefixCount = 0;
        int sigsSuffixCount = 0;
        if (isPayToScriptHash()) {
            sigsPrefixCount = 1; // OP_0 <sig>* <redeemScript>
            sigsSuffixCount = 1;
        } else if (isSentToMultiSig()) {
            sigsPrefixCount = 1; // OP_0 <sig>*
        } else if (isSentToAddress()) {
            sigsSuffixCount = 1; // <sig> <pubkey>
        }
        return ScriptBuilder.updateScriptWithSignature(scriptSig, sigBytes, index, sigsPrefixCount, sigsSuffixCount);
    }


    /**
     * Returns the index where a signature by the key should be inserted.  Only applicable to
     * a P2SH scriptSig.
     */
    public int getSigInsertionIndex(Sha256Hash hash, ECKey signingKey) {
        // Iterate over existing signatures, skipping the initial OP_0, the final redeem script
        // and any placeholder OP_0 sigs.
        List<ScriptChunk> existingChunks = chunks.subList(1, chunks.size() - 1);
        ScriptChunk redeemScriptChunk = chunks.get(chunks.size() - 1);
        checkNotNull(redeemScriptChunk.data);
        Script redeemScript = new Script(redeemScriptChunk.data);

        int sigCount = 0;
        int myIndex = redeemScript.findKeyInRedeem(signingKey);
        for (ScriptChunk chunk : existingChunks) {
            if (chunk.opcode == OP_0) {
                // OP_0, skip
            } else {
                checkNotNull(chunk.data);
                if (myIndex < redeemScript.findSigInRedeem(chunk.data, hash))
                    return sigCount;
                sigCount++;
            }
        }
        return sigCount;
    }

    private int findKeyInRedeem(ECKey key) {
        checkArgument(chunks.get(0).isOpCode()); // P2SH scriptSig
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        for (int i = 0 ; i < numKeys ; i++) {
            if (Arrays.equals(chunks.get(1 + i).data, key.getPubKey())) {
                return i;
            }
        }

        throw new IllegalStateException("Could not find matching key " + key.toString() + " in script " + this);
    }

    /**
     * Returns a list of the keys required by this script, assuming a multi-sig script.
     *
     * @throws ScriptException if the script type is not understood or is pay to address or is P2SH (run this method on the "Redeem script" instead).
     */
    public List<ECKey> getPubKeys() {
        if (!isSentToMultiSig())
            throw new ScriptException("Only usable for multisig scripts.");

        ArrayList<ECKey> result = Lists.newArrayList();
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        for (int i = 0 ; i < numKeys ; i++)
            result.add(ECKey.fromPublicOnly(chunks.get(1 + i).data));
        return result;
    }

    private int findSigInRedeem(byte[] signatureBytes, Sha256Hash hash) {
        checkArgument(chunks.get(0).isOpCode()); // P2SH scriptSig
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, true);
        for (int i = 0 ; i < numKeys ; i++) {
            if (ECKey.fromPublicOnly(chunks.get(i + 1).data).verify(hash, signature)) {
                return i;
            }
        }

        throw new IllegalStateException("Could not find matching key for signature on " + hash.toString() + " sig " + Utils.HEX.encode(signatureBytes));
    }



    ////////////////////// Interface used during verification of transactions/blocks ////////////////////////////////

    private static int getSigOpCount(List<ScriptChunk> chunks, boolean accurate) {
        int sigOps = 0;
        int lastOpCode = OP_INVALIDOPCODE;
        for (ScriptChunk chunk : chunks) {
            if (chunk.isOpCode()) {
                switch (chunk.opcode) {
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    sigOps++;
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (accurate && lastOpCode >= OP_1 && lastOpCode <= OP_16)
                        sigOps += decodeFromOpN(lastOpCode);
                    else
                        sigOps += 20;
                    break;
                default:
                    break;
                }
                lastOpCode = chunk.opcode;
            }
        }
        return sigOps;
    }

    static int decodeFromOpN(int opcode) {
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16), "decodeFromOpN called on non OP_N opcode");
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    static int encodeToOpN(int value) {
        checkArgument(value >= -1 && value <= 16, "encodeToOpN called for " + value + " which we cannot encode in an opcode.");
        if (value == 0)
            return OP_0;
        else if (value == -1)
            return OP_1NEGATE;
        else
            return value - 1 + OP_1;
    }

    /**
     * Gets the count of regular SigOps in the script program (counting multisig ops as 20)
     */
    public static int getSigOpCount(byte[] program) {
        Script script = new Script();
        try {
            script.parse(program);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        return getSigOpCount(script.chunks, false);
    }
    
    /**
     * Gets the count of P2SH Sig Ops in the Script scriptSig
     */
    public static long getP2SHSigOpCount(byte[] scriptSig) {
        Script script = new Script();
        try {
            script.parse(scriptSig);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        for (int i = script.chunks.size() - 1; i >= 0; i--)
            if (!script.chunks.get(i).isOpCode()) {
                Script subScript =  new Script();
                subScript.parse(script.chunks.get(i).data);
                return getSigOpCount(subScript.chunks, true);
            }
        return 0;
    }

    /**
     * Returns number of signatures required to satisfy this script.
     */
    public int getNumberOfSignaturesRequiredToSpend() {
        if (isSentToMultiSig()) {
            // for N of M CHECKMULTISIG script we will need N signatures to spend
            ScriptChunk nChunk = chunks.get(0);
            return Script.decodeFromOpN(nChunk.opcode);
        } else if (isSentToAddress() || isSentToRawPubKey()) {
            // pay-to-address and pay-to-pubkey require single sig
            return 1;
        } else if (isPayToScriptHash()) {
            throw new IllegalStateException("For P2SH number of signatures depends on redeem script");
        } else {
            throw new IllegalStateException("Unsupported script type");
        }
    }

    /**
     * Returns number of bytes required to spend this script. It accepts optional ECKey and redeemScript that may
     * be required for certain types of script to estimate target size.
     */
    public int getNumberOfBytesRequiredToSpend(@Nullable ECKey pubKey, @Nullable Script redeemScript) {
        if (isPayToScriptHash()) {
            // scriptSig: <sig> [sig] [sig...] <redeemscript>
            checkArgument(redeemScript != null, "P2SH script requires redeemScript to be spent");
            return redeemScript.getNumberOfSignaturesRequiredToSpend() * SIG_SIZE + redeemScript.getProgram().length;
        } else if (isSentToMultiSig()) {
            // scriptSig: OP_0 <sig> [sig] [sig...]
            return getNumberOfSignaturesRequiredToSpend() * SIG_SIZE + 1;
        } else if (isSentToRawPubKey()) {
            // scriptSig: <sig>
            return SIG_SIZE;
        } else if (isSentToAddress()) {
            // scriptSig: <sig> <pubkey>
            int uncompressedPubKeySize = 65;
            return SIG_SIZE + (pubKey != null ? pubKey.getPubKey().length : uncompressedPubKeySize);
        } else {
            throw new IllegalStateException("Unsupported script type");
        }
    }

    /**
     * <p>Whether or not this is a scriptPubKey representing a pay-to-script-hash output. In such outputs, the logic that
     * controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
     * spending input to provide a program matching that hash. This rule is "soft enforced" by the network as it does
     * not exist in Bitcoin Core. It means blocks containing P2SH transactions that don't match
     * correctly are considered valid, but won't be mined upon, so they'll be rapidly re-orgd out of the chain. This
     * logic is defined by <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP 16</a>.</p>
     *
     * <p>bitcoinj does not support creation of P2SH transactions today. The goal of P2SH is to allow short addresses
     * even for complex scripts (eg, multi-sig outputs) so they are convenient to work with in things like QRcodes or
     * with copy/paste, and also to minimize the size of the unspent output set (which improves performance of the
     * Bitcoin system).</p>
     */
    public boolean isPayToScriptHash() {
        // We have to check against the serialized form because BIP16 defines a P2SH output using an exact byte
        // template, not the logical program structure. Thus you can have two programs that look identical when
        // printed out but one is a P2SH script and the other isn't! :(
        byte[] program = getProgram();
        return program.length == 23 &&
               (program[0] & 0xff) == OP_HASH160 &&
               (program[1] & 0xff) == 0x14 &&
               (program[22] & 0xff) == OP_EQUAL;
    }

    /**
     * Returns whether this script matches the format used for multisig outputs: [n] [keys...] [m] CHECKMULTISIG
     */
    public boolean isSentToMultiSig() {
        if (chunks.size() < 4) return false;
        ScriptChunk chunk = chunks.get(chunks.size() - 1);
        // Must end in OP_CHECKMULTISIG[VERIFY].
        if (!chunk.isOpCode()) return false;
        if (!(chunk.equalsOpCode(OP_CHECKMULTISIG) || chunk.equalsOpCode(OP_CHECKMULTISIGVERIFY))) return false;
        try {
            // Second to last chunk must be an OP_N opcode and there should be that many data chunks (keys).
            ScriptChunk m = chunks.get(chunks.size() - 2);
            if (!m.isOpCode()) return false;
            int numKeys = decodeFromOpN(m.opcode);
            if (numKeys < 1 || chunks.size() != 3 + numKeys) return false;
            for (int i = 1; i < chunks.size() - 2; i++) {
                if (chunks.get(i).isOpCode()) return false;
            }
            // First chunk must be an OP_N opcode too.
            if (decodeFromOpN(chunks.get(0).opcode) < 1) return false;
        } catch (IllegalArgumentException e) { // thrown by decodeFromOpN()
            return false;   // Not an OP_N opcode.
        }
        return true;
    }

    public boolean isSentToCLTVPaymentChannel() {
        if (chunks.size() != 10) return false;
        // Check that opcodes match the pre-determined format.
        if (!chunks.get(0).equalsOpCode(OP_IF)) return false;
        // chunk[1] = recipient pubkey
        if (!chunks.get(2).equalsOpCode(OP_CHECKSIGVERIFY)) return false;
        if (!chunks.get(3).equalsOpCode(OP_ELSE)) return false;
        // chunk[4] = locktime
        if (!chunks.get(5).equalsOpCode(OP_CHECKLOCKTIMEVERIFY)) return false;
        if (!chunks.get(6).equalsOpCode(OP_DROP)) return false;
        if (!chunks.get(7).equalsOpCode(OP_ENDIF)) return false;
        // chunk[8] = sender pubkey
        if (!chunks.get(9).equalsOpCode(OP_CHECKSIG)) return false;
        return true;
    }

    private static boolean equalsRange(byte[] a, int start, byte[] b) {
        if (start + b.length > a.length)
            return false;
        for (int i = 0; i < b.length; i++)
            if (a[i + start] != b[i])
                return false;
        return true;
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the specified script object removed
     */
    public static byte[] removeAllInstancesOf(byte[] inputScript, byte[] chunkToRemove) {
        // We usually don't end up removing anything
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(inputScript.length);

        int cursor = 0;
        while (cursor < inputScript.length) {
            boolean skip = equalsRange(inputScript, cursor, chunkToRemove);
            
            int opcode = inputScript[cursor++] & 0xFF;
            int additionalBytes = 0;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                additionalBytes = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                additionalBytes = (0xFF & inputScript[cursor]) + 1;
            } else if (opcode == OP_PUSHDATA2) {
                additionalBytes = ((0xFF & inputScript[cursor]) |
                                  ((0xFF & inputScript[cursor+1]) << 8)) + 2;
            } else if (opcode == OP_PUSHDATA4) {
                additionalBytes = ((0xFF & inputScript[cursor]) |
                                  ((0xFF & inputScript[cursor+1]) << 8) |
                                  ((0xFF & inputScript[cursor+1]) << 16) |
                                  ((0xFF & inputScript[cursor+1]) << 24)) + 4;
            }
            if (!skip) {
                try {
                    bos.write(opcode);
                    bos.write(Arrays.copyOfRange(inputScript, cursor, cursor + additionalBytes));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            cursor += additionalBytes;
        }
        return bos.toByteArray();
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the given op code removed
     */
    public static byte[] removeAllInstancesOfOp(byte[] inputScript, int opCode) {
        return removeAllInstancesOf(inputScript, new byte[] {(byte)opCode});
    }
    
    ////////////////////// Script verification and helpers ////////////////////////////////
    
    public static boolean castToBool(byte[] data) {
        for (int i = 0; i < data.length; i++)
        {
            // "Can be negative zero" - Bitcoin Core (see OpenSSL's BN_bn2mpi)
            if (data[i] != 0)
                return !(i == data.length - 1 && (data[i] & 0xFF) == 0x80);
        }
        return false;
    }
    
    /**
     * Cast a script chunk to a BigInteger.
     *
     * @see #castToBigInteger(byte[], int, boolean) for values with different maximum
     * sizes.
     * @throws ScriptException if the chunk is longer than 4 bytes.
     */
    private static BigInteger castToBigInteger(byte[] chunk, boolean enforceMinimal) {
        if (chunk.length > DEFAULT_MAX_NUM_ELEMENT_SIZE)
            throw new ScriptException("Script attempted to use an integer larger than 4 bytes");
        if (enforceMinimal && !Utils.checkMinimallyEncodedLE(chunk, DEFAULT_MAX_NUM_ELEMENT_SIZE))
            throw new ScriptException("Number is not minimally encoded");
        //numbers on the stack or stored LE so convert as MPI requires BE.
        byte[] bytesBE = Utils.reverseBytes(chunk);
        return Utils.decodeMPI(bytesBE, false);
    }

    /**
     * Cast a script chunk to a BigInteger. Normally you would want
     * {@link #castToBigInteger(byte[], boolean)} instead, this is only for cases where
     * the normal maximum length does not apply (i.e. CHECKLOCKTIMEVERIFY).
     *
     * @param maxLength the maximum length in bytes.
     * @throws ScriptException if the chunk is longer than the specified maximum.
     */
    private static BigInteger castToBigInteger(final byte[] chunk, final int maxLength, boolean enforceMinimal) {
        if (chunk.length > maxLength)
            throw new ScriptException("Script attempted to use an integer larger than "
                + maxLength + " bytes");
        if (enforceMinimal && !Utils.checkMinimallyEncodedLE(chunk, 5))
            throw new ScriptException("Number is not minimally encoded");
        return Utils.decodeMPI(Utils.reverseBytes(chunk), false);
    }

    public boolean isOpReturn() {
        return chunks.size() > 0 && chunks.get(0).equalsOpCode(OP_RETURN);
    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * {@link org.bitcoinj.core.TransactionInput#verify(org.bitcoinj.core.TransactionOutput)} or
     * {@link org.bitcoinj.script.Script#correctlySpends(org.bitcoinj.core.Transaction, long, Script)}. This method
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     *
     * @deprecated Use {@link #executeScript(org.bitcoinj.core.Transaction, long, org.bitcoinj.script.Script, java.util.LinkedList, java.util.Set)}
     * instead.
     */
    @Deprecated
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, boolean enforceNullDummy) {
        final EnumSet<VerifyFlag> flags = enforceNullDummy
            ? EnumSet.of(VerifyFlag.NULLDUMMY)
            : EnumSet.noneOf(VerifyFlag.class);

        executeScript(txContainingThis, index, script, stack, Coin.ZERO, flags);
    }

    @Deprecated
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) {
         executeScript(txContainingThis, index, script, stack, Coin.ZERO, verifyFlags);
    }

    private static boolean isOpcodeDisabled(int opcode, Set<VerifyFlag> verifyFlags) {


        switch (opcode) {
            case OP_RSHIFT:
            case OP_LSHIFT:
            case OP_MUL:
            case OP_INVERT:
                // enabled codes, still disabled if flag is not activated
                // re-enabled OP Code, November 15, 2018 Hard fork
                return !verifyFlags.contains(VerifyFlag.MAGNETIC_OPCODES);

            case OP_2MUL:
            case OP_2DIV:
                //disabled codes
                return true;
            case OP_CAT:
            case OP_SPLIT:
            case OP_AND:
            case OP_OR:
            case OP_XOR:
            case OP_DIV:
            case OP_MOD:
            case OP_NUM2BIN:
            case OP_BIN2NUM:
                //enabled codes, still disabled if flag is not activated
                return !verifyFlags.contains(VerifyFlag.MONOLITH_OPCODES);

            default:
                //not an opcode that was ever disabled
                break;
        }



        return false;

    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * {@link org.bitcoinj.core.TransactionInput#verify(org.bitcoinj.core.TransactionOutput)} or
     * {@link org.bitcoinj.script.Script#correctlySpends(org.bitcoinj.core.Transaction, long, Script)}. This method
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     */
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Coin value, Set<VerifyFlag> verifyFlags) throws ScriptException {
        executeScript(txContainingThis,index, script, stack, value, verifyFlags, null);
    }

    /**
     * Executes a script in debug mode with the provided ScriptStateListener.  Exceptions (which are thrown when a script fails) are caught
     * and passed to the listener before being rethrown.
     */
    public static void executeDebugScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Coin value, Set<VerifyFlag> verifyFlags, ScriptStateListener scriptStateListener) throws ScriptException {
        try {
            executeScript(txContainingThis, index, script, stack, value, verifyFlags, scriptStateListener);
        } catch (ScriptException e) {
            scriptStateListener.onExceptionThrown(e);
            try {
                //pause to hopefully give the System.out time to beat System.err
                Thread.sleep(200);
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
            throw e;
        }
    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * {@link org.bitcoinj.core.TransactionInput#verify(org.bitcoinj.core.TransactionOutput)} or
     * {@link org.bitcoinj.script.Script#correctlySpends(org.bitcoinj.core.Transaction, long, Script)}. This method
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     */
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Coin value, Set<VerifyFlag> verifyFlags, ScriptStateListener scriptStateListener) throws ScriptException {
        int opCount = 0;
        int lastCodeSepLocation = 0;

        LinkedList<byte[]> altstack = new LinkedList<byte[]>();
        LinkedList<Boolean> ifStack = new LinkedList<Boolean>();
        final boolean enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);

        if (scriptStateListener != null) {
            scriptStateListener.setInitialState(
                    txContainingThis,
                    index,
                    script,
                    Collections.unmodifiableList(stack),
                    Collections.unmodifiableList(altstack),
                    Collections.unmodifiableList(ifStack),
                    value,
                    verifyFlags
            );
        }

        for (ScriptChunk chunk : script.chunks) {
            boolean shouldExecute = !ifStack.contains(false);

            if (scriptStateListener != null) {
                scriptStateListener._onBeforeOpCodeExecuted(chunk, shouldExecute);
            }

            if (chunk.opcode == OP_0) {
                if (!shouldExecute)
                    continue;

                stack.add(new byte[] {});
            } else if (!chunk.isOpCode()) {
                if (chunk.data.length > MAX_SCRIPT_ELEMENT_SIZE)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "attempted to push value on the stack that was too large");
                
                if (!shouldExecute)
                    continue;

                if (enforceMinimal && !chunk.isShortestPossiblePushData())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALDATA
                            , "PushData operation not compliant to Minimal data. A more specific opCode should be used.");

                stack.add(chunk.data);
            } else {
                int opcode = chunk.opcode;
                if (opcode > OP_16) {
                    opCount++;
                    if (opCount > 201)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "script contains too many opcodes");
                }
                
                if (opcode == OP_VERIF || opcode == OP_VERNOTIF)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "an illegal opcode is present in the script");

                // Some opcodes are disabled.
                if (isOpcodeDisabled(opcode, verifyFlags)) {
                    throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, "script includes a disabled opcode");
                }



                switch (opcode) {

                case OP_IF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "the script contains an unbalanced conditional");

                    // We check MINIMALIF Flag (IMPORTANT: We use peekLast, so the stack is not consumed)
                    if (verifyFlags.contains(VerifyFlag.MINIMALIF) && !checkMinimalIf(stack.peekLast())) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF, "top of the Stack does NOT meet the MINIMALIF requirements");
                    }

                    ifStack.add(castToBool(stack.pollLast()));
                    continue;
                case OP_NOTIF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "the script contains an unbalanced conditional");

                    // We check MINIMALIF Flag (IMPORTANT: We use peekLast, so the stack is not consumed)
                    if (verifyFlags.contains(VerifyFlag.MINIMALIF) && !checkMinimalIf(stack.peekLast())) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF, "top of the Stack does NOT meet the MINIMALIF requirements");
                    }

                    ifStack.add(!castToBool(stack.pollLast()));
                    continue;
                case OP_ELSE:
                    if (ifStack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "the script contains an unbalanced conditional");
                    ifStack.add(!ifStack.pollLast());
                    continue;
                case OP_ENDIF:
                    if (ifStack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "the script contains an unbalanced conditional");
                    ifStack.pollLast();
                    continue;
                }
                
                if (!shouldExecute)
                    continue;
                
                switch(opcode) {
                // OP_0 is no opcode
                case OP_1NEGATE:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false)));
                    break;
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(decodeFromOpN(opcode)), false)));
                    break;
                case OP_NOP:
                    break;
                case OP_VERIFY:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    if (!castToBool(stack.pollLast()))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_VERIFY, "the VERIFY failed");
                    break;
                case OP_RETURN:
                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN, "the script called OP_RETURN");
                case OP_TOALTSTACK:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    altstack.add(stack.pollLast());
                    break;
                case OP_FROMALTSTACK:
                    if (altstack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
                                "the operation xwas invalid given the contents of the altstack");
                    stack.add(altstack.pollLast());
                    break;
                case OP_2DROP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.pollLast();
                    stack.pollLast();
                    break;
                case OP_2DUP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    Iterator<byte[]> it2DUP = stack.descendingIterator();
                    byte[] OP2DUPtmpChunk2 = it2DUP.next();
                    stack.add(it2DUP.next());
                    stack.add(OP2DUPtmpChunk2);
                    break;
                case OP_3DUP:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    Iterator<byte[]> it3DUP = stack.descendingIterator();
                    byte[] OP3DUPtmpChunk3 = it3DUP.next();
                    byte[] OP3DUPtmpChunk2 = it3DUP.next();
                    stack.add(it3DUP.next());
                    stack.add(OP3DUPtmpChunk2);
                    stack.add(OP3DUPtmpChunk3);
                    break;
                case OP_2OVER:
                    if (stack.size() < 4)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    Iterator<byte[]> it2OVER = stack.descendingIterator();
                    it2OVER.next();
                    it2OVER.next();
                    byte[] OP2OVERtmpChunk2 = it2OVER.next();
                    stack.add(it2OVER.next());
                    stack.add(OP2OVERtmpChunk2);
                    break;
                case OP_2ROT:
                    if (stack.size() < 6)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] OP2ROTtmpChunk6 = stack.pollLast();
                    byte[] OP2ROTtmpChunk5 = stack.pollLast();
                    byte[] OP2ROTtmpChunk4 = stack.pollLast();
                    byte[] OP2ROTtmpChunk3 = stack.pollLast();
                    byte[] OP2ROTtmpChunk2 = stack.pollLast();
                    byte[] OP2ROTtmpChunk1 = stack.pollLast();
                    stack.add(OP2ROTtmpChunk3);
                    stack.add(OP2ROTtmpChunk4);
                    stack.add(OP2ROTtmpChunk5);
                    stack.add(OP2ROTtmpChunk6);
                    stack.add(OP2ROTtmpChunk1);
                    stack.add(OP2ROTtmpChunk2);
                    break;
                case OP_2SWAP:
                    if (stack.size() < 4)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] OP2SWAPtmpChunk4 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk3 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk2 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk1 = stack.pollLast();
                    stack.add(OP2SWAPtmpChunk3);
                    stack.add(OP2SWAPtmpChunk4);
                    stack.add(OP2SWAPtmpChunk1);
                    stack.add(OP2SWAPtmpChunk2);
                    break;
                case OP_IFDUP:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    if (castToBool(stack.getLast()))
                        stack.add(stack.getLast());
                    break;
                case OP_DEPTH:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.size()), false)));
                    break;
                case OP_DROP:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.pollLast();
                    break;
                case OP_DUP:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(stack.getLast());
                    break;
                case OP_NIP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] OPNIPtmpChunk = stack.pollLast();
                    stack.pollLast();
                    stack.add(OPNIPtmpChunk);
                    break;
                case OP_OVER:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    Iterator<byte[]> itOVER = stack.descendingIterator();
                    itOVER.next();
                    stack.add(itOVER.next());
                    break;
                case OP_PICK:
                case OP_ROLL:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    long val = castToBigInteger(stack.pollLast(), enforceMinimal).longValue();
                    if (val < 0 || val >= stack.size())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    Iterator<byte[]> itPICK = stack.descendingIterator();
                    for (long i = 0; i < val; i++)
                        itPICK.next();
                    byte[] OPROLLtmpChunk = itPICK.next();
                    if (opcode == OP_ROLL)
                        itPICK.remove();
                    stack.add(OPROLLtmpChunk);
                    break;
                case OP_ROT:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] OPROTtmpChunk3 = stack.pollLast();
                    byte[] OPROTtmpChunk2 = stack.pollLast();
                    byte[] OPROTtmpChunk1 = stack.pollLast();
                    stack.add(OPROTtmpChunk2);
                    stack.add(OPROTtmpChunk3);
                    stack.add(OPROTtmpChunk1);
                    break;
                case OP_SWAP:
                case OP_TUCK:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] OPSWAPtmpChunk2 = stack.pollLast();
                    byte[] OPSWAPtmpChunk1 = stack.pollLast();
                    stack.add(OPSWAPtmpChunk2);
                    stack.add(OPSWAPtmpChunk1);
                    if (opcode == OP_TUCK)
                        stack.add(OPSWAPtmpChunk2);
                    break;
                //byte string operations
                case OP_CAT:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    byte[] catBytes2 = stack.pollLast();
                    byte[] catBytes1 = stack.pollLast();

                    int len = catBytes1.length + catBytes2.length;
                    if (len > MAX_SCRIPT_ELEMENT_SIZE)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "attempted to push value on the stack that was too large");

                    byte[] catOut = new byte[len];
                    System.arraycopy(catBytes1, 0, catOut, 0, catBytes1.length);
                    System.arraycopy(catBytes2, 0, catOut, catBytes1.length, catBytes2.length);
                    stack.addLast(catOut);

                    break;

                case OP_SPLIT:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

                    BigInteger biSplitPos = castToBigInteger(stack.pollLast(), enforceMinimal);

                    //sanity check in case we aren't enforcing minimal number encoding
                    //we will check that the biSplitPos value can be safely held in an int
                    //before we cast it as BigInteger will behave similar to casting if the value
                    //is greater than the target type can hold.
                    BigInteger biMaxInt = BigInteger.valueOf((long) Integer.MAX_VALUE);
                    if (biSplitPos.compareTo(biMaxInt) >= 0)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_SPLIT_RANGE, "invalid OP_SPLIT range");

                    int splitPos = biSplitPos.intValue();
                    byte[] splitBytes = stack.pollLast();

                    if (splitPos > splitBytes.length || splitPos < 0)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_SPLIT_RANGE, "invalid OP_SPLIT range");

                    byte[] splitOut1 = new byte[splitPos];
                    byte[] splitOut2 = new byte[splitBytes.length - splitPos];

                    System.arraycopy(splitBytes, 0, splitOut1, 0, splitPos);
                    System.arraycopy(splitBytes, splitPos, splitOut2, 0, splitOut2.length);

                    stack.addLast(splitOut1);
                    stack.addLast(splitOut2);
                    break;

                case OP_NUM2BIN:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

                    int numSize = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();

                    if (numSize > MAX_SCRIPT_ELEMENT_SIZE || numSize < 0)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "attempted to push value on the stack that was too large");

                    byte[] rawNumBytes = stack.pollLast();

                    // Try to see if we can fit that number in the number of
                    // byte requested.
                    byte[] minimalNumBytes = Utils.minimallyEncodeLE(rawNumBytes);
                    if (minimalNumBytes.length > numSize) {
                        //we can't
                        throw new ScriptException(ScriptError.SCRIPT_ERR_IMPOSSIBLE_ENCODING, "the encoding is not possible");
                    }

                    if (minimalNumBytes.length == numSize) {
                        //already the right size so just push it to stack
                        stack.addLast(minimalNumBytes);
                    } else if (numSize == 0) {
                        stack.addLast(Utils.EMPTY_BYTE_ARRAY);
                    } else {
                        int signBit = 0x00;
                        if (minimalNumBytes.length > 0) {
                            signBit = minimalNumBytes[minimalNumBytes.length - 1] & 0x80;
                            minimalNumBytes[minimalNumBytes.length - 1] &= 0x7f;
                        }
                        int minimalBytesToCopy = minimalNumBytes.length > numSize ? numSize : minimalNumBytes.length;
                        byte[] expandedNumBytes = new byte[numSize]; //initialized to all zeroes
                        System.arraycopy(minimalNumBytes, 0, expandedNumBytes, 0, minimalBytesToCopy);
                        expandedNumBytes[expandedNumBytes.length - 1] = (byte) signBit;
                        stack.addLast(expandedNumBytes);
                    }
                    break;

                case OP_BIN2NUM:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

                    byte[] binBytes = stack.pollLast();
                    byte[] numBytes = Utils.minimallyEncodeLE(binBytes);

                    if (!Utils.checkMinimallyEncodedLE(numBytes, DEFAULT_MAX_NUM_ELEMENT_SIZE))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "operand is not a number in the valid range");

                    stack.addLast(numBytes);

                    break;
                case OP_SIZE:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
                    break;
                case OP_INVERT:
                    // re-enabled OP Code, November 15, 2018 Hard fork
                    if (stack.size() < 1) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    }
                    byte[] toInvertByte = stack.pollLast();
                    for (int i = 0; i < toInvertByte.length; i++) toInvertByte[i] = (byte) ~toInvertByte[i];
                    stack.push(toInvertByte);
                    break;
                case OP_AND:
                case OP_OR:
                case OP_XOR:
                    // (x1 x2 - out)
                    if (stack.size() < 2) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    }

                    //valtype &vch1 = stacktop(-2);
                    //valtype &vch2 = stacktop(-1);
                    byte[] vch2 = stack.pollLast();
                    byte[] vch1 = stack.pollLast();

                    // Inputs must be the same size
                    if (vch1.length != vch2.length) {
                        throw new ScriptException(ScriptError.SCRIPT_ER_OPERAND_SIZE, "invalid operand size");
                    }

                    // To avoid allocating, we modify vch1 in place.
                    switch (opcode) {
                        case OP_AND:
                            for (int i = 0; i < vch1.length; i++) {
                                vch1[i] &= vch2[i];
                            }
                            break;
                        case OP_OR:
                            for (int i = 0; i < vch1.length; i++) {
                                vch1[i] |= vch2[i];
                            }
                            break;
                        case OP_XOR:
                            for (int i = 0; i < vch1.length; i++) {
                                vch1[i] ^= vch2[i];
                            }
                            break;
                        default:
                            break;
                    }

                    // And pop vch2.
                    //popstack(stack);

                    //put vch1 back on stack
                    stack.addLast(vch1);

                    break;

                case OP_EQUAL:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new byte[] {1} : new byte[] {});
                    break;
                case OP_EQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "OP_EQUALVERIFY failed, non-equal operands");
                    break;
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger numericOPnum = castToBigInteger(stack.pollLast(), enforceMinimal);
                                        
                    switch (opcode) {
                    case OP_1ADD:
                        numericOPnum = numericOPnum.add(BigInteger.ONE);
                        break;
                    case OP_1SUB:
                        numericOPnum = numericOPnum.subtract(BigInteger.ONE);
                        break;
                    case OP_NEGATE:
                        numericOPnum = numericOPnum.negate();
                        break;
                    case OP_ABS:
                        if (numericOPnum.signum() < 0)
                            numericOPnum = numericOPnum.negate();
                        break;
                    case OP_NOT:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ONE;
                        else
                            numericOPnum = BigInteger.ZERO;
                        break;
                    case OP_0NOTEQUAL:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ZERO;
                        else
                            numericOPnum = BigInteger.ONE;
                        break;
                    default:
                        throw new AssertionError("Unreachable");
                    }
                    
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
                    break;
                case OP_2MUL:
                case OP_2DIV:
                    throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, "script includes a disabled opcode");
                case OP_ADD:
                case OP_SUB:
                case OP_MUL:
                case OP_DIV:
                case OP_MOD:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger numericOPnum2 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    BigInteger numericOPnum1 = castToBigInteger(stack.pollLast(), enforceMinimal);

                    BigInteger numericOPresult;
                    switch (opcode) {
                    case OP_ADD:
                        numericOPresult = numericOPnum1.add(numericOPnum2);
                        break;
                    case OP_SUB:
                        numericOPresult = numericOPnum1.subtract(numericOPnum2);
                        break;

                    case OP_DIV:
                        if (numericOPnum2.intValue() == 0)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DIV_BY_ZERO, "divide by zero error");
                        numericOPresult = numericOPnum1.divide(numericOPnum2);
                        break;

                        case OP_MOD:
                            if (numericOPnum2.intValue() == 0)
                                throw new ScriptException(ScriptError.SCRIPT_ERR_MOD_BY_ZERO, "modulo by zero error");

                            /**
                             * BigInteger doesn't behave the way we want for modulo operations.  Firstly it's
                             * always garunteed to return a +ve result.  Secondly it will throw an exception
                             * if the 2nd operand is negative.  So we'll convert the values to longs and use native
                             * modulo.  When we expand the number limits to arbitrary length we will likely need
                             * a new BigNum implementation to handle this correctly.
                             */
                            long lOp1 = numericOPnum1.longValue();
                            if (!BigInteger.valueOf(lOp1).equals(numericOPnum1)) {
                                //in case the value is larger than a long can handle we need to crash and burn.
                                throw new RuntimeException("Cannot handle large negative operand for modulo operation");
                            }
                            long lOp2 = numericOPnum2.longValue();
                            if (!BigInteger.valueOf(lOp2).equals(numericOPnum2)) {
                                //in case the value is larger than a long can handle we need to crash and burn.
                                throw new RuntimeException("Cannot handle large negative operand for modulo operation");
                            }
                            long lOpResult = lOp1 % lOp2;
                            numericOPresult = BigInteger.valueOf(lOpResult);

                            break;

                        case OP_BOOLAND:
                        if (!numericOPnum1.equals(BigInteger.ZERO) && !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_BOOLOR:
                        if (!numericOPnum1.equals(BigInteger.ZERO) || !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMEQUAL:
                        if (numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMNOTEQUAL:
                        if (!numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) <= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) >= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_MIN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                    case OP_MAX:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                     case OP_MUL:
                        // re-enabled OP Code, November 15, 2018 Hard fork
                        numericOPresult = numericOPnum1.multiply(numericOPnum2);
                        break;
                    default:
                        throw new RuntimeException("Opcode switched at runtime?");
                    }
                    
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
                    break;

                case OP_LSHIFT:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger numBitsL = castToBigInteger(stack.pollLast(), enforceMinimal);
                    if (numBitsL.longValue() < 0)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "the number of bits to move must be a positive number");
                    byte[] bytesToMoveL = stack.pollLast();
                    byte[] bytesMovedL  = executeLShift(bytesToMoveL, numBitsL.intValue());
                    stack.add(bytesMovedL);
                    break;
                case OP_RSHIFT:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger numBitsR = castToBigInteger(stack.pollLast(), enforceMinimal);
                    if (numBitsR.longValue() < 0)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "the number of bits to move must be a positive number");
                    byte[] bytesToMoveR = stack.pollLast();
                    byte[] bytesMovedR  = executeRShift(bytesToMoveR, numBitsR.intValue());
                    stack.add(bytesMovedR);
                    break;
                case OP_NUMEQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger OPNUMEQUALVERIFYnum2 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    BigInteger OPNUMEQUALVERIFYnum1 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    
                    if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY, "P_NUMEQUALVERIFY failed, non-equal operands");
                    break;
                case OP_WITHIN:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    BigInteger OPWITHINnum3 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    BigInteger OPWITHINnum2 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    BigInteger OPWITHINnum1 = castToBigInteger(stack.pollLast(), enforceMinimal);
                    if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE, false)));
                    else
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ZERO, false)));
                    break;
                case OP_RIPEMD160:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    RIPEMD160Digest digest = new RIPEMD160Digest();
                    byte[] dataToHash = stack.pollLast();
                    digest.update(dataToHash, 0, dataToHash.length);
                    byte[] ripmemdHash = new byte[20];
                    digest.doFinal(ripmemdHash, 0);
                    stack.add(ripmemdHash);
                    break;
                case OP_SHA1:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    try {
                        stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);  // Cannot happen.
                    }
                    break;
                case OP_SHA256:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(Sha256Hash.hash(stack.pollLast()));
                    break;
                case OP_HASH160:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(Utils.sha256hash160(stack.pollLast()));
                    break;
                case OP_HASH256:
                    if (stack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");
                    stack.add(Sha256Hash.hashTwice(stack.pollLast()));
                    break;
                case OP_CODESEPARATOR:
                    lastCodeSepLocation = chunk.getStartLocationInProgram() + 1;
                    break;
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    if (txContainingThis == null)
                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
                    executeCheckSig(txContainingThis, (int) index, script, stack, lastCodeSepLocation, opcode, value, verifyFlags);
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (txContainingThis == null)
                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
                    opCount = executeMultiSig(txContainingThis, (int) index, script, stack, opCount, lastCodeSepLocation, opcode, value, verifyFlags);
                    break;
                case OP_CHECKLOCKTIMEVERIFY:
                    if (!verifyFlags.contains(VerifyFlag.CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "script used a reserved opcode");
                        }
                        break;
                    }
                    executeCheckLockTimeVerify(txContainingThis, (int) index, script, stack, lastCodeSepLocation, opcode, verifyFlags);
                    break;
                case OP_CHECKSEQUENCEVERIFY:
                    if (!verifyFlags.contains(VerifyFlag.CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "script used a reserved opcode");
                        }
                        break;
                    }
                    executeCheckSequenceVerify(txContainingThis, (int) index, script, stack, verifyFlags);
                    break;
                case OP_NOP1:
                case OP_NOP4:
                case OP_NOP5:
                case OP_NOP6:
                case OP_NOP7:
                case OP_NOP8:
                case OP_NOP9:
                case OP_NOP10:
                    if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "script used a reserved opcode");
                    }
                    break;
                    
                default:
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "an illegal opcode is present in the script");
                }
            }
            
            if (stack.size() + altstack.size() > 1000 || stack.size() + altstack.size() < 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "stack is, or would be, too large");

            if (scriptStateListener != null) {
                scriptStateListener.onAfterOpCodeExectuted();
            }
        }
        
        if (!ifStack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "the script contains an unbalanced conditional");

        if (scriptStateListener != null) {
            scriptStateListener.onScriptComplete();
        }
    }

    /**
     * Returns the Bit representation of the content
     */
    public static String toBits(byte content) {
        StringBuffer result = new StringBuffer();
        byte[] masks = {(byte)0x80,(byte)0x40,(byte)0x20,(byte)0x10,(byte)0x08,(byte)0x04,(byte)0x02,(byte)0x01};

            for (int i = 0; i < 8; i++) {
                if ((content & masks[i]) == 0) result.append("0");
                else result.append("1");
            }
            result.append(" ");

        return result.toString();
    }

    /**
     * Performs a LShift operation on the byte array, moving all the bits to the left the number of positions
     * specified by numBits.
     */
    private static byte[] executeLShift(byte[] original, int numBits) {

        /*
            The following example shows how the bits are moved. After this move, we still need to
            restore the sign bit, but that's pretty straightforward, so we won't describe it here.

            Example: array length = 3, numBits = 10:
                - byte_shift = 1: number of complete bytes to move
                - bits_shift = 2: number of extra bits to move after moving the previous byte

            original:    [AAAAAAAA] [BBBBBBBB] [CCCCCCCC]

            We process it from right-to-Left. if byte_shift > 0, some complete bytes on the right will be empty
            after being moved to the left, so no need to process them. Here we start processing at
            position 1, since the position 2 will be empty after moving the whole byte to the left.

            result:      [00000000] [00000000] [00000000]   <- initial state
            result:      [00000000] [CCCCCCCC] [00000000]   <- processing byte 1
            result:      [00000000] [CCCCCC00] [00000000]   <- processing byte 1
            result:      [BBBBBBBB] [CCCCCC00] [00000000]   <- processing byte 0
            result:      [BBBBBB00] [CCCCCC00] [00000000]   <- processing byte 0
            result:      [BBBBBBCC] [CCCCCC00] [00000000]   <- processing byte 0 (*)

            (*) is not present in the first iteration, since we would have stepped out of the array. In this step,
            we are filling the right side of our byte with some bits from the left side of the original byte.

            processed byte:     [BBBBBB00]
            original byte:      [CCCCCCCC]

            We move the bits in the original, to the right: [000000CC]
            And we perform an OR: [BBBBBBB00] | [000000CC] = [BBBBBBCC]
         */
        byte[] result = new byte[original.length];
        if (numBits == 0) return original;
        else if (original.length > 0) {

            int byte_shift = numBits / 8;   // number of full bytes to move
            int bits_shift = numBits % 8;   // extra bits to move after moving the full bytes

            int startPoint = original.length -1 -byte_shift;
            if (startPoint >= 0) {
                for (int i = startPoint; i >=0; i--) {

                    if (byte_shift > 0) result[i] = original[i + byte_shift];
                    else result[i] = original[i];
                    if (bits_shift > 0) {
                        int byteProcessed = (int) result[i];
                        byteProcessed = (byte) (byteProcessed << bits_shift);
                        if (i + byte_shift + 1 < original.length) {
                            int byteExtraBits =  original[i + byte_shift + 1];
                            byteExtraBits = byteExtraBits & 0xFF;
                            byteExtraBits = (byteExtraBits) >> (8 - bits_shift);
                            byteProcessed = (byte) (byteProcessed | byteExtraBits);
                        }
                        result[i] = (byte) byteProcessed;
                    }
                } //for...
            } // if...

        } // if...
        return result;
    }

    /**
     * Performs a LShift operation on the byte array, moving all the bits to the left the number of positions
     * specified by numBits.
     */
    private static byte[] executeRShift(byte[] original, int numBits) {

        /*
            The following example shows how the bits are moved. After this move, we still need to
            restore the sign bit, but that's pretty straightforward, so we won't describe it here.

            Example: array length = 3, numBits = 10:
                - byte_shift = 1: number of complete bytes to move
                - bits_shift = 2: number of extra bits to move after moving the previous byte

            original:    [AAAAAAAA] [BBBBBBBB] [CCCCCCCC]

            We process it from left-to-right. if byte_shift > 0, some complete bytes on the right will be empty
            after being moved to the right, so no need to process them. Here we start processing at
            position 1, since the position 0 will be empty after moving the whole byte to the right.

            result:      [00000000] [00000000] [00000000]   <- initial state
            result:      [00000000] [AAAAAAAA] [00000000]   <- processing byte 1
            result:      [00000000] [00AAAAAA] [00000000]   <- processing byte 1
            result:      [BBBBBBBB] [00AAAAAA] [BBBBBBBB]   <- processing byte 2
            result:      [BBBBBB00] [00CCCCCC] [00BBBBBB]   <- processing byte 2
            result:      [BBBBBBCC] [00CCCCCC] [AABBBBBB]   <- processing byte 2 (*)

            (*) is not present in the first iteration, since we would have stepped out of the array. In this step,
            we are filling the left side of our byte with some bits from the right side of the original byte.

            processed byte:     [00BBBBBB]
            original byte:      [AAAAAAAA]

            We move the bits in the original, to the left: [AA000000]
            And we perform an OR: [00BBBBBB] | [AA000000] = [AABBBBBB]
         */

        byte[] result = new byte[original.length];

        if (numBits == 0) return original;
        else if (original.length > 0) {

            int byte_shift = numBits / 8;   // number of full bytes to move
            int bits_shift = numBits % 8;   // extra bits to move after moving the full bytes

            int startPoint = 0 + byte_shift;
            if (startPoint <= original.length - 1) {
                for (int i = startPoint; i < original.length; i++) {
                    if (byte_shift > 0) result[i] = original[i - 1];
                    else result[i] = original[i];
                    if (bits_shift > 0) {

                        int byteProcessed = (int) result[i];
                        byteProcessed = byteProcessed & 0xFF;
                        byteProcessed = (byte) (byteProcessed >> bits_shift);
                        if (i - byte_shift - 1 >= 0) {
                            int byteExtraBits =  original[i - byte_shift - 1];
                            byteExtraBits = (byteExtraBits) << (8 - bits_shift);
                            byteProcessed = (byte) (byteProcessed | byteExtraBits);
                        }
                        result[i] = (byte) byteProcessed;
                    }
                } //for...
            } // if...
        } // if...

        return result;
    }

    // This is more or less a direct translation of the code in Bitcoin Core
    private static void executeCheckLockTimeVerify(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                        int lastCodeSepLocation, int opcode,
                                        Set<VerifyFlag> verifyFlags) {
        if (stack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums to avoid year 2038 issue.
        final BigInteger nLockTime = castToBigInteger(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

        if (nLockTime.compareTo(BigInteger.ZERO) < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");

        // There are two kinds of nLockTime, need to ensure we're comparing apples-to-apples
        if (!(
            ((txContainingThis.getLockTime() <  Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) < 0) ||
            ((txContainingThis.getLockTime() >= Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) >= 0))
        )
            throw new ScriptException("Locktime requirement type mismatch");

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nLockTime.compareTo(BigInteger.valueOf(txContainingThis.getLockTime())) > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement not satisfied");

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        //
        // testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (!txContainingThis.getInput(index).hasSequence())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME
                    , "Transaction contains a final transaction input for a CHECKLOCKTIMEVERIFY script.");
    }

    /**
     * Implementation of the CHECKSEQUENCEVERIFY OpCode, as defined in BIP 112.
     * (Implementation from Bitcoin-abc used as a reference)
     *
     * @param txContainingThis          Transaction this script is included into
     * @param index                     index
     * @param script                    Script to execute
     * @param stack                     Script execution stack
     * @param verifyFlags               Verification flags
     */
    @SuppressWarnings("Duplicates")
    private static void executeCheckSequenceVerify(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                                   Set<VerifyFlag> verifyFlags) {
        // If the stack is empty, we raise an Error
        if (stack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");

        // Thus as a special case we accept up to 5-byte bignums to avoid year 2038 issue.
        final long nSequence = castToBigInteger(stack.getLast()
                , 5
                , verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();

        if (nSequence  < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");


        // if the 31-bit bit is enabled, we continue with the execution, otherwise
        // we do nothing else and let the rest of the script execute...
        // 31 bit enabled = 0x80000000

        BigInteger disabledFlagMask = new BigInteger("80000000", 16);
        if ((nSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0)
            if (!checkSequence(txContainingThis, nSequence, index))
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative time lock requirement not satisfied");
    }

    /**
     * Auxiliar method for the CHECKSEUQNCEVERIFY Op. It checks the nSequence from the top of the stack against
     * The sequence in the transaction input.
     *
     * @param txContainingThis  Transaction this script is included into
     * @param nSequence         nSequence (from the top of the stack, parameter of the CHECKSEQUENCEVERIFY opcode)
     * @param vinIndex          transaction input index
     * @return                  TRue (valid), False (invalid).
     */
    private static boolean checkSequence(Transaction txContainingThis, long nSequence, int vinIndex) {
        boolean result = true;

        // Regarding the nSequence value structure (both in the parameter from the
        // topStck or the "nSequence" field from the input:

        // - 3 important bit sets: SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG-FLAG and SEQUENCE_LOCKTIME_MASK
        //     - SEQUENCE_LOCKTIME_DISABLE_FLAG FLAG is the most significant bit (31-bit, starting from 0).
        //        (mask: 0x80000000)
        //     - SEQUENCE_LOCKTIME_MASK is the value of the 16 least significant bits
        //        (mask: 0x0000FFFF)
        //     - SEQUENCE_LOCKTIME_TYPE_FLAG is the 23th least-significant bit
        //        (mask: 0x400000)
        //          - if set, the VALUE is a multiple of 512 seconds
        //          - if NOT set, the VALUE is the number of blocks

        long typeAndValueMask = TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG | TransactionInput.SEQUENCE_LOCKTIME_MASK;

        // Relative lock times are supported by comparing the passed in operand to
        // the sequence number of the input.
        long txToSequence = txContainingThis.getInputs().get(vinIndex).getSequenceNumber();

        // Fails if the transaction's version number is not set high enough to
        // trigger BIP 68 rules.
        if (txContainingThis.getVersion() < 2) return false;

        // Sequence numbers with their most significant bit set are not consensus
        // constrained. Testing that the transaction's sequence number do not have
        // this bit set prevents using this property to get around a
        // CHECKSEQUENCEVERIFY check:

        if ((txToSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0)
            return false;

        // Mask off any bits that do not have consensus-enforced meaning before
        // doing the integer comparisons:

        long txToSequenceMasked = txToSequence | typeAndValueMask;
        long nSequenceMasked = nSequence  | typeAndValueMask;

        // We want to compare apples to apples, so fail the script unless the type
        // of nSequenceMasked being tested is the same as the nSequenceMasked in the
        // transaction.

        if (!( ((txToSequenceMasked < typeAndValueMask) && (nSequenceMasked < typeAndValueMask))
                ||
                ((txToSequenceMasked >= typeAndValueMask) && (nSequenceMasked >= typeAndValueMask))
                ))
            return false;

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nSequenceMasked > txToSequenceMasked) return false;

        return result;
    }

    private static void executeCheckSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                        int lastCodeSepLocation, int opcode, Coin value,
                                        Set<VerifyFlag> verifyFlags) {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
            || verifyFlags.contains(VerifyFlag.DERSIG)
            || verifyFlags.contains(VerifyFlag.LOW_S);
        if (stack.size() < 2)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");
        byte[] pubKey = stack.pollLast();
        byte[] sigBytes = stack.pollLast();

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sigBytes.length + 1);
        try {
            writeBytes(outStream, sigBytes);
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen
        }
        connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());

        // TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
        boolean sigValid = false;


        try {

            // We check the signature format (an empty signature is still a "valid" signature from an
            // (structure) perspective...

            if (sigBytes.length > 0) {

                // We check the signature Encoding.
                // In case of failed verification, and Exception is thrown
                checkSignatureEncoding(sigBytes, verifyFlags);

                // We check the Public Key encoding and compression.
                // In case of failed verification, and Exception is thrown
                checkPubKeyEncoding(pubKey, verifyFlags);

                // Signature is well-structured...
                TransactionSignature sig = TransactionSignature.decodeFromBitcoin(sigBytes, requireCanonical,
                        verifyFlags.contains(VerifyFlag.LOW_S));

                // TODO: Should check hash type is known
                Sha256Hash hash = sig.useForkId() ?
                        txContainingThis.hashForSignatureWitness(index, connectedScript, value, sig.sigHashMode(), sig.anyoneCanPay(), verifyFlags) :
                        txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);

                sigValid = ECKey.verify(hash.getBytes(), sig, pubKey);

            }

        } catch (SignatureFormatError e) {
            sigValid = false;
        }

        // NULLFAIL Verification:
        // If the NULLFAIL flag is active and the result of the Signature Verification is FALSE, we check
        // that the signature is an empty Array...
        if (!sigValid && verifyFlags.contains(VerifyFlag.NULLFAIL) && sigBytes.length > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL-compliant");

        if (opcode == OP_CHECKSIG)
            stack.add(sigValid ? new byte[] {1} : new byte[] {});
        else if (opcode == OP_CHECKSIGVERIFY)
            if (!sigValid)
                throw new ScriptException("Script failed OP_CHECKSIGVERIFY");
    }

    private static int executeMultiSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                       int opCount, int lastCodeSepLocation, int opcode, Coin value,
                                       Set<VerifyFlag> verifyFlags) {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
            || verifyFlags.contains(VerifyFlag.DERSIG)
            || verifyFlags.contains(VerifyFlag.LOW_S);
        final boolean enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);

        // We have on the Stack the number of Signatures, followed by the
        // signatures themselves. so we check:
        // - At least we have 2 elements on the stack
        // - The number of signatures specified in the stack is a POSITIVE number...

        // if the stack is empty, we raise an ERROR...
        if (stack.size() == 0) throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "he operation was invalid given the contents of the stack");

        // We check if the number of signatures specified on the Stack is NEGATIVE or > 20
        int pubKeyCount = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();
        if (pubKeyCount < 0 || pubKeyCount > 20)
                throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEY_COUNT, "there are too many, or not enough, public keys");

        opCount += pubKeyCount;
        if (opCount > 201)
            throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "script contains too many opcodes");
        if (stack.size() < pubKeyCount + 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

        LinkedList<byte[]> pubkeys = new LinkedList<byte[]>();
        for (int i = 0; i < pubKeyCount; i++) {
            byte[] pubKey = stack.pollLast();
            pubkeys.add(pubKey);
        }

        int sigCount = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();
        if (sigCount < 0 || sigCount > pubKeyCount)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_COUNT, "sig count out of range");
        if (stack.size() < sigCount + 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "the operation was invalid given the contents of the stack");

        LinkedList<byte[]> sigs = new LinkedList<byte[]>();
        for (int i = 0; i < sigCount; i++) {
            byte[] sig = stack.pollLast();
            sigs.add(sig);
        }

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        for (byte[] sig : sigs) {
            UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sig.length + 1);
            try {
                writeBytes(outStream, sig);
            } catch (IOException e) {
                throw new RuntimeException(e); // Cannot happen
            }
            connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());
        }

        boolean valid = true;

        // we copy the Signature array into another List, and we use this copy to check the
        // Multisignature
        // NOTE this is important, since later on we need the original List of signatures to
        // perform other verifications, like NULLFAIL

        LinkedList<byte[]> sigsCopy = new LinkedList<byte[]>(sigs);

        while (! sigsCopy.isEmpty()) {
            byte[] pubKey = pubkeys.pollFirst();
            // We could reasonably move this out of the loop, but because signature verification is significantly
            // more expensive than hashing, its not a big deal.
            TransactionSignature sig;
            try {

                if (sigsCopy.getFirst().length > 0) {

                    // We check the signature Encoding.
                    // In case of failed verification, and Exception is thrown
                    checkSignatureEncoding(sigsCopy.getFirst(), verifyFlags);

                    // We check the Public Key encoding and compression.
                    // In case of failed verification, and Exception is thrown
                    checkPubKeyEncoding(pubKey, verifyFlags);


                    // Signature is well-structured, but it can still be Empty, so we control that situations...
                    if (sigsCopy.getFirst().length > 0) {
                        sig = TransactionSignature.decodeFromBitcoin(sigsCopy.getFirst(), requireCanonical);
                        Sha256Hash hash = sig.useForkId() ?
                                txContainingThis.hashForSignatureWitness(index, connectedScript, value, sig.sigHashMode(), sig.anyoneCanPay(), verifyFlags) :
                                txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);
                        if (ECKey.verify(hash.getBytes(), sig, pubKey))
                            sigsCopy.pollFirst();
                    }
                }

            } catch (SignatureFormatError e) {
                // the sig failed to verify against the pubkey, but that's ok, lets move on to the next one
            }
            if (sigsCopy.size() > pubkeys.size()) {
                valid = false;
                break;
            }
        } // while...

        // We uselessly remove a stack object to emulate a Bitcoin Core bug.
        byte[] nullDummy = stack.pollLast();
        if (verifyFlags.contains(VerifyFlag.NULLDUMMY) && nullDummy.length > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLDUMMY, "CHECKMULTISIG with non-null nulldummy");

        // NULLFAIL Verification:
        // If the NULLFAIL flag is active and the result of the Signature Verification is FALSE, we check
        // that every signature involved is an empty Array...
        if (!valid && verifyFlags.contains(VerifyFlag.NULLFAIL))
            for (byte[] sig : sigs) if (sig.length > 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL-compliant");

        if (opcode == OP_CHECKMULTISIG) {
            stack.add(valid ? new byte[] {1} : new byte[] {});
        } else if (opcode == OP_CHECKMULTISIGVERIFY) {
            if (!valid)
                throw new ScriptException("Script failed OP_CHECKMULTISIGVERIFY");
        }
        return opCount;
    }

    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey, enabling all
     * validation rules.
     * @param txContainingThis The transaction in which this input scriptSig resides.
     *                         Accessing txContainingThis from another thread while this method runs results in undefined behavior.
     * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @deprecated Use {@link #correctlySpends(org.bitcoinj.core.Transaction, long, org.bitcoinj.script.Script, java.util.Set)}
     * instead so that verification flags do not change as new verification options
     * are added.
     */
    @Deprecated
    public void correctlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey) {
        correctlySpends(txContainingThis, scriptSigIndex, scriptPubKey, Coin.ZERO, ALL_VERIFY_FLAGS);
    }

    @Deprecated
    public void correctlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey,
                                Set<VerifyFlag> verifyFlags) {
        correctlySpends(txContainingThis, scriptSigIndex, scriptPubKey, Coin.ZERO, verifyFlags);
    }
    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * @param txContainingThis The transaction in which this input scriptSig resides.
     *                         Accessing txContainingThis from another thread while this method runs results in undefined behavior.
     * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @param verifyFlags Each flag enables one validation rule. If in doubt, use {@link #correctlySpends(Transaction, long, Script)}
     *                    which sets all flags.
     */
    public void correctlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey, Coin value,
                                Set<VerifyFlag> verifyFlags) {
        // Clone the transaction because executing the script involves editing it, and if we die, we'll leave
        // the tx half broken (also it's not so thread safe to work on it directly.
        try {
            txContainingThis = txContainingThis.getParams().getDefaultSerializer().makeTransaction(txContainingThis.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e);   // Should not happen unless we were given a totally broken transaction.
        }

        // We check the size of the Script:
        if (getProgram().length > 10000 || scriptPubKey.getProgram().length > 10000)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "the script is too large");

        // In case FORKID is enabled, then we also force the STRICTENC flag
        if (verifyFlags.contains(VerifyFlag.SIGHASH_FORKID))
            verifyFlags.add(VerifyFlag.STRICTENC);

        // In case the "SIGPUSHONLY" flag is enmabled, we check that the script is composed of ONLY
        // PUSH operations...
        if (verifyFlags.contains(VerifyFlag.SIGPUSHONLY) && (!this.isPushOnly()))
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY
                    ,"attempted to spend a P2SH scriptPubKey with a script that contained script ops");

        LinkedList<byte[]> stack = new LinkedList<byte[]>();
        LinkedList<byte[]> p2shStack = null;

        executeScript(txContainingThis, scriptSigIndex, this, stack, value, verifyFlags);
        //executeDebugScript(txContainingThis, scriptSigIndex, this, stack, value, verifyFlags, ScriptLogManager.getListener(ScriptLogListener.ScriptType.scriptSig));

        if (verifyFlags.contains(VerifyFlag.P2SH))
            p2shStack = new LinkedList<byte[]>(stack);

        executeScript(txContainingThis, scriptSigIndex, scriptPubKey, stack, value, verifyFlags);
        //executeDebugScript(txContainingThis, scriptSigIndex, scriptPubKey, stack, value, verifyFlags, ScriptLogManager.getListener(ScriptLogListener.ScriptType.scriptPubKey));

        if (stack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "script evaluated false");
        
        if (!castToBool(stack.pollLast()))
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "script evaluated false");

        // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
        // program but it has "useless" form that if evaluated as a normal program always returns true.
        // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
        // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
        //
        // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
        //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
        //     un-wieldy to copy/paste.
        // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
        //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
        //     overall scalability and performance.

        // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
        if (verifyFlags.contains(VerifyFlag.P2SH) && scriptPubKey.isPayToScriptHash()) {
            for (ScriptChunk chunk : chunks)
                if (chunk.isOpCode() && chunk.opcode > OP_16)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY
                            ,"attempted to spend a P2SH scriptPubKey with a script that contained script ops");
            
            byte[] scriptPubKeyBytes = p2shStack.pollLast();
            Script scriptPubKeyP2SH = new Script(scriptPubKeyBytes);

            executeScript(txContainingThis, scriptSigIndex, scriptPubKeyP2SH, p2shStack, value, verifyFlags);
            //executeDebugScript(txContainingThis, scriptSigIndex, scriptPubKeyP2SH, p2shStack, value, verifyFlags, ScriptLogManager.getListener(ScriptLogListener.ScriptType.p2sh));

            if (p2shStack.isEmpty())
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "script evaluated false");
            
            if (!castToBool(p2shStack.pollLast()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "script evaluated false");

            // We restore the Stack with the rsult of the p2shStack after executing the redeem script...
            stack = p2shStack;

        }

        // The CLEANSTACK check is only performed after potential P2SH evaluation,
        // as the non-P2SH evaluation of a P2SH script will obviously not result in
        // a clean stack (the P2SH inputs remain). The same holds for witness
        // evaluation.
        if (verifyFlags.contains(VerifyFlag.CLEANSTACK) && verifyFlags.contains(VerifyFlag.P2SH)) {
            if (stack.size() != 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CLEANSTACK
                        , "CleanStack check failed. Stack size is not empty.");
        }
    }


    /**
     * Checks if the top of the stack (parameter) meets the requirements for the MINIMALIF Flag, which are:
     * - the value is an empty vector.
     * - OR:
     * - The value must be a single byte AND the value must be 1.
     *
     * NOTE: This methods receives the top of the stack as a parameter, so the caller must make sure that
     * the stack is not modified (best option is to use stack.peekLast() before calling this method).
     *
     * @param topStack  Value from the top of the stack
     * @return          true: Pass MINIMALIF validation /False: NOT pass
     */
    private static boolean checkMinimalIf(byte[] topStack) {
        return ((topStack.length == 0) || (topStack.length == 1 && topStack[0] == 1));
    }

    /**
     * checks whether the encoded signature looks to be validly encoded, depending on the flags supplied.
     * NOTE: this method has been changed, from returning a boolean to returning void and throwing a more
     * specific exception depending on the cause of the problem.
     *
     * Following the implementation from bitcoin-abc, the SignatureEncoding Verification can now fail due to
     * different factors, and we need info about which ones has explicity failed. so instead of returning a
     * boolean (which is not specific enough), we throw a more specific exception in case of failure.
     *
     * @throws              Exception in case signature is not valid
     */
    private static void checkSignatureEncoding(byte[] sigBytes, Set<VerifyFlag> flags) throws SignatureFormatError {

        // NOTE:
        // When the "STRICTENC" flag is active, we need to check if the Signature encoding is right, and
        // different errors might be thrown: SIG_DER, SIG_HASHTYPE and FORID.
        //  - SIG_DER: The signature is not DER-encoded
        //  - SIGHASH_TYPE: The SIGHASH (last byte in the signature) is wrong.
        //  - FORKID:

        boolean derEncodingOK = true;
        boolean sighashTypeOK = true;
        boolean forkIdOK = true;
        String errMsg = null;

        // If the flags specify STRICTENC, DERSIG or LOW_S, we check if the Signature is CANONICAL...
        if ((flags.contains(VerifyFlag.STRICTENC)
                || flags.contains(VerifyFlag.DERSIG)
                || flags.contains(VerifyFlag.LOW_S))
                && !TransactionSignature.isEncodingCanonical(sigBytes)) {
            derEncodingOK = false;
            errMsg = "Signature not in DER Format";
        }


        if (derEncodingOK) {
            // We check Low DER Signature...
            if (flags.contains(VerifyFlag.LOW_S)) checkLowDERSignature(sigBytes);

            // We check the HASHTYPE and the FORKID...
            if (flags.contains(VerifyFlag.STRICTENC)) {

                // Checking hashtype...
                if (!TransactionSignature.isValidHashType(sigBytes)) {
                    sighashTypeOK = false;
                    errMsg = "Hashtype not correct in Signature";
                }


                // checking forkIdEnabled...
                boolean usesForkId = TransactionSignature.hasForkId(sigBytes);
                boolean forIkEnabled = flags.contains(VerifyFlag.SIGHASH_FORKID);
                if (!forIkEnabled && usesForkId) {
                    forkIdOK = false;
                    errMsg = "FORKID verification disabled, but FORKId found in the Signature";
                }
                if (forIkEnabled && !usesForkId) {
                    forkIdOK = false;
                    errMsg = "FORKID verification enabled, but no FORKId found in the Signature";
                }
            }
        }


        // Now we trigger the error. In case more than one error has been detected, we trigger only one of them. The
        // priority in this case does not affect the outcome of the Script (ScriptException in any case).

        if (!sighashTypeOK) throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_HASHTYPE, errMsg);
        if (!forkIdOK) throw new ScriptException(ScriptError.SCRIPT_ERR_FORKID, errMsg);
        if (!derEncodingOK) throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER, errMsg);

        // If we reach this far, Signature is OK...
    }

    // TODO: Implementation pending...
    private static void checkLowDERSignature(byte[] sigBytes) throws SignatureFormatError {}

    /**
     * Checks the Public Key encoding
     * (bitcoin-abc implementation as a reference)
     *
     * @param sigBytes              signature
     * @param flags                 verification flags
     * @throws ScriptException      Exception
     */
    private static void checkPubKeyEncoding(byte[] sigBytes, Set<VerifyFlag> flags) throws ScriptException {

        if ((flags.contains(VerifyFlag.STRICTENC))
            && !ECKey.isPubKeyCanonical(sigBytes))
            throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEYTYPE, "Public Key not properly encoded");

        // Only compressed keys are accepted when
        // SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE is enabled.

        if (flags.contains(VerifyFlag.PUBKEYTYPE) && !IsCompressedPubKey(sigBytes))
            throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEYTYPE, "Publick Key not properly compressed.");

        // If we reach this far, Signature is OK...
    }

    /**
     * Checks if the public key given is properly compressed.
     *
     * @param sigBytes      Signature
     * @return              true (properly compressed) / False
     */
    private static boolean IsCompressedPubKey(byte[] sigBytes) {
        //  Non-canonical public key: invalid length for compressed key
        if (sigBytes.length != 33) return false;

        //  Non-canonical public key: invalid prefix for compressed key
        if (sigBytes[0] != 0x02 && sigBytes[0] != 0x03) return false;

        return true;
    }

    /**
     * Indicates if this script is made up of only PUSH operations
     * @return  true (ony PUSH) / False
     */
    public boolean isPushOnly() {
        boolean result = true;
        Iterator<ScriptChunk> it = chunks.iterator();

        while (result && it.hasNext()) {
            int opCode = it.next().opcode;
            // Note that IsPushOnly() *does* consider OP_RESERVED to be a push-type
            // opcode, however execution of OP_RESERVED fails, so it's not relevant
            // to P2SH/BIP62 as the scriptSig would fail prior to the P2SH special
            // validation code being executed.
            if (opCode > ScriptOpCodes.OP_16) result = false;
        } // while...

        return result;
    }

    // Utility that doesn't copy for internal use
    private byte[] getQuickProgram() {
        if (program != null)
            return program;
        return getProgram();
    }

    /**
     * Get the {@link org.bitcoinj.script.Script.ScriptType}.
     * @return The script type.
     */
    public ScriptType getScriptType() {
        ScriptType type = ScriptType.NO_TYPE;
        if (isSentToAddress()) {
            type = ScriptType.P2PKH;
        } else if (isSentToRawPubKey()) {
            type = ScriptType.PUB_KEY;
        } else if (isPayToScriptHash()) {
            type = ScriptType.P2SH;
        }
        return type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(getQuickProgram(), ((Script)o).getQuickProgram());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getQuickProgram());
    }
}
