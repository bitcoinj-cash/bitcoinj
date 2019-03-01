package org.bitcoinj.script;

import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Utils;
import java.math.BigInteger;

import static org.bitcoinj.core.Utils.HEX;

/**
 * This class represents an Item in the Stack used by the Bitcoin Scripting Language.
 * Each element of the Stack is an array of Bytes. Depending on the way each item is
 * used, we can treat it as a number, as a signature, etc.
 *
 * This class provides an abstraction with useful methods for using an item as a Number
 * (more types might come in the future)
 */
public class StackItem {

    // The "physical" content of the item.
    private byte[] content;

    // Constructors (private). Use the Factory methods instead.
    private StackItem(byte[] content)                   { this.content =  content;}
    private StackItem(String hex)  throws Exception     { this.content = castToByteArray(hex); }
    private StackItem(long num)                         { this.content = castToByteArray(BigInteger.valueOf(num));}


    /**
     * Returns a new Item storing the bytes given.
     */
    public static StackItem ofBytes(byte[] content)     { return new StackItem(content);}

    /**
     * Returns a new Item storing the bytes related to the HEX representation given. The Hex String
     * might or not might have a "0x" preffix.
     */
    public static StackItem ofHex(String hex) throws Exception  {return new StackItem(hex);}

    /**
     * Returns a new Item storing the bytes related to the Number provided.
     */
    public static StackItem ofNum(long num) {return new StackItem(num);}

    /**
     * Returns a new Item storing the data specified. Data types supported:
     * - Numeric
     * - String: Hexadecimal (Starting with '0x'), or binary (otherwise). A COMMA can be used as a byte separator
     */
    public static StackItem of(Object obj) throws Exception {
        if (obj instanceof  StackItem)  return (StackItem) obj;
        if (obj instanceof Integer)     return ofNum(((Number) obj).longValue());
        if (obj instanceof BigInteger)  return ofNum(((BigInteger) obj).longValue());
        if (obj instanceof String) {
            String objStr = (String) obj;
            if ((objStr == null) || (objStr.trim().length() == 0)) return EMPTY();
            else {
                if ((objStr != null) && objStr.startsWith("0x"))    return ofHex(objStr);
                if ((objStr != null) && (!objStr.startsWith("0x"))) return ofBits(objStr);
            }
        }
        throw new Exception("Data Type not supported");
    }

    /**
     * Returns a new instance storing the bytes rlated to the BIt pattern given. The pattern can use COMMA as ç
     * a separator for each byte. NO blanks or any other characteres are allowed.
     */
    public static StackItem ofBits(String bits) throws Exception {
        byte[] content = castBinaryToByteArray(bits);
        return new StackItem(content);
    }

    // Numeric Constants:
    public static StackItem ONE()       throws Exception { return new StackItem("0x01"); }
    public static StackItem EMPTY()     throws Exception { return new StackItem("");}
    public static StackItem MINUSONE()  throws Exception { return new StackItem("0x81"); }

    // returns the content
    public byte[] bytes() {return content;}

    /**
     * Returns the Bit representation of the content
     */
    public String toBits() {
        StringBuffer result = new StringBuffer().append("[ ");
        byte[] masks = {(byte)0x80,(byte)0x40,(byte)0x20,(byte)0x10,(byte)0x08,(byte)0x04,(byte)0x02,(byte)0x01};
        for (byte byteContent : content) {
            for (int i = 0; i < 8; i++) {
                if ((byteContent & masks[i]) == 0) result.append("0");
                else result.append("1");
            }
            result.append(" ");
        }
        result.append("]");
        return result.toString();
    }

    /**
     * Converts a binary representation (in string format) into a byte array. Only the characteres "1", "0" and ","
     * are allowed. If there is more than 1 byte, the character "," must be used as a separator.
     */
    protected static byte[] castBinaryToByteArray(String binary) throws Exception {
        byte[] masks = {(byte)0x80,(byte)0x40,(byte)0x20,(byte)0x10,(byte)0x08,(byte)0x04,(byte)0x02,(byte)0x01};
        byte[] result = null;
        if (binary != null) {
            String[] bytesStr = binary.split(",");
            result = new byte[bytesStr.length];
            for (int i  = 0; i < bytesStr.length; i++) {
                String byteStr = bytesStr[i];
                if (byteStr.length() != 8) throw new Exception("Each byte must have 8 Bits");
                int byteResult = result[i];
                for (int b = 0; b < 8; b ++) {
                    if (byteStr.charAt(b) == '1') byteResult = byteResult | masks[b];
                }
                result[i] = (byte) byteResult;
            } // for..
        } // if..
        return result;
    }

    /**
     * Converts an Hex String into an equivalent byte array.
     */
    protected static byte[] castHexToByteArray(String hex) {
        byte[] result = new byte[0];
        if (hex != null && hex.length() > 0) {
            int index = 0;
            if (hex.startsWith("0x")) index = 2;
            result = HEX.decode(hex.substring(index).toLowerCase());
        }
        return result;
    }

    /**
     * Converts an Hex String into an equivalent byte array. As a convenience method, this method also
     * allows for using COMMA as separator, for specifying different bytes separately. When using a
     * COMMA separator, each element must represent a single BYTE (<= 0xFF), and it might or might not
     * have the "0x" preffix.
     */
    protected static byte[] castToByteArray(String num) throws Exception {
        byte[] result = new byte[0];
        if (num != null && num.length() > 0) {
            if (!num.contains(",")) return castHexToByteArray(num);
            else {
                String[] hexs = num.split(",");
                result = new byte[hexs.length];
                for (int i = 0; i < hexs.length; i++) {
                    byte[] hexBytes = castHexToByteArray(hexs[i]);
                    if (hexBytes.length > 1) throw new Exception("Each number must be a single Byte");
                    result[i]= hexBytes[0];
                } // for...

            }
        }
        return result;
    }

    /**
     * Converts a byte Array into a BigInteger. The byte array follows the conventions used in the Bitcoin protocol:
     * - little endian codification: The least significatn bytes are on the left
     * - Signed magnitude representation: most significant bit contains the sign (1 = negative)
     */
    protected static BigInteger castToBigInteger(byte[] chunk, boolean enforceMaxLength, boolean enforceMinimal) {
        final int DEFAULT_MAX_NUM_ELEMENT_SIZE = 4;
        if (enforceMaxLength && chunk.length > DEFAULT_MAX_NUM_ELEMENT_SIZE)
            throw new ScriptException("Script attempted to use an integer larger than 4 bytes");
        if (enforceMinimal && !Utils.checkMinimallyEncodedLE(chunk, DEFAULT_MAX_NUM_ELEMENT_SIZE))
            throw new ScriptException("Number is not minimally encoded");
        //numbers on the stack or stored LE so convert as MPI requires BE.
        byte[] bytesBE = Utils.reverseBytes(chunk);
        return Utils.decodeMPI(bytesBE, false);
    }

    /**
     * Converts a BigInteger into a byte array
     */
    protected static byte[] castToByteArray(BigInteger num) {
        return Utils.reverseBytes(Utils.encodeMPI((BigInteger) num, false));
    }

    /**
     * Returns the content as a Number (BigInteger)
     */
    public BigInteger asNumber() {
        return castToBigInteger(content, false, false);
    }

    /**
     * It treats the content as a Number and return a new Instance with the negative value.
     */
    public StackItem negative() {
        BigInteger num = castToBigInteger(content, false, false).negate();
        byte[] newContent = castToByteArray(num);
        return new StackItem(newContent);
    }
}
