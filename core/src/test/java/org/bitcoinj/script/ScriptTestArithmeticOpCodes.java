package org.bitcoinj.script;

import org.junit.Test;

import java.util.EnumSet;

/**
 * Testing class for the Arithmetic Op Codes. Further coverage of OPcodes will be
 * added in the future.
 */
public class ScriptTestArithmeticOpCodes extends ScriptTestOpCodes{

    // FLAGS used for testing
    private static EnumSet<Script.VerifyFlag> FLAGS = Script.ALL_VERIFY_FLAGS;


    private void checkOP_MUL(Object op1, Object op2, Object expected) throws Exception {

        StackItem op1El = StackItem.of(op1);
        StackItem op2El = StackItem.of(op2);
        StackItem expEl = StackItem.of(expected);

        // Negative values for multiplication

        checkBinaryTestResult(op1El, op2El, ScriptOpCodes.OP_MUL, FLAGS, expEl, null);
        checkBinaryTestResult(op1El, op2El.negative(), ScriptOpCodes.OP_MUL, FLAGS, expEl.negative(), null);
        checkBinaryTestResult(op1El.negative(), op2El, ScriptOpCodes.OP_MUL, FLAGS, expEl.negative(), null);
        checkBinaryTestResult(op1El.negative(), op2El.negative(), ScriptOpCodes.OP_MUL, FLAGS, expEl, null);

        // Commutativity:
        checkBinaryTestResult(op2El, op1El, ScriptOpCodes.OP_MUL, FLAGS, expEl, null);
        checkBinaryTestResult(op2El.negative(), op1El, ScriptOpCodes.OP_MUL, FLAGS, expEl.negative(), null);
        checkBinaryTestResult(op2El, op1El.negative(),  ScriptOpCodes.OP_MUL, FLAGS, expEl.negative(), null);
        checkBinaryTestResult(op2El.negative(), op1El.negative(), ScriptOpCodes.OP_MUL, FLAGS, expEl, null);

        // Multiplication identities:
        checkBinaryTestResult(op1El, StackItem.ONE(),  ScriptOpCodes.OP_MUL, FLAGS, op1El, null);
        checkBinaryTestResult(op1El, StackItem.MINUSONE(),  ScriptOpCodes.OP_MUL, FLAGS, op1El.negative(), null);
        checkBinaryTestResult(StackItem.EMPTY(), op2El,  ScriptOpCodes.OP_MUL, FLAGS, StackItem.EMPTY(), null);

        checkBinaryTestResult(StackItem.ONE(), op2El,  ScriptOpCodes.OP_MUL, FLAGS, op2El, null);
        checkBinaryTestResult(StackItem.MINUSONE(), op2El,  ScriptOpCodes.OP_MUL, FLAGS, op2El.negative(), null);
        checkBinaryTestResult(op1El, StackItem.EMPTY(),  ScriptOpCodes.OP_MUL, FLAGS, StackItem.EMPTY(), null);
    }


    @Test
    public void testOP_MUL() throws Exception {
        checkOP_MUL("0x05","0x06", "0x1E");
        checkOP_MUL("0x05","0x26", "0xBE,0x00");
        checkOP_MUL("0x45","0x26", "0x3E,0x0A");
        checkOP_MUL("0x02","0x56,0x24", "0xAC,0x48");
        checkOP_MUL("0x05","0x26,0x03,0x32", "0xBE,0x0F,0xFA,0x00");
        checkOP_MUL("0x06","0x26,0x03,0x32,0x04", "0xE4,0x12,0x2C,0x19");
        checkOP_MUL("0xA0,0xA0","0xF5,0xE4", "0x20,0xB9,0xDD,0x0C");
        checkOP_MUL("0x05,0x26","0x26,0x03,0x32", "0xBE,0xB3,0x71,0x6D,0x07");
        checkOP_MUL("0x06,0x26","0x26,0x03,0x32,0x04", "0xE4,0xB6,0xA3,0x85,0x9F,0x00");
        checkOP_MUL("0x05,0x26,0x09","0x26,0x03,0x32", "0xBE,0xB3,0xC7,0x89,0xC9,0x01");
        checkOP_MUL("0x06,0x26,0x09","0x26,0x03,0x32,0x04", "0xE4,0xB6,0xF9,0xA1,0x61,0x26");
        checkOP_MUL("0x06,0x26,0x09,0x34","0x26,0x03,0x32,0x04", "0xE4,0xB6,0xF9,0x59,0x05,0x4F,0xDA,0x00");
    }

    /**
     * Convenience method for testing the LSHIFT or RSHIFT operators, specifying an expected Error.
     */
    private void checkOP_SHIFT(int op, Object op1, Object op2, Object expected, ScriptError expectedError) throws Exception {
        checkBinaryTestResult(op1, op2, op, FLAGS, expected, expectedError);
    }

    /**
     * Convenience method for testing the LSHIFT or RSHIFT operators, without specifying an expected Error.
     */
    private void checkOP_SHIFT(int op, Object op1, Object op2, Object expected) throws Exception {
        checkBinaryTestResult(op1, op2, op, FLAGS, expected, null);
    }

    @Test
    public void testOP_LSHIFT() throws Exception {

        int SHIFT = ScriptOpCodes.OP_LSHIFT;

        // Moving empy bytes:

        checkOP_SHIFT(SHIFT, "", "", "");
        checkOP_SHIFT(SHIFT, "", "0x01", "");
        checkOP_SHIFT(SHIFT, "", "0x02", "");
        checkOP_SHIFT(SHIFT, "", "0xFF", "");

        // Moving a single byte, using a bit pattern as the expected result:

        checkOP_SHIFT(SHIFT, "0xFF", "", "11111111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x01", "11111110");
        checkOP_SHIFT(SHIFT, "0xFF", "0x02", "11111100");
        checkOP_SHIFT(SHIFT, "0xFF", "0x03", "11111000");
        checkOP_SHIFT(SHIFT, "0xFF", "0x04", "11110000");
        checkOP_SHIFT(SHIFT, "0xFF", "0x05", "11100000");
        checkOP_SHIFT(SHIFT, "0xFF", "0x06", "11000000");
        checkOP_SHIFT(SHIFT, "0xFF", "0x07", "10000000");
        checkOP_SHIFT(SHIFT, "0xFF", "0x08", "00000000");

        // Moving a single byte, using an HEX as the expected result:
        // (same scenario as above)

        checkOP_SHIFT(SHIFT, "0xFF", "0x01", "0xFE");
        checkOP_SHIFT(SHIFT, "0xFF", "0x02", "0xFC");
        checkOP_SHIFT(SHIFT, "0xFF", "0x03", "0xF8");
        checkOP_SHIFT(SHIFT, "0xFF", "0x04", "0xF0");
        checkOP_SHIFT(SHIFT, "0xFF", "0x05", "0xE0");
        checkOP_SHIFT(SHIFT, "0xFF", "0x06", "0xC0");
        checkOP_SHIFT(SHIFT, "0xFF", "0x07", "0x80");
        checkOP_SHIFT(SHIFT, "0xFF", "0x08", "0x00");

        // Moving more bits than we have...
        checkOP_SHIFT(SHIFT, "0xFF", "0xFA", "0x00");

        // Moving bits in 2 bytes, checking boundaries:

        checkOP_SHIFT(SHIFT, "0x00,0x80", "0x01", "0x01,0x00");
        checkOP_SHIFT(SHIFT, "0x00,0x80,0x00", "0x01", "0x01,0x00,0x00");
        checkOP_SHIFT(SHIFT, "0x00,0x00,0x80", "0x01", "0x00,0x01,0x00");
        checkOP_SHIFT(SHIFT, "0x80,0x00,0x00", "0x01", "0x00,0x00,0x00");

        // {0x9F, 0x11, 0xF5, 0x55} is a sequence of bytes that is equal to the bit pattern
        // "10011111,00010001,11110101,01010101"

        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "", "10011111,00010001,11110101,01010101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x01", "00111110,00100011,11101010,10101010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x02", "01111100,01000111,11010101,01010100");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x03", "11111000,10001111,10101010,10101000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x04", "11110001,00011111,01010101,01010000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x05", "11100010,00111110,10101010,10100000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x06", "11000100,01111101,01010101,01000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x07", "10001000,11111010,10101010,10000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x08", "00010001,11110101,01010101,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x09", "00100011,11101010,10101010,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0A", "01000111,11010101,01010100,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0B", "10001111,10101010,10101000,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0C", "00011111,01010101,01010000,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0D", "00111110,10101010,10100000,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0E", "01111101,01010101,01000000,00000000");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0F", "11111010,10101010,10000000,00000000");

        // Error thrown when second parameter is negative:
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", StackItem.MINUSONE(),
                "11111010,10101010,10000000,00000000", ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE);
    }



    @Test
    public void testOP_RSHIFT() throws Exception {

        int SHIFT = ScriptOpCodes.OP_RSHIFT;
        // Moving empy bytes:

        checkOP_SHIFT(SHIFT, "", "", "");
        checkOP_SHIFT(SHIFT, "", "0x01", "");
        checkOP_SHIFT(SHIFT, "", "0x02", "");
        checkOP_SHIFT(SHIFT, "", "0xFF", "");


        // Moving a single byte, using a bit pattern as the expected result:

        checkOP_SHIFT(SHIFT,"0xFF", "", "11111111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x01", "01111111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x02", "00111111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x03", "00011111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x04", "00001111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x05", "00000111");
        checkOP_SHIFT(SHIFT, "0xFF", "0x06", "00000011");
        checkOP_SHIFT(SHIFT, "0xFF", "0x07", "00000001");
        checkOP_SHIFT(SHIFT, "0xFF", "0x08", "00000000");

        // Moving a single byte, using a HEX pattern as the expected result:
        // (same scenario as above)

        checkOP_SHIFT(SHIFT,"0xFF", "0x01", "0x7F");
        checkOP_SHIFT(SHIFT, "0xFF", "0x02", "0x3F");
        checkOP_SHIFT(SHIFT, "0xFF", "0x03", "0x1F");
        checkOP_SHIFT(SHIFT, "0xFF", "0x04", "0x0F");
        checkOP_SHIFT(SHIFT, "0xFF", "0x05", "0x07");
        checkOP_SHIFT(SHIFT, "0xFF", "0x06", "0x03");
        checkOP_SHIFT(SHIFT, "0xFF", "0x07", "0x01");
        checkOP_SHIFT(SHIFT, "0xFF", "0x08", "0x00");

        // Moving more bits than we have...
        checkOP_SHIFT(SHIFT, "0xFF", "0xFA", "0x00");

        // Moving bits in 2 bytes, checking boundaries:

        checkOP_SHIFT(SHIFT, "0x01,0x00", "0x01", "0x00,0x80");
        checkOP_SHIFT(SHIFT, "0x01,0x00,0x00", "0x01", "0x00,0x80,0x00");
        checkOP_SHIFT(SHIFT, "0x00,0x01,0x00", "0x01", "0x00,0x00,0x80");
        checkOP_SHIFT(SHIFT, "0x00,0x00,0x01", "0x01", "0x00,0x00,0x00");

        // {0x9F, 0x11, 0xF5, 0x55} is a sequence of bytes that is equal to the bit pattern
        // "10011111,00010001,11110101,01010101"

        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "", "10011111,00010001,11110101,01010101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x01", "01001111,10001000,11111010,10101010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x02", "00100111,11000100,01111101,01010101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x03", "00010011,11100010,00111110,10101010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x04", "00001001,11110001,00011111,01010101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x05", "00000100,11111000,10001111,10101010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x06", "00000010,01111100,01000111,11010101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x07", "00000001,00111110,00100011,11101010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x08", "00000000,10011111,00010001,11110101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x09", "00000000,01001111,10001000,11111010");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0A", "00000000,00100111,11000100,01111101");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0B", "00000000,00010011,11100010,00111110");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0C", "00000000,00001001,11110001,00011111");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0D", "00000000,00000100,11111000,10001111");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0E", "00000000,00000010,01111100,01000111");
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", "0x0F", "00000000,00000001,00111110,00100011");

        // Error thrown when second parameter is negative:
        checkOP_SHIFT(SHIFT, "0x9F,0x11,0xF5,0x55", StackItem.MINUSONE(),
                "11111010,10101010,10000000,00000000", ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE);

    }

}
