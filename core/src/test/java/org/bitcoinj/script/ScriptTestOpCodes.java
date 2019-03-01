package org.bitcoinj.script;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ScriptException;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.LinkedList;


/**
 * Base class for testing the different OPCodes in the Bitcoin script language. It provides
 * some utility methods for testing and casting between data types.
 *
 * As a general rule, the data in the stack is an array of bytes. The "StackItem" class provides
 * an abstraction over it, so the content can be treated as a number or any other data.
 *
 * the process of testing a OpCode consists of building a Script with the OPCode desired, putting the
 * needed operands into the Stack, and run the Script. The result (top of the stack) is then compared
 * to the expected result, to determine whether the result is OK or not.
 */

public class ScriptTestOpCodes {


    /**
     * Verifies the specified Script works properly, and that the result of the execution (top of the stack) is
     * the expected result.
     */
    protected void checkTestResult(LinkedList<byte[]> originalStack, Script script, EnumSet<Script.VerifyFlag> flags,
                                   byte[] expected, ScriptError expectedError)
            throws Exception {

        boolean result = true;
        try {
            // We execute the script over the stack given...
            Script.executeScript(null, 0, script, originalStack, Coin.ZERO, flags);

            // If the script executed without errors, now we check if the top of the stack matches the expected result...
            byte[] topStack = originalStack.pollLast();
            if (topStack.length == expected.length) {
                for (int i = 0; i < topStack.length; i++) if (topStack[i] != expected[i]) result = false;
            } else result = false;

            // If the result is WRONG, we throw an exception...
            if (!result) {
                StackItem topStackItem = StackItem.ofBytes(topStack);
                StackItem expectedItem = StackItem.ofBytes(expected);
                throw new Exception("Test ERROR: expected: " + expectedItem.toBits()
                        +  ", actual result: " + topStackItem.toBits());
            }

        } catch (ScriptException se) {
            // An exception has been thrown by the Script engine. We check if an expected Error has been expecified,
            // and if the error thrown matches:
            if ((expectedError != null) && (!se.getError().equals(expectedError)))
                throw new Exception("Test ERROR: Expected error: " + expectedError.getMnemonic()
                + ", actual error: " + se.getError().getMnemonic());
        }
    }

    /**
     * Verifies that the Op-Code works properly with the 2 operands provided, and the result (after executing the
     * script engine behind the scenes) is the same as the expected one.
     *
     */
    protected void checkBinaryTestResult(byte[] op1, byte[] op2, int opCode, EnumSet<Script.VerifyFlag> flags,
                                           byte[] expected, ScriptError expectedError) throws Exception {
        try {
            LinkedList<byte[]> stack = new LinkedList<>();
            stack.add(op1);
            stack.add(op2);

            // We build a Script that only contains the OP Code
            ScriptBuilder scriptBuilder = new ScriptBuilder();
            Script script = scriptBuilder.op(opCode).build();

            // We run the Script.
            checkTestResult(stack, script, flags, expected, expectedError);
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Convenience method, using "StackItem" instans for the stack Elemewnts instead of raw byte arrays.
     */
    protected void checkBinaryTestResult(Object op1, Object op2, int opCode, EnumSet<Script.VerifyFlag> flags,
                                         Object expected, ScriptError expectedError) throws Exception {
        StackItem op1Item = StackItem.of(op1);
        StackItem op2Item = StackItem.of(op2);
        StackItem expectedItem = StackItem.of(expected);
        checkBinaryTestResult(op1Item.bytes(), op2Item.bytes(), opCode, flags, expectedItem.bytes(), expectedError);
    }


    /**
     * Verifies that the op Code works properly with the Operand provided.
     */
    protected void checkUnaryTestResult(byte[] op1, int opCode, EnumSet<Script.VerifyFlag> flags,
                                        byte[] expected, ScriptError expectedError)
    throws Exception {
        try {
            LinkedList<byte[]> stack = new LinkedList<>();
            stack.add(op1);

            // We build a Script that only contains the OP Code
            ScriptBuilder scriptBuilder = new ScriptBuilder();
            Script script = scriptBuilder.op(opCode).build();

            // We run the Script.
            checkTestResult(stack, script, flags, expected, expectedError);

        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Convenience method, using "StackItem" instans for the stack Elemewnts instead of raw byte arrays.
     */
    protected void checkUnaryTestResult(Object op1, int opCode, EnumSet<Script.VerifyFlag> flags,
                                        Object expected, ScriptError expectedError) throws Exception {
        StackItem op1Item = StackItem.of(op1);
        StackItem expectedItem = StackItem.of(expected);
        checkUnaryTestResult(op1Item.bytes(),  opCode, flags, expectedItem.bytes(), expectedError);
    }
}
