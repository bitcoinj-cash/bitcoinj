/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Thomas König
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
import org.bitcoinj.params.UnitTestParams;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.EnumSet;
import java.util.Set;

import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVALIDOPCODE;


public class ScriptHelpers {
    private static final NetworkParameters unitTestParameters = new UnitTestParams();

    public static Script parseScriptString(String string) throws IOException {
        String[] words = string.split("[ \\t\\n]");

        UnsafeByteArrayOutputStream out = new UnsafeByteArrayOutputStream();

        for(String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int)val));
                else
                    Script.writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(HEX.decode(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(Charset.forName("UTF-8")));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                // CHANGE: We throw a Disabled OPCode Exception instad of a more general IllegalArgumentEx
                // throw new IllegalArgumentException(String.format("Invalid Data: %s", w));
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, String.format("Invalid Data: %s", w));
            }
        }
        return new Script(out.toByteArray());
    }

    public static Set<Script.VerifyFlag> parseVerifyFlags(String str) {
        Set<Script.VerifyFlag> flags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (!"NONE".equals(str) && !"".equals(str)) {
            for (String flag : str.split(",")) {
                try {
                    flags.add(Script.VerifyFlag.valueOf(flag));
                } catch (IllegalArgumentException x) {
                    throw new IllegalArgumentException(String.format("unrecognized verify flag: %s", flag));
                }
            }
        }
        return flags;
    }

    public static Transaction buildCreditingTransaction(final Script scriptPubKey, final Coin value) {
        Transaction transaction = new Transaction(unitTestParameters);
        transaction.setVersion(1);
        transaction.setLockTime(0);
        transaction.addInput(new TransactionInput(unitTestParameters, transaction,
                new ScriptBuilder().number(0).number(0).build().getProgram()));
        transaction.addOutput(new TransactionOutput(unitTestParameters, transaction, value, scriptPubKey.getProgram()));
        return transaction;
    }

    public static Transaction buildSpendingTransaction(final Script scriptSig,
                         final Transaction txCredit) {
        Transaction txSpend = new Transaction(unitTestParameters);
        txSpend.setVersion(1);
        txSpend.setLockTime(0);
        txSpend.addInput(new TransactionInput(unitTestParameters, txSpend, scriptSig.getProgram(),
                new TransactionOutPoint(unitTestParameters, txCredit.getOutput(0))));
        txSpend.addOutput(new TransactionOutput(unitTestParameters, txSpend, txCredit.getOutput(0).getValue(),
                new ScriptBuilder().build().getProgram()));
        return txSpend;
    }
}
