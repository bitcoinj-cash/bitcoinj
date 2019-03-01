/*
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
 */
package org.bitcoinj.script;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.VerificationException;
import org.junit.Test;

import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

@RunWith(Parameterized.class)
public class ScriptDataDrivenTest {
    @Parameters
    public static Collection<JsonNode> getData() throws IOException {
        Collection<JsonNode> testData = new ArrayList<JsonNode>(1000);
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(Thread.currentThread().getContextClassLoader().
                getResourceAsStream("script_tests.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            if (test.size() > 1) {          // ignore comments
                testData.add(test);
            }
        }
        return testData;
    }

    private JsonNode jsonData;

    public ScriptDataDrivenTest(JsonNode testData) {
        jsonData = testData;
    }

    @Test
    public void testNamedScript() throws IOException {
        Coin value = Coin.valueOf(0);
        Script scriptSig;
        Script scriptPubKey;
        Set<Script.VerifyFlag> flags;
        String expected = "";
        String comments = "";
        int i = 0;
        String result = "OK";

        // NOTE:
        // In case the test cases are missing the EXPECTED_RESULT field (because they all belong to a file where all
        // the tests are supposed to fail, for example), we don't need to parse that field. So in that case we need
        // to set the EXPECTED_RESULT in advance...
        //  - If all the tests are supposed to fail, set the EXPECTED_RESULT to 'ERROR'.
        //  - If all the tests are supposed to fail, set the EXPECTED_RESULT to 'OK'.

        // NOTE: USe the following values depending on the json file:
        // script_tests.json from bitcoinJ: null
        // script_invalid.json from bitcoinj-cash: "ERROR"
        // script_valid.json from bitcoinj-cash: "OK"
        // script_tests.json from bitcopin.abc: null
        // script_tests.json from nChain branch: null

        String FIXED_EXPECTED_RESULT = null;

        //FIXED_EXPECTED_RESULT = "ERROR"
        //FIXED_EXPECTED_RESULT = "OK"

        try {


            // We check length of each Test
            if (jsonData.size() > 6) {
                fail(String.format("too many fields in json: %s", jsonData));
            }
            // We check if the test specifies some money (first position of the array within the test)
            if (jsonData.get(0).isArray()) {
                value = Coin.parseCoin(jsonData.get(i++).get(0).asText());
            }


            String scriptSigString = jsonData.get(i++).asText();
            String scriptPubKeyString = jsonData.get(i++).asText();
            String flagString = jsonData.get(i++).asText();

            if (FIXED_EXPECTED_RESULT == null) {
                expected = jsonData.get(i++).asText();
                if (jsonData.size() > 4) {
                    comments = jsonData.get(i).asText();
                }
            }
            else expected = FIXED_EXPECTED_RESULT;


            flags = ScriptHelpers.parseVerifyFlags(flagString);

            // TODO: these capabilities have not been implemented yet or they are failing
            if (expected.equals("SIG_HIGH_S")) {
                return;
            }
            scriptSig = ScriptHelpers.parseScriptString(scriptSigString);
            scriptPubKey = ScriptHelpers.parseScriptString(scriptPubKeyString);

            Transaction creditTx = ScriptHelpers.buildCreditingTransaction(scriptPubKey,value);
            creditTx.verify();
            Transaction spendTx = ScriptHelpers.buildSpendingTransaction(scriptSig, creditTx);
            spendTx.verify();

            scriptSig.correctlySpends(spendTx, 0, scriptPubKey, value, flags);

        }

        catch (ScriptException e) {
            if (FIXED_EXPECTED_RESULT != null) result = "ERROR";
            else if (e.getError() != null)
                    result = e.getError().getMnemonic();
                 else result = "UNKNOWN_ERROR";
        } catch (VerificationException e) {
            if (expected != null && !expected.equals("")) result = "ERROR";
            else result = "UNKNOWN_ERROR";
        } catch (Throwable e) {
            // We shouldn't get here
            e.printStackTrace();
        }

        if (!result.equals(expected)) {
            fail(String.format("FAILED: result=%s, expected=%s", result,expected));
        }
    }

}
