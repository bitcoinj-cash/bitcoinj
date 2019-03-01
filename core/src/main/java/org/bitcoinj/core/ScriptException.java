/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core;


import org.bitcoinj.script.ScriptError;

public class ScriptException extends VerificationException {

    private  ScriptError err = null;

    public ScriptException(ScriptError err, String msg) {
        super(msg);
        this.err = err;
    }

    public ScriptException(ScriptError err, String msg, Exception e) {
        super(msg, e);
        this.err = err;
    }

    public ScriptException(String msg) {
        super(msg);
    }

    public ScriptError getError() {
        return err;
    }

}
