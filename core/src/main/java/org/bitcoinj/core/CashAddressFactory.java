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
package org.bitcoinj.core;

import javafx.util.Pair;
import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static org.bitcoinj.core.Address.isAcceptableVersion;
import static org.bitcoinj.core.CashAddressHelper.ConvertBits;

public class CashAddressFactory {

    public static CashAddressFactory create() {
        return new CashAddressFactory();
    }

    public CashAddress fromP2SHHash(NetworkParameters params, byte[] hash160) {
        return new CashAddress(params, CashAddress.CashAddressType.Script, hash160);
    }

    public CashAddress fromP2SHScript(NetworkParameters params, Script scriptPubKey) {
        checkArgument(scriptPubKey.isPayToScriptHash(), "Not a P2SH script");
        return fromP2SHHash(params, scriptPubKey.getPubKeyHash());
    }

    public CashAddress getFromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException {
        VersionedChecksummedBytes parsed = new VersionedChecksummedBytes(base58);
        NetworkParameters addressParams = null;
        if (params != null) {
            if (!isAcceptableVersion(params, parsed.version)) {
                throw new WrongNetworkException(parsed.version, params.getAcceptableAddressCodes());
            }
            addressParams = params;
        } else {
            for (NetworkParameters p : Networks.get()) {
                if (isAcceptableVersion(p, parsed.version)) {
                    addressParams = p;
                    break;
                }
            }
            if (addressParams == null) {
                throw new AddressFormatException("No network found for " + base58);
            }
        }
        return new CashAddress(addressParams, parsed.version, parsed.bytes);
    }

    public CashAddress getFromFormattedAddress(NetworkParameters params, String addr) throws AddressFormatException {
        CashAddressValidator cashAddressValidator = CashAddressValidator.create();

        Pair<String, byte[]> pair = CashAddressHelper.decodeCashAddress(addr, params.getCashAddrPrefix());
        String prefix = pair.getKey();
        byte[] payload = pair.getValue();

        cashAddressValidator.checkValidPrefix(params, prefix);
        cashAddressValidator.checkNonEmptyPayload(payload);

        byte extraBits = (byte) (payload.length * 5 % 8);
        cashAddressValidator.checkAllowedPadding(extraBits);

        byte last = payload[payload.length - 1];
        byte mask = (byte) ((1 << extraBits) - 1);
        cashAddressValidator.checkNonZeroPadding(last, mask);

        byte[] data = new byte[payload.length * 5 / 8];
        ConvertBits(data, payload, 5, 8, false);

        byte versionByte = data[0];
        cashAddressValidator.checkFirstBitIsZero(versionByte);

        int hashSize = calculateHashSizeFromVersionByte(versionByte);
        cashAddressValidator.checkDataLength(data, hashSize);

        byte result[] = new byte[data.length - 1];
        System.arraycopy(data, 1, result, 0, data.length - 1);
        CashAddress.CashAddressType type = getAddressTypeFromVersionByte(versionByte);

        return new CashAddress(params, type, result);
    }

    private CashAddress.CashAddressType getAddressTypeFromVersionByte(byte versionByte)
            throws AddressFormatException {
        switch (versionByte >> 3 & 0x1f) {
            case 0:
                return CashAddress.CashAddressType.PubKey;
            case 1:
                return CashAddress.CashAddressType.Script;
            default:
                throw new AddressFormatException("Unknown Type");
        }
    }

    private int calculateHashSizeFromVersionByte(byte versionByte) {
        int hash_size = 20 + 4 * (versionByte & 0x03);
        if ((versionByte & 0x04) != 0) {
            hash_size *= 2;
        }
        return hash_size;
    }

}
