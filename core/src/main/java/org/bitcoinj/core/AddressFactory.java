/*
 * Copyright 2018 bitcoinj-cash developers
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
/**
 * This is a factory class that creates Address or CashAddress objects from strings.
 * It will create an Address object from Base58 strings or a CashAddress object from
 * cashaddr format strings.
 */
public class AddressFactory {

    public static AddressFactory create() {
        return new AddressFactory();
    }

    /**
     * Construct an address from a string representation.
     * @param params
     *            The expected NetworkParameters or null if you don't want validation.
     * @param plainAddress
     *            The textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL" or
     *            "bitcoincash:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h"
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid or the address
     *             is for the wrong network.
     */
    public Address getAddress(NetworkParameters params, String plainAddress) {
        try {
            return CashAddressFactory.create().getFromFormattedAddress(params, plainAddress);
        } catch (AddressFormatException x) {
            try {
                return Address.fromBase58(params, plainAddress);
            } catch (AddressFormatException x2) {
                throw new AddressFormatException("Address " + plainAddress + " does not match cash (" + x.getMessage() + ") or legacy formats (" + x2.getMessage());
            }
        }
    }
}
