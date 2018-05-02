package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class AddressFactoryTest {

    private CashAddressFactory cashAddressFactory;
    private AddressFactory addressFactory;

    @Before
    public void setUpCashAddressFactory() {
        cashAddressFactory = CashAddressFactory.create();
        addressFactory = AddressFactory.create();
    }

    @Test
    public void testAddressFactory() {
        NetworkParameters params = MainNetParams.get();
        String cashAddress = "bitcoincash:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        String legacyAddress = "1AyEgvE2XNM65EkdisywrZZghHuMv1ngf8";
        try {
            //create cash addresses using both methods
            CashAddress fromFormattedAddress = cashAddressFactory.getFromFormattedAddress(params, cashAddress);
            Address fromGetAddress = addressFactory.getAddress(params, cashAddress);

            //create legacy addresses using both methods
            Address fromBase58 = Address.fromBase58(params, legacyAddress);
            Address fromGetAddressLegacy = addressFactory.getAddress(params, legacyAddress);

            //test proper creation of cash addresses
            assertEquals(fromFormattedAddress.toString(), cashAddress);
            assertEquals(fromGetAddress.toString(), cashAddress);

            //test proper creation of legacy addresses
            assertEquals(fromBase58.toString(), legacyAddress);
            assertEquals(fromGetAddressLegacy.toBase58(), legacyAddress);
        } catch (AddressFormatException ex) {
            fail("Unexpected exception: " + ex.getMessage());
        }
    }
    @Test
    public void testingUsingWrongFactory() {
        NetworkParameters params = MainNetParams.get();
        String cashAddress = "bitcoincash:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        String legacyAddress = "1AyEgvE2XNM65EkdisywrZZghHuMv1ngf8";
        try {
            cashAddressFactory.getFromFormattedAddress(params, legacyAddress);
            fail("getFromFormattedAddress should fail with legacy address");
        } catch (AddressFormatException ex) {
            //message may contain:  "Cannot contain both upper and lower case letters"));
        }

        try {
            Address.fromBase58(params, cashAddress);
            fail("fromBase58 should fail with a cash address");
        } catch (AddressFormatException ex) {
            //message may contain:  "Illegal character"
        }
    }
}
