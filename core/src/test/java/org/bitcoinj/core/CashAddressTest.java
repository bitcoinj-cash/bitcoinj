package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Created by Hash Engineering Soltuions on 1/19/2018.
 */
public class CashAddressTest {

    private static final String ADDRESSES_FILE_PATH = "org/bitcoinj/core/bch_addresses.csv";
    private static final Map<String, String> CASH_ADDRESS_BY_LEGACY_FORMAT = new HashMap<String, String>();

    private CashAddressFactory cashAddressFactory;

    @BeforeClass
    public static void loadAddressBatch() throws IOException {
        ClassLoader classLoader = CashAddressTest.class.getClassLoader();
        File file = new File(classLoader.getResource(ADDRESSES_FILE_PATH).getFile());
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] components = line.split(",");
            CASH_ADDRESS_BY_LEGACY_FORMAT.put(components[0], components[1]);
        }
    }

    @Before
    public void setUpCashAddressFactory() {
        cashAddressFactory = CashAddressFactory.create();
    }

    @Test
    public void testPrefixDoesNotMatchWithChecksum() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "bchtest:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignored) {
        }
    }

    @Test
    public void testPrefixDoesMatchesWithChecksum() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "bitcoincash:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
        } catch (AddressFormatException ex) {
            fail("Unexpected exception: " + ex.getMessage());
        }
    }

    @Test
    public void testNoPayload() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testUnknownVersionByte() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{0x07, 0x01, 0x16, 0x15, 0x17, 0x16, 0x11, 0x0e, 0x1c, 0x06, 0x19, 0xa,
                0x1c, 0x00, 0xb, 0x00, 0x18, 0x05, 0x1e, 0x13, 0x07, 0x1d, 0x0b, 0x02, 0x03, 0x03, 0x03, 0x1a, 0x3,
                0x14, 0x1b, 0x1f, 0x19, 0x18};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testMoreThanAllowedPadding() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{0x07, 0x01, 0x16, 0x15, 0x17, 0x16, 0x11, 0x0e, 0x1c, 0x06, 0x19, 0xa,
                0x1c, 0x00, 0xb, 0x00, 0x18, 0x05, 0x1e, 0x13, 0x07, 0x1d, 0x0b, 0x02, 0x03};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testNonZeroPadding() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{0x07, 0x01, 0x16, 0x15, 0x17, 0x16, 0x11, 0x0e, 0x1c, 0x06, 0x19, 0xa,
                0x1c, 0x00, 0xb, 0x00, 0x18, 0x05, 0x1e, 0x13, 0x0d};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testFirstBitOfByteVersionNonZero() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{0x1f, 0x01, 0x16, 0x15, 0x17, 0x16, 0x11, 0x0e, 0x1c, 0x06, 0x19, 0xa,
                0x1c, 0x00, 0xb, 0x00, 0x18, 0x05, 0x1e, 0x13, 0x07, 0x1d, 0x0b, 0x02, 0x03, 0x03, 0x03, 0x1a, 0x3,
                0x14, 0x1b, 0x1f, 0x19, 0x18};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testHashSizeDoesNotMatch() {
        NetworkParameters params = MainNetParams.get();
        byte[] payload = new byte[]{0x00, 0x06, 0x16, 0x15, 0x17, 0x16, 0x11, 0x0e, 0x1c, 0x06, 0x19, 0xa,
                0x1c, 0x00, 0xb, 0x00, 0x18, 0x05, 0x1e, 0x13, 0x07, 0x1d, 0x0b, 0x02, 0x03, 0x03, 0x03, 0x1a, 0x3,
                0x14, 0x1b, 0x1f, 0x19, 0x18};
        String plainAddress = CashAddressHelper.encodeCashAddress(params.getCashAddrPrefix(), payload);
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testInvalidChecksum() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "bitcoincash:ppk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignored) {
        }
    }

    @Test
    public void testAllUpperCaseAddress() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "BITCOINCASH:QPK4HK3WUXE2UQTQC97N8ATZRRR6R5MLECZF9SUR4H";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
        } catch (AddressFormatException ex) {
            fail("Unexpected exception: " + ex.getMessage());
        }
    }

    @Test
    public void testAllLowerCaseAddress() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "bitcoincash:qpk4hk3wuxe2uqtqc97n8atzrrr6r5mleczf9sur4h";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
        } catch (AddressFormatException ex) {
            fail("Unexpected exception: " + ex.getMessage());
        }
    }

    @Test
    public void testMixingCaseAddress() {
        NetworkParameters params = MainNetParams.get();
        String plainAddress = "bitcoincash:qPk4hk3wuxe2UQtqc97n8atzrRR6r5mlECzf9sur4H";
        try {
            cashAddressFactory.getFromFormattedAddress(params, plainAddress);
            fail("Exception expected but didn't happen");
        } catch (AddressFormatException ignore) {
        }
    }

    @Test
    public void testFromLegacyToCashAddress() {
        NetworkParameters params = MainNetParams.get();
        for (String legacy : CASH_ADDRESS_BY_LEGACY_FORMAT.keySet()) {
            Address legacyAddress = cashAddressFactory.getFromBase58(params, legacy);
            String plainCashAddress = CASH_ADDRESS_BY_LEGACY_FORMAT.get(legacy);

            assertEquals(legacyAddress.toString(), plainCashAddress);
        }
    }

    @Test
    public void testFromCashToLegacyAddress() {
        NetworkParameters params = MainNetParams.get();
        for (String legacy : CASH_ADDRESS_BY_LEGACY_FORMAT.keySet()) {
            Address cashAddress = cashAddressFactory.getFromFormattedAddress(params, CASH_ADDRESS_BY_LEGACY_FORMAT.get(legacy));

            assertEquals(cashAddress.toBase58(), legacy);
        }
    }


}
