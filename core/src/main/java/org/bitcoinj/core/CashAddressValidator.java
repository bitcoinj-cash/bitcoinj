package org.bitcoinj.core;

public class CashAddressValidator {

    public static CashAddressValidator create() {
        return new CashAddressValidator();
    }

    public void checkValidPrefix(NetworkParameters params, String prefix) throws AddressFormatException {
        if (!prefix.equals(params.getCashAddrPrefix())) {
            throw new AddressFormatException("Invalid prefix for network: " +
                    prefix + " != " + params.getCashAddrPrefix() + " (expected)");
        }
    }

    public void checkNonEmptyPayload(byte[] payload) throws AddressFormatException {
        if (payload.length == 0) {
            throw new AddressFormatException("No payload");
        }
    }

    public void checkAllowedPadding(byte extraBits) throws AddressFormatException {
        if (extraBits >= 5) {
            throw new AddressFormatException("More than allowed padding");
        }
    }

    public void checkNonZeroPadding(byte last, byte mask) {
        if ((last & mask) != 0) {
            throw new AddressFormatException("Nonzero bytes ");
        }
    }

    public void checkFirstBitIsZero(byte versionByte) {
        if ((versionByte & 0x80) != 0) {
            throw new AddressFormatException("First bit is reserved");
        }
    }

    public void checkDataLength(byte[] data, int hashSize) {
        if (data.length != hashSize + 1) {
            throw new AddressFormatException("Data length " + data.length + " != hash size " + hashSize);
        }
    }

}
