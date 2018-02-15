package org.bitcoinj.core;

/**
 * Created by Hash Engineering on 1/19/2018.
 */
public class CashAddress extends Address {

    public enum CashAddressType {
        PubKey(0),
        Script(1);

        private int value;

        CashAddressType(int value) {
            this.value = value;
        }

        byte getValue() {
            return (byte) value;
        }
    }

    private CashAddressType addressType;

    static int getLegacyVersion(NetworkParameters params, CashAddressType type) {
        switch (type) {
            case PubKey:
                return params.getAddressHeader();
            case Script:
                return params.getP2SHHeader();
        }
        throw new AddressFormatException("Invalid Cash address type: " + type.value);
    }

    static CashAddressType getType(NetworkParameters params, int version) {
        if (version == params.getAddressHeader()) {
            return CashAddressType.PubKey;
        } else if (version == params.getP2SHHeader()) {
            return CashAddressType.Script;
        }
        throw new AddressFormatException("Invalid Cash address version: " + version);
    }

    CashAddress(NetworkParameters params, CashAddressType addressType, byte[] hash) {
        super(params, getLegacyVersion(params, addressType), hash);
        this.addressType = addressType;
    }

    CashAddress(NetworkParameters params, int version, byte[] hash160) {
        super(params, version, hash160);
        this.addressType = getType(params, version);
    }

    public boolean isP2SHAddress() {
        return addressType == CashAddressType.Script;
    }

    public CashAddressType getAddressType() {
        return addressType;
    }

    public String toString() {
        return CashAddressHelper.encodeCashAddress(getParameters().getCashAddrPrefix(),
                CashAddressHelper.packAddressData(getHash160(), addressType.getValue()));
    }

    @Override
    public Address clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
