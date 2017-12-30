package org.bitcoinj.pow;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;

public abstract class AbstractRuleCheckerFactory {

    protected NetworkParameters networkParameters;

    public AbstractRuleCheckerFactory(NetworkParameters networkParameters) {
        this.networkParameters = networkParameters;
    }

    public abstract RulesPoolChecker getRuleChecker(StoredBlock storedPrev, Block nextBlock);

    protected boolean isTestNet() {
        return NetworkParameters.ID_TESTNET.equals(networkParameters.getId());
    }

}
