package org.bitcoinj.pow.rule;

import org.bitcoinj.core.*;
import org.bitcoinj.pow.AbstractPowRulesChecker;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

public class RegTestRuleChecker extends AbstractPowRulesChecker {
    public RegTestRuleChecker(NetworkParameters networkParameters) {
        super(networkParameters);
    }

    public void checkRules(StoredBlock storedPrev, Block nextBlock, BlockStore blockStore,
                                    AbstractBlockChain blockChain) throws VerificationException, BlockStoreException {
        // always pass
    }
}
