package org.bitcoinj.pow.factory;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.pow.AbstractRuleCheckerFactory;
import org.bitcoinj.pow.RulesPoolChecker;
import org.bitcoinj.pow.rule.MinimalDifficultyRuleChecker;
import org.bitcoinj.pow.rule.NewDifficultyAdjustmentAlgorithmRulesChecker;

public class DAARuleCheckerFactory extends AbstractRuleCheckerFactory {

    public DAARuleCheckerFactory(NetworkParameters parameters) {
        super(parameters);
    }

    @Override
    public RulesPoolChecker getRuleChecker(StoredBlock storedPrev, Block nextBlock) {
        RulesPoolChecker rulesChecker = new RulesPoolChecker(networkParameters);
        if (isTestNet() && TestNet3Params.isValidTestnetDateBlock(nextBlock)) {
            rulesChecker.addRule(new MinimalDifficultyRuleChecker(networkParameters));
        } else {
            rulesChecker.addRule(new NewDifficultyAdjustmentAlgorithmRulesChecker(networkParameters));
        }
        return rulesChecker;
    }

}
