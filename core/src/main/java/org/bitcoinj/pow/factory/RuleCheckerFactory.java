package org.bitcoinj.pow.factory;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.pow.AbstractRuleCheckerFactory;
import org.bitcoinj.pow.RulesPoolChecker;

public class RuleCheckerFactory extends AbstractRuleCheckerFactory {

    private AbstractRuleCheckerFactory daaRulesFactory;
    private AbstractRuleCheckerFactory edaRulesFactory;

    public static RuleCheckerFactory create(NetworkParameters parameters) {
        return new RuleCheckerFactory(parameters);
    }

    private RuleCheckerFactory(NetworkParameters parameters) {
        super(parameters);
        this.daaRulesFactory = new DAARuleCheckerFactory(parameters);
        this.edaRulesFactory = new EDARuleCheckerFactory(parameters);
    }

    @Override
    public RulesPoolChecker getRuleChecker(StoredBlock storedPrev, Block nextBlock) {
        if (isNewDaaActivated(storedPrev, networkParameters)) {
            return daaRulesFactory.getRuleChecker(storedPrev, nextBlock);
        } else {
            return edaRulesFactory.getRuleChecker(storedPrev, nextBlock);
        }
    }

    private boolean isNewDaaActivated(StoredBlock storedPrev, NetworkParameters parameters) {
        return storedPrev.getHeight() >= parameters.getDAAUpdateHeight();
    }

}
