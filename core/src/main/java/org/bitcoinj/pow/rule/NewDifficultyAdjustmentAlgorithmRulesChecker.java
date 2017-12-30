package org.bitcoinj.pow.rule;

import com.google.common.base.Preconditions;
import org.bitcoinj.core.*;
import org.bitcoinj.params.AbstractBitcoinNetParams;
import org.bitcoinj.pow.AbstractPowRulesChecker;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import java.math.BigInteger;

/**
 * The new DAA algorithm seeks to accomplish the following objectives:
 * - Adjust difficulty to hash rate to target a mean block interval of 600 seconds.
 * - Avoid sudden changes in difficulty when hash rate is fairly stable.
 * - Adjust difficulty rapidly when hash rate changes rapidly.
 * - Avoid oscillations from feedback between hash rate and difficulty.
 * - Be resilient to attacks such as timestamp manipulation.
 * <p>
 * https://www.bitcoinabc.org/november
 */
public class NewDifficultyAdjustmentAlgorithmRulesChecker extends AbstractPowRulesChecker {

    private static final int AVERAGE_BLOCKS_PER_DAY = 144;

    public NewDifficultyAdjustmentAlgorithmRulesChecker(NetworkParameters networkParameters) {
        super(networkParameters);
    }

    @Override
    public void checkRules(StoredBlock storedPrev, Block nextBlock, BlockStore blockStore, AbstractBlockChain blockChain) throws VerificationException, BlockStoreException {
        checkNextCashWorkRequired(storedPrev, nextBlock, blockStore);
    }

    /**
     * Compute the next required proof of work using a weighted average of the
     * estimated hashrate per block.
     * <p>
     * Using a weighted average ensure that the timestamp parameter cancels out in
     * most of the calculation - except for the timestamp of the first and last
     * block. Because timestamps are the least trustworthy information we have as
     * input, this ensures the algorithm is more resistant to malicious inputs.
     */
    private void checkNextCashWorkRequired(StoredBlock storedPrev, Block nextBlock, BlockStore blockStore) {
        int prevHeight = storedPrev.getHeight();
        Preconditions.checkState(prevHeight >= networkParameters.getInterval());

        try {
            StoredBlock last = GetMostSuitableBlock(storedPrev, blockStore);
            StoredBlock first = getFirst(storedPrev, blockStore);

            BigInteger nextTarget = AbstractBitcoinNetParams.ComputeTarget(first, last);
            networkParameters.verifyDifficulty(nextTarget, nextBlock);
        } catch (BlockStoreException x) {
            // We don't have enough blocks, yet
        }
    }

    /**
     * To reduce the impact of timestamp manipulation, we select the block we are
     * basing our computation on via a median of 3.
     */
    private StoredBlock GetMostSuitableBlock(StoredBlock pindex, BlockStore blockStore) throws BlockStoreException {
        /**
         * In order to avoid a block is a very skewed timestamp to have too much
         * influence, we select the median of the 3 top most blocks as a starting
         * point.
         */
        StoredBlock blocks[] = new StoredBlock[3];
        blocks[2] = pindex;
        blocks[1] = pindex.getPrev(blockStore);
        blocks[0] = blocks[1].getPrev(blockStore);

        // Sorting network.
        if (blocks[0].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[2]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[2];
            blocks[2] = temp;
        }

        if (blocks[0].getHeader().getTimeSeconds() > blocks[1].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[1]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[1];
            blocks[1] = temp;
        }

        if (blocks[1].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[1], blocks[2]);
            StoredBlock temp = blocks[1];
            blocks[1] = blocks[2];
            blocks[2] = temp;
        }

        // We should have our candidate in the middle now.
        return blocks[1];
    }

    private StoredBlock getFirst(StoredBlock storedPrev, BlockStore blockStore) throws BlockStoreException {
        StoredBlock first = storedPrev;
        for (int i = AVERAGE_BLOCKS_PER_DAY; i > 0; --i) {
            first = first.getPrev(blockStore);
            if (first == null) {
                throw new BlockStoreException("The previous block no longer exists");
            }
        }
        return GetMostSuitableBlock(first, blockStore);
    }

}
