#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "primitives/transaction.h"
#include "script/script.h"
#include "chainparams.h"
#include "core_io.h"
#include "utilstrencodings.h"
#include "komodo_hardfork.h"
#include "assetchain.h"
#include "main.h" // isFinalTx

 // ./komodo-test --gtest_filter=IsFinalTxTest.*
namespace IsFinalTxTest {

    const uint32_t SEQUENCE_FINAL = std::numeric_limits<uint32_t>::max();
    const uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    uint256 CreateFakeTxId(uint8_t n) {
        arith_uint256 number = 0;
        for (int i = 0; i < 32; i++) {
            arith_uint256 mask(n);
            mask = mask << (i * 8);
            number = number | mask;
        }
        return ArithToUint256(number);
    }

    void DeleteFakeChain() {
        chainActive.SetTip(nullptr); // this will clear chainActive.vChain
        for (BlockMap::value_type& entry : mapBlockIndex) {
            delete entry.second;
        }
        mapBlockIndex.clear();
    }

    void CreateFakeChain(int nDesiredHeight, bool fClearChain = true) {

        /* inside komodo_hardfork_active we have chainActive.Height() call to determine current
           height for KMD, so we should emulate the chain */

        uint256 zero; zero.SetNull();

        if (fClearChain) {
            DeleteFakeChain();
        }

        int maxHeight = chainActive.Height();
        for (int i = 0; i < (nDesiredHeight - maxHeight); ++i) {
            CBlock block;
            block.hashPrevBlock = chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : zero;

            uint256 hash = block.GetHash();
            // std::cerr << i << ": " << hash.ToString() << std::endl;

            // kind of AddToBlockIndex emulation
            CBlockIndex* pindexNew = new CBlockIndex(block); // Construct new block index object
            BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
            pindexNew->phashBlock = &((*mi).first);
            pindexNew->nHeight = i + maxHeight + 1;
            pindexNew->pprev = chainActive.Tip();
            mi->second = pindexNew;

            chainActive.SetTip(pindexNew);
        }

        // CBlockIndex *pindex = nullptr;
        // for (int i = 0; i < nDesiredHeight; ++i) {
        //     pindex = chainActive[i];
        //     if (pindex) {
        //         std::cerr << pindex->nHeight << ": " << pindex->GetBlockHash().ToString() << " (prev:" << (pindex->pprev ? pindex->pprev->GetBlockHash().ToString() : zero.ToString()) << ")" << std::endl;
        //     }
        // }
    }

    /// @brief Create CMutableTransaction with the following params:
    /// @param nLockTimeIn - given nLockTime
    /// @param nCountFinal - number of "final" inputs, with nSequence == SEQUENCE_FINAL (0xffffffff)
    /// @param nCountNonFinal - number of "non-final" inputs, with Sequence != SEQUENCE_FINAL
    /// @return CMutableTransaction

    CMutableTransaction BuildTransactionTemplate(uint32_t nLockTimeIn, uint8_t nCountFinal, uint8_t nCountNonFinal, uint32_t nSequenceNonFinalDefault = MAX_SEQUENCE_NONFINAL) {

        // A script with a single opcode that accepts the transaction (pushes true on the stack)
        CScript accepting_script = CScript() << CScriptNum(1);
        // A script with a single opcode that rejects the transaction (OP_FALSE)
        CScript rejecting_script = CScript() << OP_FALSE;

        CMutableTransaction mtx;

        size_t vin_number = 0;

        // adding "final" vins
        for (uint8_t idx = 0; idx < nCountFinal; ++idx) {
            vin_number++;
            mtx.vin.push_back(
                CTxIn(COutPoint(CreateFakeTxId(vin_number), vin_number),
                    accepting_script,
                    std::numeric_limits<uint32_t>::max())
            );
        }

        // adding "non-final" vins
        for (uint8_t idx = 0; idx < nCountNonFinal; ++idx) {
            vin_number++;
            mtx.vin.push_back(
                CTxIn(COutPoint(CreateFakeTxId(vin_number), vin_number),
                    accepting_script,
                    nSequenceNonFinalDefault)
            );
        }

        mtx.vout.push_back(CTxOut(1 * COIN, rejecting_script));

        mtx.fOverwintered = true;
        mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
        mtx.nVersion = SAPLING_TX_VERSION;

        mtx.nLockTime = nLockTimeIn;

        // static size_t tx_count;
        // std::cerr << ++tx_count << ". " << CTransaction(mtx).ToString() << std::endl;

        return mtx;
    }

    /* original Bitcoin implementation */
    bool IsFinalTxBitcoin(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
    {
        if (tx.nLockTime == 0)
            return true;
        if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
            return true;

        // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
        // transaction is still considered final if all inputs' nSequence ==
        // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
        //
        // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
        // also check that the spending input's nSequence != SEQUENCE_FINAL,
        // ensuring that an unsatisfied nLockTime value will actually cause
        // IsFinalTx() to return false here:
        for (const auto& txin : tx.vin) {
            if (!(txin.nSequence == std::numeric_limits<uint32_t>::max()))
                return false;
        }
        return true;
    }

    TEST(IsFinalTxTest, isfinaltxbitcoin) {

        int sapling_activation_height = 1140409;
        int64_t sapling_block_time = 1544835390;

        int tbh = sapling_activation_height + 10;
        int64_t tbt = sapling_block_time + 1;

        SelectParams(CBaseChainParams::MAIN);

        // transaction with nLockTime = 0 considered as Final
        EXPECT_TRUE(IsFinalTxBitcoin(CTransaction(BuildTransactionTemplate(0, 1, 1)), tbh, tbt));
        // transaction with nLockTime < block height considered as Final
        EXPECT_TRUE(IsFinalTxBitcoin(CTransaction(BuildTransactionTemplate(tbh - 1, 1, 1)), tbh, tbt));
        // transaction with nLockTime < sapling_block_time considered as Final
        EXPECT_TRUE(IsFinalTxBitcoin(CTransaction(BuildTransactionTemplate(tbt - 1, 1, 1)), tbh, tbt));
        // nLockTIme > tbh - non-Final
        EXPECT_FALSE(IsFinalTxBitcoin(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 1)), tbh, tbt));
        // transaction with all vins have SEQUENCE_FINAL is final
        EXPECT_TRUE(IsFinalTxBitcoin(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 0)), tbh, tbt));
    }


    TEST(IsFinalTxTest, isfinaltxkomodo) {

        int sapling_activation_height = 1140409;
        int64_t sapling_block_time = 1544835390;

        int tbh = nDecemberHardforkHeight;
        int64_t tbt = nStakedDecemberHardforkTimestamp;

        CreateFakeChain(tbh, true);

        /* common cases, when nLockTime = 0 or nLockTime < nBlockHeight | nBlockTime */
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(0, 1, 1, 0)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh - 1, 1, 1, 0)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt - 1, 1, 1, 0)), tbh, tbt));

        /* first we will do the test for before December 2019 hardfork values */

        /* before hardfork tx with vin with nSequence == 0xfffffffe treated as final if
           nLockTime > (nBlockTime | nBlockHeight), such vins considered same way as vins with
           Sequence == 0xffffffff. all other sequences in vins should be considered same way as in bitcoin,
           if vin have "non-final" sequence and nLockTime >= (nBlockTime | nBlockHeight) it should be
           considered as non-final.
        */

        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));

        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));

        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 1, 777)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 1, 777)), tbh, tbt));

        // all vins have SEQUENCE_FINAL, so it's final
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 0)), tbh, tbt));

        /* after let's "jump" into hardfork times, we will increase tbh and tbt to match HF times, as
           komodo_hardfork_active using chainActive.Height() we should create fake chain */
        tbh++; tbt++;
        CreateFakeChain(tbh, false); // this will just update the fake chain to desired height, not re-create from scratch

        /* after hardfork we consider nSequence == 0xfffffffe as final if nLockTime <= (nBlockTime | nBlockHeight) */
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh - 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt - 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));

        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));

        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 1, MAX_SEQUENCE_NONFINAL)), tbh, tbt));

        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh - 1 , 1, 1, 777)), tbh, tbt));
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt - 1, 1, 1, 777)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh, 1, 1, 777)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt, 1, 1, 777)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbh + 1, 1, 1, 777)), tbh, tbt));
        EXPECT_FALSE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 1, 777)), tbh, tbt));

        // all vins have SEQUENCE_FINAL, so it's final
        EXPECT_TRUE(IsFinalTx(CTransaction(BuildTransactionTemplate(tbt + 1, 1, 0)), tbh, tbt));

        DeleteFakeChain();

        EXPECT_EQ(mapBlockIndex.size(), 0);
        EXPECT_EQ(chainActive.Height(), -1);
    }
}