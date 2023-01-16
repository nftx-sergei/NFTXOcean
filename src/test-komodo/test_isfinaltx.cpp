#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "primitives/transaction.h"
#include "script/script.h"
#include "chainparams.h"
#include "core_io.h"
#include "utilstrencodings.h"

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

}