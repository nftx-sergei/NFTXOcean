#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "primitives/transaction.h"
#include "script/script.h"
#include "chainparams.h"
#include "core_io.h"
#include "utilstrencodings.h"

 // ./komodo-test --gtest_filter=IsFinalTxTest.*
namespace IsFinalTxTest {

    CMutableTransaction BuildTransactionTemplate() {

        // A script with a single opcode that accepts the transaction (pushes true on the stack)
        CScript accepting_script = CScript() << CScriptNum(1);
        // A script with a single opcode that rejects the transaction (OP_FALSE)
        CScript rejecting_script = CScript() << OP_FALSE;

        CMutableTransaction mtx;
        mtx.vin.resize(1);
        // Mock an unspent transaction output
        mtx.vin[0].prevout.hash = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
        mtx.vin[0].prevout.n = 1;
        mtx.vin[0].scriptSig = accepting_script;
        mtx.vin[0].nSequence = std::numeric_limits<uint32_t>::max();
        mtx.vout.push_back(CTxOut(1 * COIN, rejecting_script));

        mtx.fOverwintered = true;
        mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
        mtx.nVersion = SAPLING_TX_VERSION;

        mtx.nLockTime = 0;

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
        int transaction_block_height = sapling_activation_height + 10;
        int fake_source_fund_height = transaction_block_height - 1;
        int64_t sapling_block_time = 1544835390;

        SelectParams(CBaseChainParams::MAIN);

        CMutableTransaction mtx = BuildTransactionTemplate();

        EXPECT_TRUE(IsFinalTxBitcoin(CTransaction(mtx), transaction_block_height, sapling_block_time));

    }

}