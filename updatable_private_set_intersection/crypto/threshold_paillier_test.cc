#include "updatable_private_set_intersection/crypto/threshold_paillier.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "updatable_private_set_intersection/util/status_testing.inc"

namespace updatable_private_set_intersection {
namespace {
using ::testing::Eq;
using ::testing::HasSubstr;
using testing::IsOkAndHolds;
using testing::StatusIs;
using ::testing::TestWithParam;

const int32_t modulus_length    = 1536;
const int32_t statistical_param = 100;

/**
 * generating the keys does not fail
 */
TEST(ThresholdPaillierTest, TestGeneratePublicKey) {
    Context ctx;
    ASSERT_OK(GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param));
}


/**
 * generate keys, party one encrypts a message and partially decrypts,
 * and party two fully decrypts; decrypted value should match the message
 */
TEST(ThresholdPaillierTest, TestDecryptionParty112) {
    Context ctx;
    ASSERT_OK_AND_ASSIGN(
        auto keys, GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param)
    );

    ThresholdPaillier party_one(&ctx, std::get<0>(keys));
    ThresholdPaillier party_two(&ctx, std::get<1>(keys));

    BigNum message = ctx.GenerateRandLessThan(std::get<0>(keys).n);

    ASSERT_OK_AND_ASSIGN(
        BigNum ciphertext,
        party_one.Encrypt(message)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum partial,
        party_one.PartialDecrypt(ciphertext)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum decrypted,
        party_two.Decrypt(ciphertext, partial)
    );

    EXPECT_EQ(message, decrypted);
}

/**
 * generate keys, party two encrypts a message and partially decrypts,
 * and party one fully decrypts; decrypted value should match the message
 */
TEST(ThresholdPaillierTest, TestDecryptionParty221) {
    Context ctx;
    ASSERT_OK_AND_ASSIGN(
        auto keys, GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param)
    );

    ThresholdPaillier party_one(&ctx, std::get<0>(keys));
    ThresholdPaillier party_two(&ctx, std::get<1>(keys));

    BigNum message = ctx.GenerateRandLessThan(std::get<0>(keys).n);

    ASSERT_OK_AND_ASSIGN(
        BigNum ciphertext,
        party_two.Encrypt(message)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum partial,
        party_two.PartialDecrypt(ciphertext)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum decrypted,
        party_one.Decrypt(ciphertext, partial)
    );

    EXPECT_EQ(message, decrypted);
}

/**
 * generate keys, party two encrypts a message, party two partially decrypts,
 * and then party one fully decrypts; decrypted value should match the message
 */
TEST(ThresholdPaillierTest, TestDecryptionParty121) {
    Context ctx;
    ASSERT_OK_AND_ASSIGN(
        auto keys, GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param)
    );

    ThresholdPaillier party_one(&ctx, std::get<0>(keys));
    ThresholdPaillier party_two(&ctx, std::get<1>(keys));

    BigNum message = ctx.GenerateRandLessThan(std::get<0>(keys).n);

    ASSERT_OK_AND_ASSIGN(
        BigNum ciphertext,
        party_one.Encrypt(message)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum partial,
        party_two.PartialDecrypt(ciphertext)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum decrypted,
        party_one.Decrypt(ciphertext, partial)
    );

    EXPECT_EQ(message, decrypted);
}

/**
 * generate keys, party two encrypts a message, party two partially decrypts,
 * and then party one fully decrypts; decrypted value should match the message
 */
TEST(ThresholdPaillierTest, TestDecryptionParty212) {
    Context ctx;
    ASSERT_OK_AND_ASSIGN(
        auto keys, GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param)
    );

    ThresholdPaillier party_one(&ctx, std::get<0>(keys));
    ThresholdPaillier party_two(&ctx, std::get<1>(keys));

    BigNum message = ctx.GenerateRandLessThan(std::get<0>(keys).n);

    ASSERT_OK_AND_ASSIGN(
        BigNum ciphertext,
        party_two.Encrypt(message)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum partial,
        party_one.PartialDecrypt(ciphertext)
    );

    ASSERT_OK_AND_ASSIGN(
        BigNum decrypted,
        party_two.Decrypt(ciphertext, partial)
    );

    EXPECT_EQ(message, decrypted);
}

}
}
