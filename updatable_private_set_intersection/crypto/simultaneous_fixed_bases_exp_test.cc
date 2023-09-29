/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "updatable_private_set_intersection/crypto/simultaneous_fixed_bases_exp.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

#include "updatable_private_set_intersection/crypto/big_num.h"
#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/ec_group.h"
#include "updatable_private_set_intersection/crypto/ec_point.h"
#include "updatable_private_set_intersection/util/status.inc"
#include "updatable_private_set_intersection/util/status_testing.inc"

namespace updatable_private_set_intersection {
namespace {

using ::testing::HasSubstr;
using testing::StatusIs;

const uint64_t P = 35879;
const uint64_t Q = 63587;
const uint64_t N = P * Q;
const uint64_t S = 2;

using ZnExp = SimultaneousFixedBasesExp<ZnElement, ZnContext>;

const int kTestCurveId = NID_secp224r1;

class SimultaneousFixedBasesExpTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(
        auto ec_group,
        updatable_private_set_intersection::ECGroup::Create(kTestCurveId, &ctx_));
    ec_group_ = std::make_unique<updatable_private_set_intersection::ECGroup>(
        std::move(ec_group));
  }

  updatable_private_set_intersection::Context ctx_;
  std::unique_ptr<updatable_private_set_intersection::ECGroup> ec_group_;
};

TEST_F(SimultaneousFixedBasesExpTest, ZnMultipleExp) {
  updatable_private_set_intersection::BigNum n = ctx_.CreateBigNum(P);  // Prime modulus.
  auto base1 = ctx_.GenerateRandLessThan(n);
  auto base2 = ctx_.GenerateRandLessThan(n);
  updatable_private_set_intersection::BigNum exponent1 = ctx_.CreateBigNum(29);
  updatable_private_set_intersection::BigNum exponent2 = ctx_.CreateBigNum(2245);

  std::vector<ZnElement> bases;
  bases.push_back(base1);
  bases.push_back(base2);
  std::unique_ptr<ZnContext> zn_context(new ZnContext({n}));

  ASSERT_OK_AND_ASSIGN(
      auto exp, ZnExp::Create(bases, ctx_.One(), 2, std::move(zn_context)));

  std::vector<updatable_private_set_intersection::BigNum> exponents;
  exponents.push_back(exponent1);
  exponents.push_back(exponent2);
  ASSERT_OK_AND_ASSIGN(auto result, exp->SimultaneousExp(exponents));

  auto result1 = base1.ModExp(exponent1, n);
  auto result2 = base2.ModExp(exponent2, n);
  auto expected = result1.ModMul(result2, n);

  EXPECT_EQ(result, expected);
}

TEST_F(SimultaneousFixedBasesExpTest, FailsWhenNumExponentsNotEqualNumBases) {
  updatable_private_set_intersection::BigNum n = ctx_.CreateBigNum(P);  // Prime modulus.
  auto base1 = ctx_.GenerateRandLessThan(n);
  auto base2 = ctx_.GenerateRandLessThan(n);
  updatable_private_set_intersection::BigNum exponent1 = ctx_.CreateBigNum(29);
  updatable_private_set_intersection::BigNum exponent2 = ctx_.CreateBigNum(2245);

  std::vector<ZnElement> bases;
  bases.push_back(base1);
  std::unique_ptr<ZnContext> zn_context(new ZnContext({n}));

  ASSERT_OK_AND_ASSIGN(
      auto exp, ZnExp::Create(bases, ctx_.One(), 1, std::move(zn_context)));

  std::vector<updatable_private_set_intersection::BigNum> exponents;
  exponents.push_back(exponent1);
  exponents.push_back(exponent2);

  EXPECT_THAT(exp->SimultaneousExp(exponents),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Number of exponents")));
}

TEST_F(SimultaneousFixedBasesExpTest, FailsWhenNumSimultaneousLargerThanBases) {
  updatable_private_set_intersection::BigNum n = ctx_.CreateBigNum(P);  // Prime modulus.
  auto base1 = ctx_.GenerateRandLessThan(n);
  auto base2 = ctx_.GenerateRandLessThan(n);
  updatable_private_set_intersection::BigNum exponent1 = ctx_.CreateBigNum(29);
  updatable_private_set_intersection::BigNum exponent2 = ctx_.CreateBigNum(2245);

  std::vector<ZnElement> bases;
  bases.push_back(base1);
  std::unique_ptr<ZnContext> zn_context(new ZnContext({n}));

  EXPECT_THAT(ZnExp::Create(bases, ctx_.One(), 2, std::move(zn_context)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("num_simultaneous parameter")));
}

TEST_F(SimultaneousFixedBasesExpTest, FailsWhenNumSimultaneousZero) {
  updatable_private_set_intersection::BigNum n = ctx_.CreateBigNum(P);  // Prime modulus.
  auto base1 = ctx_.GenerateRandLessThan(n);
  auto base2 = ctx_.GenerateRandLessThan(n);
  updatable_private_set_intersection::BigNum exponent1 = ctx_.CreateBigNum(29);
  updatable_private_set_intersection::BigNum exponent2 = ctx_.CreateBigNum(2245);

  std::vector<ZnElement> bases;
  bases.push_back(base1);
  bases.push_back(base2);
  std::unique_ptr<ZnContext> zn_context(new ZnContext({n}));

  EXPECT_THAT(
      ZnExp::Create(bases, ctx_.One(), 0, std::move(zn_context)),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("positive")));
}

}  // namespace
}  // namespace updatable_private_set_intersection
