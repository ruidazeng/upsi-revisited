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

#include "updatable_private_set_intersection/util/ec_key_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>

#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/ec_group.h"
#include "updatable_private_set_intersection/crypto/ec_key.pb.h"
#include "updatable_private_set_intersection/crypto/openssl.inc"
#include "updatable_private_set_intersection/util/proto_util.h"
#include "updatable_private_set_intersection/util/status_testing.inc"

namespace updatable_private_set_intersection::ec_key_util {
namespace {
using ::testing::Test;

const int kTestCurveId = NID_X9_62_prime256v1;

TEST(EcKeyUtilTest, GenerateKey) {
  std::filesystem::path temp_dir(::testing::TempDir());
  std::string key_filename = (temp_dir / "ec.key").string();

  // Generate an EC key.
  ASSERT_OK(GenerateEcKey(kTestCurveId, key_filename));
  ASSERT_TRUE(std::filesystem::exists(key_filename));

  // Read the key and verify it is valid.
  Context context;
  ASSERT_OK_AND_ASSIGN(auto ec_group, ECGroup::Create(kTestCurveId, &context));
  ASSERT_OK_AND_ASSIGN(auto key_proto,
                       ProtoUtils::ReadProtoFromFile<EcKeyProto>(key_filename));
  ASSERT_OK_AND_ASSIGN(auto key,
                       DeserializeEcKey(&context, kTestCurveId, key_proto));
  EXPECT_OK(ec_group.CheckPrivateKey(key));
}
}  // namespace
}  // namespace updatable_private_set_intersection::ec_key_util
