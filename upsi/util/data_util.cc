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

#include "upsi/util/data_util.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <numeric>
#include <random>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/container/btree_set.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "upsi/crypto/context.h"
#include "upsi/util/status.inc"

namespace upsi {
namespace {

static const char kAlphaNumericCharacters[] =
    "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
static const size_t kAlphaNumericSize = 62;

////////////////////////////////////////////////////////////////////////////////
// HELPER METHODS
////////////////////////////////////////////////////////////////////////////////

char* strndup_with_new(const char* the_string, size_t max_length) {
  if (the_string == nullptr) return nullptr;

  char* result = new char[max_length + 1];
  result[max_length] = '\0';  // terminate the string because strncpy might not
  return strncpy(result, the_string, max_length);
}

void SplitCSVLineWithDelimiter(char* line, char delimiter,
                               std::vector<char*>* cols) {
  char* end_of_line = line + strlen(line);
  char* end;
  char* start;

  for (; line < end_of_line; line++) {
    // Skip leading whitespace, unless said whitespace is the delimiter.
    while (std::isspace(*line) && *line != delimiter) ++line;

    if (*line == '"' && delimiter == ',') {  // Quoted value...
      start = ++line;
      end = start;
      for (; *line; line++) {
        if (*line == '"') {
          line++;
          if (*line != '"')  // [""] is an escaped ["]
            break;           // but just ["] is end of value
        }
        *end++ = *line;
      }
      // All characters after the closing quote and before the comma
      // are ignored.
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
    } else {
      start = line;
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
      // Skip all trailing whitespace, unless said whitespace is the delimiter.
      for (end = line; end > start; --end) {
        if (!std::isspace(end[-1]) || end[-1] == delimiter) break;
      }
    }
    const bool need_another_column =
        (*line == delimiter) && (line == end_of_line - 1);
    *end = '\0';
    cols->push_back(start);
    // If line was something like [paul,] (comma is the last character
    // and is not proceeded by whitespace or quote) then we are about
    // to eliminate the last column (which is empty). This would be
    // incorrect.
    if (need_another_column) cols->push_back(end);

    assert(*line == '\0' || *line == delimiter);
  }
}

void SplitCSVLineWithDelimiterForStrings(const std::string& line,
                                         char delimiter,
                                         std::vector<std::string>* cols) {
  // Unfortunately, the interface requires char* instead of const char*
  // which requires copying the string.
  char* cline = strndup_with_new(line.c_str(), line.size());
  std::vector<char*> v;
  SplitCSVLineWithDelimiter(cline, delimiter, &v);
  for (char* str : v) {
    cols->push_back(str);
  }
  delete[] cline;
}

std::vector<std::string> SplitCsvLine(const std::string& line) {
  std::vector<std::string> cols;
  SplitCSVLineWithDelimiterForStrings(line, ',', &cols);
  return cols;
}

// Escapes a string for CSV file writing. By default, this will surround each
// string with double quotes, and escape each occurrence of a double quote by
// replacing it with 2 double quotes.
std::string EscapeForCsv(absl::string_view input) {
  return absl::StrCat("\"", absl::StrReplaceAll(input, {{"\"", "\"\""}}), "\"");
}

}  // namespace


////////////////////////////////////////////////////////////////////////////////
// DATASET CLASS
////////////////////////////////////////////////////////////////////////////////

Dataset::Dataset(Context* ctx, const std::string& fn) {
    this->ctx = ctx;
    std::ifstream file(fn);
    if (!file.is_open()) {
        throw std::runtime_error("[Dataset] failed to open " + fn);
    }

    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> columns = SplitCsvLine(line);
        elements.push_back(columns[0]);
        if (columns.size() > 1) {
            values.push_back(std::stoll(columns[1]));
        }
    }

    if (values.size() > 0 && elements.size() != values.size()) {
        throw std::runtime_error(
            "[Dataset] malformed dataset file " + fn + ": "
            + std::to_string(elements.size()) + " elements vs. "
            + std::to_string(values.size()) + " values"
        );
    }

    file.close();
    if (file.is_open()) {
        throw std::runtime_error("[Dataset] failed to close " + fn);
    }
}

Status Dataset::Write(const std::string& fn) const {
    std::ofstream file(fn);
    if (!file.is_open()) {
        return InvalidArgumentError("[Dataset] failed to open " + fn);
    }

    for (size_t i = 0; i < elements.size(); i++) {
        file << EscapeForCsv(elements[i]);
        if (values.size() > 0) { file << "," << values[i]; }
        file << std::endl;
    }

    file.close();
    if (file.fail()) {
        return InternalError("[Dataset] failed to write and close " + fn);
    }

    return OkStatus();
}

void Dataset::Print() const {
    for (size_t i = 0; i < elements.size(); i++) {
        std::cout << EscapeForCsv(elements[i]);
        if (values.size() > 0) { std::cout << "," << values[i]; }
        std::cout << std::endl;
    }
}

std::vector<BigNum> Dataset::Elements() const {
    std::vector<BigNum> out;
    for (const std::string& element : elements) {
        out.push_back(ctx->CreateBigNum(std::stoull(element)));
    }
    return out;
}

std::vector<std::pair<BigNum, BigNum>> Dataset::ElementsAndValues() const {
    assert(values.size() > 0);
    std::vector<std::pair<BigNum, BigNum>> out;
    for (size_t i = 0; i < elements.size(); i++) {
        auto pair = std::make_pair(
            ctx->CreateBigNum(std::stoull(elements[i])),
            ctx->CreateBigNum(values[i])
        );
        out.push_back(pair);
    }
    return out;
}

////////////////////////////////////////////////////////////////////////////////

std::vector<Dataset> ReadDailyDatasets(Context* ctx, std::string dir, int days) {
    std::vector<Dataset> datasets;

    for (int day = 1; day <= days; day++) {
        std::cout << "[DataUtil] reading ";
        std::cout << dir + std::to_string(day) + ".csv" << std::endl;

        Dataset daily(ctx, dir + std::to_string(day) + ".csv");
        datasets.push_back(daily);
    }

    return datasets;
}

std::tuple<std::vector<Dataset>, std::vector<Dataset>, int64_t> GenerateAddOnlySets(
    Context* ctx,
    std::vector<uint32_t> sizes,
    uint32_t shared_size,
    uint32_t max_value
) {
    uint32_t total_size = std::accumulate(sizes.begin(), sizes.end(), static_cast<uint32_t>(0));
    if (shared_size > total_size) {
        throw std::runtime_error("[GenerateAddOnlySets] intersection larger than party's sets");
    }
    if (max_value > 0 && shared_size > std::numeric_limits<int64_t>::max() / max_value) {
        throw std::runtime_error(
            "[GenerateAddOnlySets] shared_size * max_value is larger than int64_t::max"
        );
    }
    std::random_device rd;
    std::mt19937 gen(rd());

    // elements shared between parties
    std::vector<std::string> intersection(shared_size);
    for (int64_t i = 0; i < shared_size; i++) {
        intersection[i] = GetRandomSetElement();
    }

    // copy shared elements, fill to total_size, and shuffle so shared aren't all at the front
    std::vector<std::string> p0_set = intersection;
    std::vector<std::string> p1_set = intersection;
    for (int64_t i = shared_size; i < total_size; i++) {
        p0_set.push_back(GetRandomSetElement());
        p1_set.push_back(GetRandomSetElement());
    }
    std::shuffle(p0_set.begin(), p0_set.end(), gen);
    std::shuffle(p1_set.begin(), p1_set.end(), gen);

    // presumably for faster lookup
    absl::btree_set<std::string> p1_btree(p1_set.begin(), p1_set.end());

    // generate associated values for p0 and keep track of the expected sum
    std::vector<int64_t> p0_values(total_size);
    int64_t sum = 0;
    for (int64_t i = 0; i < total_size; i++) {
        p0_values[i] = (
            ctx->GenerateRandLessThan(ctx->CreateBigNum(max_value)).ToIntValue().value()
        );
        if (p1_btree.count(p0_set[i]) > 0) { sum += p0_values[i]; }
    }

    size_t i = 0;
    std::vector<Dataset> p0_datasets;
    std::vector<Dataset> p1_datasets;
    for (size_t day = 0; day < sizes.size(); day++) {
        std::vector<std::string> p0_daily(sizes[day]);
        std::vector<int64_t> p0_daily_values(sizes[day]);
        std::vector<std::string> p1_daily(sizes[day]);
        for (size_t j = 0; j < sizes[day]; j++, i++) {
            p0_daily[j] = p0_set[i];
            p0_daily_values[j] = p0_values[i];
            p1_daily[j] = p1_set[i];
        }
        Dataset p0_dataset(ctx, p0_daily, p0_daily_values);
        p0_datasets.push_back(p0_dataset);

        Dataset p1_dataset(ctx, p1_daily);
        p1_datasets.push_back(p1_dataset);
    }

    return std::make_tuple(p0_datasets, p1_datasets, sum);
}

std::tuple<std::vector<Dataset>, std::vector<Dataset>, int64_t> GenerateDeletionSets(
    Context* ctx,
    std::vector<uint32_t> sizes,
    uint32_t shared_size,
    uint32_t max_value
) {
    uint32_t total_size = std::accumulate(sizes.begin(), sizes.end(), static_cast<uint32_t>(0));
    if (shared_size > total_size) {
        throw std::runtime_error("[GenerateDeletionSets] intersection larger than party's sets");
    }
    if (max_value > 0 && shared_size > std::numeric_limits<int64_t>::max() / max_value) {
        throw std::runtime_error(
            "[GenerateDeletionSets] shared_size * max_value is larger than int64_t::max"
        );
    }
    std::random_device rd;
    std::mt19937 gen(rd());

    // elements shared between parties
    std::vector<std::string> intersection(shared_size);
    for (int64_t i = 0; i < shared_size; i++) {
        intersection[i] = GetRandomSetElement();
    }

    // copy shared elements, fill to total_size, and shuffle so shared aren't all at the front
    std::vector<std::string> p0_set = intersection;
    std::vector<std::string> p1_set = intersection;
    for (int64_t i = shared_size; i < total_size; i++) {
        p0_set.push_back(GetRandomSetElement());
        p1_set.push_back(GetRandomSetElement());
    }
    std::shuffle(p0_set.begin(), p0_set.end(), gen);
    std::shuffle(p1_set.begin(), p1_set.end(), gen);

    // presumably for faster lookup
    absl::btree_set<std::string> p1_btree(p1_set.begin(), p1_set.end());

    // generate associated values for p0 and keep track of the expected sum
    std::vector<int64_t> p0_values(total_size);
    int64_t sum = 0;
    for (int64_t i = 0; i < total_size; i++) {
        p0_values[i] = (
            ctx->GenerateRandBetween(
                ctx->One(),
                ctx->CreateBigNum(max_value)
            ).ToIntValue().value()
        );
        if (p1_btree.count(p0_set[i]) > 0) { sum += p0_values[i]; }
    }

    size_t i = 0;
    std::vector<Dataset> p0_datasets;
    std::vector<Dataset> p1_datasets;
    for (size_t day = 0; day < sizes.size(); day++) {
        std::vector<std::string> p0_daily(sizes[day]);
        std::vector<int64_t> p0_daily_values(sizes[day]);
        std::vector<std::string> p1_daily(sizes[day]);
        std::vector<int64_t> p1_daily_values(sizes[day]);
        for (size_t j = 0; j < sizes[day]; j++, i++) {
            p0_daily[j] = p0_set[i];
            p0_daily_values[j] = p0_values[i];
            p1_daily[j] = p1_set[i];

            // TODO (max): this needs to be much more sophisticated
            p1_daily_values[j] = 1;
        }
        Dataset p0_dataset(ctx, p0_daily, p0_daily_values);
        p0_datasets.push_back(p0_dataset);

        Dataset p1_dataset(ctx, p1_daily, p1_daily_values);
        p1_datasets.push_back(p1_dataset);
    }

    return std::make_tuple(p0_datasets, p1_datasets, sum);
}

}  // namespace upsi
