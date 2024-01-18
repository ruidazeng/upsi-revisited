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
            values[i] < 0? ctx->Zero() - ctx->CreateBigNum(-values[i]) : ctx->CreateBigNum(values[i])
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

////////////////////////////////////////////////////////////////////////////////
// MOCK ADDITION DATA HELPERS
////////////////////////////////////////////////////////////////////////////////

std::tuple<
    Dataset, std::vector<Dataset>,
    Dataset, std::vector<Dataset>,
    int64_t
> GenerateAddOnlySets(
    Context* ctx,
    uint32_t days,
    uint32_t daily_size,
    uint32_t start_size,
    uint32_t shared_size,
    uint32_t max_value
) {
    uint32_t total_size = start_size + (days * daily_size);

    if (shared_size > total_size) {
        throw std::runtime_error(
            "[DataUtil] intersection larger than party's sets : "
            + std::to_string(shared_size) + " vs. " + std::to_string(total_size)
        );
    } else if (max_value > 0 && shared_size > std::numeric_limits<int64_t>::max() / max_value) {
        throw std::runtime_error(
            "[DataUtil] shared_size * max_value is larger than int64_t::max"
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
    Dataset p0_tree(ctx), p1_tree(ctx);
    for (; i < start_size; i++) {
        p0_tree.elements.push_back(p0_set[i]);
        p1_tree.elements.push_back(p1_set[i]);
        p0_tree.values.push_back(p0_values[i]);
    }

    std::vector<Dataset> p0_days, p1_days;
    for (uint32_t day = 0; day < days; day++) {
        Dataset p0_daily(ctx), p1_daily(ctx);
        for (uint32_t j = 0; j < daily_size; j++, i++) {
            p0_daily.elements.push_back(p0_set[i]);
            p1_daily.elements.push_back(p1_set[i]);
            p0_daily.values.push_back(p0_values[i]);
        }
        p0_days.push_back(p0_daily);
        p1_days.push_back(p1_daily);
    }

    return std::make_tuple(p0_tree, p0_days, p1_tree, p1_days, sum);
}

////////////////////////////////////////////////////////////////////////////////
// MOCK DELETION DATA HELPERS
////////////////////////////////////////////////////////////////////////////////

namespace {

std::pair<std::string, int64_t> sample(std::map<std::string, int64_t>& map) {
    if (map.empty()) { throw std::runtime_error("[DataUtil] sampling empty set"); };
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, map.size() - 1);

    auto it = map.begin();
    std::advance(it, dis(gen));
    std::pair<std::string, int64_t> rs = *it;
    map.erase(it);
    return rs;
}

// generate some days
std::vector<Dataset> GenerateDeletionDays(
    Context* ctx,
    uint32_t daily_size,
    uint32_t daily_del,
    uint32_t total_size,
    std::map<std::string, int64_t>& universe,
    std::map<std::string, int64_t>& current
) {
    std::vector<Dataset> datasets;
    size_t ops = 0;
    for (uint32_t day = 0; day < total_size / daily_size; day++) {
        Dataset daily(ctx);

        uint32_t i = 0;
        // deletions if they are possible
        for (; i < daily_del && !current.empty(); i++, ops++) {
            auto element = sample(current);
            daily.elements.push_back(element.first);
            daily.values.push_back(-element.second);
        }

        // additions otherwise
        for (; i < daily_size; i++, ops++) {
            auto element = sample(universe);
            daily.elements.push_back(element.first);
            daily.values.push_back(element.second);
            current[element.first] = element.second;
        }
        datasets.push_back(daily);
    }

    // in case total_size < daily_size, makes sure there is first day
    if (datasets.empty()) {
        Dataset day(ctx);
        datasets.push_back(day);
    }

    // if the start_size isn't a multiple of daily_size, add extra additions to the first day to
    // get to the desired start_size
    for (; ops < total_size; ops++) {
        auto element = sample(universe);
        datasets[0].elements.push_back(element.first);
        datasets[0].values.push_back(element.second);
        current[element.first] = element.second;
    }
    return datasets;
}

}  // namespace

std::tuple<
    Dataset, std::vector<Dataset>,
    Dataset, std::vector<Dataset>,
    int64_t
> GenerateDeletionSets(
    Context* ctx,
    uint32_t days,
    uint32_t daily_size,
    uint32_t start_size,
    uint32_t max_value,
    Functionality func
) {
    uint32_t total_size = start_size + (days * daily_size);
    BigNum max_value_bn = ctx->CreateBigNum(max_value);

    // at most 1/4 of the operations per day are deletions
    uint32_t daily_del = daily_size / 4;

    std::map<std::string, int64_t> p0_universe;
    std::map<std::string, int64_t> p1_universe;

    uint64_t i = 0;

    // shared elements
    for (; i < total_size / 3; i++) {
        std::string element = GetRandomSetElement();
        if (func == Functionality::CA) {
            p0_universe[element] = 1;
        } else if (func == Functionality::SUM) {
            p0_universe[element] = ctx->GenerateRandBetween(
                ctx->One(), max_value_bn
            ).ToIntValue().value();
        } else {
            throw std::runtime_error("[DataUtil] incorrect functionality provided");
        }
        p1_universe[element] = 1;
    }

    // different elements
    for (; i < total_size; i++) {
        if (func == Functionality::CA) {
            p0_universe[GetRandomSetElement()] = 1;
        } else if (func == Functionality::SUM) {
            p0_universe[GetRandomSetElement()] = ctx->GenerateRandBetween(
                ctx->One(), max_value_bn
            ).ToIntValue().value();
        } else {
            throw std::runtime_error("[DataUtil] incorrect functionality provided");
        }
        p1_universe[GetRandomSetElement()] = 1;
    }

    std::map<std::string, int64_t> p0_endset, p1_endset;

    Dataset p0_tree(ctx), p1_tree(ctx);
    for (size_t j = 0; j < start_size; j++) {
        auto p0_element = sample(p0_universe);
        p0_tree.elements.push_back(p0_element.first);
        p0_tree.values.push_back(p0_element.second);
        p0_endset[p0_element.first] = p0_element.second;

        auto p1_element = sample(p1_universe);
        p1_tree.elements.push_back(p1_element.first);
        p1_tree.values.push_back(p1_element.second);
        p1_endset[p1_element.first] = p1_element.second;
    }

    uint64_t initial_sum = 0;
    for (const auto& element : p0_endset) {
        if (p1_endset.find(element.first) != p1_endset.end()) {
            initial_sum += element.second;
        }
    }

    // generate daily data sets that will be put into the tree
    std::vector<Dataset> p0_days = GenerateDeletionDays(
        ctx, daily_size, daily_del, daily_size * days, p0_universe, p0_endset
    );
    std::vector<Dataset> p1_days = GenerateDeletionDays(
        ctx, daily_size, daily_del, daily_size * days, p1_universe, p1_endset
    );

    uint64_t sum = 0;
    for (const auto& element : p0_endset) {
        if (p1_endset.find(element.first) != p1_endset.end()) {
            sum += element.second;
        }
    }

    return std::make_tuple(p0_tree, p0_days, p1_tree, p1_days, sum - initial_sum);
}

}  // namespace upsi
