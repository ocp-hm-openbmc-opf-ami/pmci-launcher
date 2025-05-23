/*
// Copyright (c) 2024 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <memory>
#include <sdbusplus/asio/connection.hpp>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

using ConfigurationField = std::variant<uint64_t, std::vector<uint64_t>,
                                        std::string, std::vector<std::string>>;
using ConfigurationName = std::string;
using ConfigurationMap =
    std::unordered_map<ConfigurationName, ConfigurationField>;

class HubConfiguration
{
  public:
    HubConfiguration(std::shared_ptr<sdbusplus::asio::connection> conn) :
        conn(conn)
    {
        i3cHubConfigs = getAllI3CHubConfigs();
    };
    ~HubConfiguration()
    {
        i3cHubConfigs.clear();
    };

    ConfigurationMap findI3CHubConfig(const uint8_t hubID,
                                      const uint8_t topMostRootBus);
    std::string getHubName(const ConfigurationMap& config);
    std::vector<std::string> getChannelNames(const ConfigurationMap& config);
    std::vector<uint8_t> getBusList();

  private:
    std::vector<std::string> getConfigurationPaths();
    ConfigurationMap getConfigurationMap(const std::string& configurationPath);
    std::vector<ConfigurationMap> getAllI3CHubConfigs();

    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::vector<ConfigurationMap> i3cHubConfigs;
};
