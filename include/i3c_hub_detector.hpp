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

#pragma once

#include <cstdint>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <set>
#include <string>
#include <unordered_map>

struct HubInfo
{
    uint8_t deviceID;
    int bus;
    std::string busName;
    std::string targetPortConfig;
    uint8_t topMostRootBus;
    std::string name;
    std::vector<std::string> activeTargetPortList;
};

extern std::unordered_map<
    std::string /*Hub path*/,
    std::pair<HubInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    hubList;

HubInfo getHubInfo(const std::string& hubPath, uint8_t topMostRootBusNo);
std::string generateObjectPath(const std::string& hubPath);
void addHubInterface(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& objectPath, const std::string& hubPath,
    const HubInfo& hubInfo);
void checkForHubChanges(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer);
void rescanI3CBusses();
void pollI3CHubChanges(
    std::shared_ptr<boost::asio::io_context> ioc,
    std::shared_ptr<sdbusplus::asio::object_server> objectServer);
