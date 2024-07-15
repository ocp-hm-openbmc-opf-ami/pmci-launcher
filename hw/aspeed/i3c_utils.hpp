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

#include <cstdint>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <set>
#include <string>
#include <unordered_map>

void readFromFile(const std::string& filePath, std::string& data);

struct HubInfo
{
    uint8_t deviceID;
    int rootBus;
    std::string rootBusName;
    std::string targetPortConfig;
    uint8_t topMostRootBus;
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

namespace hw
{
namespace aspeed
{

// TODO: Move this to entity-manager
static const std::unordered_map<uint8_t, std::string> i3cBusMap{
    {0, "1e7a2000.i3c0"}, {1, "1e7a3000.i3c1"}, {2, "1e7a4000.i3c2"},
    {3, "1e7a5000.i3c3"}, {4, "1e7a6000.i3c4"}, {5, "1e7a7000.i3c5"}};

uint8_t readHubID(const std::string& hubPath);
std::string readTPConf(const std::string& hubPath);
int findRootBusNo(const std::string& hubPath);
std::string readRootBusName(const std::string& hubPath);
std::set<std::string> findI3CHubs(const uint8_t topMostRootI3CBusNum);
void rescanI3CRootBus(const uint8_t rootI3CBusNum);
std::string getI3CRootBusPath(const uint8_t topMostRootI3CBusNum);
void rescanI3CBus(const std::string& busPath);
} // namespace aspeed
} // namespace hw
