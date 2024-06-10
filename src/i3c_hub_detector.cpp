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

#include "i3c_utils.hpp"

#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <filesystem>
#include <fstream>
#include <list>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

const std::string hubBaseObjectPath = "/xyz/openbmc_project/I3CHub";
const static constexpr char* hubInterfaceName = "xyz.openbmc_project.I3C.Hub";

// Use the list of BHS platform for now.
// TODO: get this from entity-manager or scan for all root busses, depending on
// future use cases.
const std::vector<uint8_t> interestedI3CRootBusList = {2 /*I3C_MNG*/,
                                                       5 /*I3C_PCIe*/};

struct HubInfo
{
    uint8_t deviceID;
    int rootBus;
    std::string rootBusName;
    std::string targetPortConfig;
    uint8_t topMostRootBus;
};

std::unordered_map<
    std::string /*Hub path*/,
    std::pair<HubInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    hubList;

static HubInfo getHubInfo(const std::string& hubPath, uint8_t topMostRootBusNo)
{
    HubInfo hubInfo;
    hubInfo.deviceID = hw::aspeed::readHubID(hubPath);
    hubInfo.rootBus = hw::aspeed::findRootBusNo(hubPath);
    hubInfo.rootBusName = hw::aspeed::readRootBusName(hubPath);
    hubInfo.targetPortConfig = hw::aspeed::readTPConf(hubPath);
    hubInfo.topMostRootBus = topMostRootBusNo;

    return hubInfo;
}

// Object path template:
// '/xyz/openbmc_project/I3CHub/<RootBus>_<DeviceID>'.
static std::string generateObjectPath(const std::string& hubPath)
{
    const std::string hubMatchString = "-4cd";
    std::string hubObjPath = hubBaseObjectPath;
    size_t pos = hubPath.find(hubMatchString);
    while (pos != std::string::npos)
    {
        std::string subHubPath = hubPath.substr(
            0, hubPath.find_first_of("/", pos + hubMatchString.length()));

        hubObjPath += "/" +
                      std::to_string(hw::aspeed::findRootBusNo(subHubPath)) +
                      "_" + std::to_string(hw::aspeed::readHubID(subHubPath));

        pos = hubPath.find(hubMatchString, pos + hubMatchString.length());
    }
    return hubObjPath;
}

static void addHubInterface(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& objectPath, const std::string& hubPath,
    const HubInfo& hubInfo)
{

    auto interface = objectServer->add_unique_interface(objectPath.c_str(),
                                                        hubInterfaceName);
    interface->register_property("DeviceID", hubInfo.deviceID);
    interface->register_property("RootBus", hubInfo.rootBus);
    interface->register_property("RootBusName", hubInfo.rootBusName);
    interface->register_property("TargetPortConfig", hubInfo.targetPortConfig);
    interface->register_property("TopMostRootBus", hubInfo.topMostRootBus);
    interface->initialize();

    hubList[hubPath] = std::make_pair(hubInfo, std::move(interface));
}

static void checkForHubChanges(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer)
{
    std::unordered_map<std::string, uint8_t> hubPaths;
    for (auto const& i3cRootBusNo : interestedI3CRootBusList)
    {
        std::set<std::string> hubPathsTemp =
            hw::aspeed::findI3CHubs(i3cRootBusNo);
        for (const auto& hubPath : hubPathsTemp)
        {
            hubPaths.emplace(hubPath, i3cRootBusNo);
        }
    }

    // Remove the hubs which are not present in the current scan at first
    for (auto it = hubList.begin(); it != hubList.end();)
    {
        if (hubPaths.find(it->first) == hubPaths.end())
        {
            // Hub removed
            auto& hubPath = it->first;
            auto& hubInfo = it->second.first;
            std::string hubInfoLog =
                "Hub removed. DeviceID: " + std::to_string(hubInfo.deviceID) +
                ", " + "RootBus: " + std::to_string(hubInfo.rootBus) + ", " +
                "RootBusName: " + hubInfo.rootBusName + ", " +
                "TargetPortConfig: " + hubInfo.targetPortConfig + ", " +
                "TopMostRootBus: " + std::to_string(hubInfo.topMostRootBus);
            phosphor::logging::log<phosphor::logging::level::INFO>(
                hubInfoLog.c_str());

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Removed hub path: " + hubPath).c_str());

            it = hubList.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Check for new hubs and add them
    for (auto const& [hubPath, i3cRootBusNo] : hubPaths)
    {
        if (hubList.find(hubPath) == hubList.end())
        {
            // New hub found
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("New Hub found: " + hubPath).c_str());

            HubInfo hubInfo = getHubInfo(hubPath, i3cRootBusNo);
            std::string objPath = generateObjectPath(hubPath);
            addHubInterface(objectServer, objPath, hubPath, hubInfo);

            std::string hubInfoLog =
                "Hub added. DeviceID: " + std::to_string(hubInfo.deviceID) +
                ", " + "RootBus: " + std::to_string(hubInfo.rootBus) + ", " +
                "RootBusName: " + hubInfo.rootBusName + ", " +
                "TargetPortConfig: " + hubInfo.targetPortConfig + ", " +
                "TopMostRootBus: " + std::to_string(hubInfo.topMostRootBus);
            phosphor::logging::log<phosphor::logging::level::INFO>(
                hubInfoLog.c_str());
        }
    }
}

static void rescanI3CBusses()
{
    std::for_each(interestedI3CRootBusList.begin(),
                  interestedI3CRootBusList.end(), [](uint8_t i3cRootBusNo) {
                      hw::aspeed::rescanI3CRootBus(i3cRootBusNo);
                  });
}

static void pollI3CHubChanges(
    std::shared_ptr<boost::asio::io_context> ioc,
    std::shared_ptr<sdbusplus::asio::object_server> objectServer)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Checking I3C hub changes");

    // We don't need to do driver level re-scan for the first time.
    static bool firstTime = true;
    if (firstTime)
    {
        firstTime = false;
        checkForHubChanges(objectServer);
    }
    else
    {
        rescanI3CBusses();

        // Driver may take some time to re-scan all i3c busses. Add a safe delay
        // before checking hub changes.
        // TODO: Optimize the safe delay if needed.
        static boost::asio::steady_timer waitTimer(*ioc);
        static std::chrono::seconds safeDelayInSec(2);
        auto waitTimerHandler =
            [objectServer](const boost::system::error_code& error) {
                if (error)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "waitTimer error. Skipping hub changes check.");
                    return;
                }

                checkForHubChanges(objectServer);
            };
        waitTimer.expires_after(safeDelayInSec);
        waitTimer.async_wait(waitTimerHandler);
    }

    // Check for i3c bus changes on every 10 sec.
    // TODO: Optimize the interval if needed.
    static boost::asio::steady_timer rescanTimer(*ioc);
    static std::chrono::seconds rescanIntervalInSec(10);
    auto rescanTimerHandler =
        [ioc, objectServer](const boost::system::error_code& error) {
            if (error)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "rescanTimer error. Exiting.");
                return;
            }

            pollI3CHubChanges(ioc, objectServer);
        };

    rescanTimer.expires_after(rescanIntervalInSec);
    rescanTimer.async_wait(rescanTimerHandler);
}

int main()
{
    auto ioc = std::make_shared<boost::asio::io_context>();
    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name("xyz.openbmc_project.I3C.Hub.Detector");

    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait([ioc](const boost::system::error_code&, const int&) {
        // Stop processing events
        ioc->stop();
    });

    pollI3CHubChanges(ioc, objectServer);

    ioc->run();
    return 0;
}
