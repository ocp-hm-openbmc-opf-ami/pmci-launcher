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

#include "i3c_hub_detector.hpp"

#include "hub_configuration.hpp"
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

std::unordered_map<
    std::string /*Hub path*/,
    std::pair<HubInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    hubList;

// TODO: Create an 'I3CDeviceManager' class and move APIs and below variables to
// it.
static std::unique_ptr<HubConfiguration> hubConfig = nullptr;

std::vector<std::string>
    getActiveTPList(const std::vector<std::string>& channelNames,
                    const std::string& tpConf)
{
    constexpr std::size_t tpConfSize = 8;
    if (tpConf.size() != tpConfSize || channelNames.size() < tpConfSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getActiveTPList: invalid size",
            phosphor::logging::entry("SIZE=%d", tpConf.size()),
            phosphor::logging::entry("CHANNEL_SIZE=%d", channelNames.size()));
        return {};
    }
    // A tpConf value may look like "suuisuud", which means I3C hub port 3 and 7
    // are configured as SMBus, port 4 is configured as I3C, port 0 is disabled
    // and 1, 2, 5, 6 are undefined.
    std::vector<std::string> activeTPList;
    for (std::size_t i = 0; i < tpConf.size(); ++i)
    {
        if (tpConf[i] == 's' /*For SMBus devices*/ ||
            tpConf[i] == 'i' /*For I3C devices*/)
        {
            activeTPList.push_back(channelNames[tpConfSize - i - 1]);
        }
    }
    return activeTPList;
}

HubInfo getHubInfo(const std::string& hubPath, uint8_t topMostRootBusNo)
{
    HubInfo hubInfo;
    hubInfo.deviceID = hw::aspeed::readHubID(hubPath);
    hubInfo.bus = hw::aspeed::findBusNo(hubPath);
    hubInfo.busName = hw::aspeed::readBusName(hubPath);
    hubInfo.targetPortConfig = hw::aspeed::readTPConf(hubPath);
    hubInfo.topMostRootBus = topMostRootBusNo;

    ConfigurationMap config =
        hubConfig->findI3CHubConfig(hubInfo.deviceID, topMostRootBusNo);
    hubInfo.name = hubConfig->getHubName(config);

    std::vector<std::string> channelNames = hubConfig->getChannelNames(config);
    hubInfo.activeTargetPortList =
        getActiveTPList(channelNames, hubInfo.targetPortConfig);
    return hubInfo;
}

// Object path template:
// '/xyz/openbmc_project/I3CHub/<Bus>_<DeviceID>'.
std::string generateObjectPath(const std::string& hubPath)
{
    const std::string hubMatchString = "-4cd";
    std::string hubObjPath = hubBaseObjectPath;
    size_t pos = hubPath.find(hubMatchString);
    while (pos != std::string::npos)
    {
        std::string subHubPath = hubPath.substr(
            0, hubPath.find_first_of("/", pos + hubMatchString.length()));

        hubObjPath += "/" + std::to_string(hw::aspeed::findBusNo(subHubPath)) +
                      "_" + std::to_string(hw::aspeed::readHubID(subHubPath));

        pos = hubPath.find(hubMatchString, pos + hubMatchString.length());
    }
    return hubObjPath;
}

void addHubInterface(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& objectPath, const std::string& hubPath,
    const HubInfo& hubInfo)
{

    auto interface = objectServer->add_unique_interface(objectPath.c_str(),
                                                        hubInterfaceName);
    interface->register_property("DeviceID", hubInfo.deviceID);
    interface->register_property("Bus", hubInfo.bus);
    interface->register_property("BusName", hubInfo.busName);
    interface->register_property("TargetPortConfig", hubInfo.targetPortConfig);
    interface->register_property("TopMostRootBus", hubInfo.topMostRootBus);
    interface->register_property("Name", hubInfo.name);
    interface->register_property("ActiveTargetPortList",
                                 hubInfo.activeTargetPortList);
    interface->initialize();

    hubList[hubPath] = std::make_pair(hubInfo, std::move(interface));
}

void checkForHubChanges(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer)
{
    std::unordered_map<std::string, uint8_t> hubPaths;
    for (auto const& i3cRootBusNo : interestedI3CRootBusList)
    {
        std::set<std::string> hubPathsTemp =
            hw::aspeed::findI3CHubs(i3cRootBusNo);
        if(hubPathsTemp.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
              ("Failed to find the Bus:" + i3cRootBusNo));
        }
        else
        {
            for (const auto& hubPath : hubPathsTemp)
            {
                 hubPaths.emplace(hubPath, i3cRootBusNo);
            }
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
                ", " + "Bus: " + std::to_string(hubInfo.bus) + ", " +
                "BusName: " + hubInfo.busName + ", " +
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
    for (auto const& [hubPath, i3cBusNo] : hubPaths)
    {
        if (hubList.find(hubPath) == hubList.end())
        {
            // New hub found
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("New Hub found: " + hubPath).c_str());

            HubInfo hubInfo = getHubInfo(hubPath, i3cBusNo);
            std::string objPath = generateObjectPath(hubPath);
            addHubInterface(objectServer, objPath, hubPath, hubInfo);

            std::string hubInfoLog =
                "Hub added. DeviceID: " + std::to_string(hubInfo.deviceID) +
                ", " + "Bus: " + std::to_string(hubInfo.bus) + ", " +
                "BusName: " + hubInfo.busName + ", " +
                "TargetPortConfig: " + hubInfo.targetPortConfig + ", " +
                "TopMostRootBus: " + std::to_string(hubInfo.topMostRootBus);
            phosphor::logging::log<phosphor::logging::level::INFO>(
                hubInfoLog.c_str());
        }
    }
}

void rescanI3CBusses()
{
    std::for_each(interestedI3CRootBusList.begin(),
                  interestedI3CRootBusList.end(), [](uint8_t i3cRootBusNo) {
                      hw::aspeed::rescanI3CRootBus(i3cRootBusNo);
                  });
}

void pollI3CHubChanges(
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

#ifndef UNIT_TESTS
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

    hubConfig = std::make_unique<HubConfiguration>(conn);
    pollI3CHubChanges(ioc, objectServer);

    ioc->run();
    return 0;
}
#endif
