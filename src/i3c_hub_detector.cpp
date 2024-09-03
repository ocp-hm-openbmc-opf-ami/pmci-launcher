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
const static constexpr char* i3cInterfaceName = "xyz.openbmc_project.I3CDevice";
const static constexpr char* i2cInterfaceName = "xyz.openbmc_project.I2CDevice";

const std::string i3cIntName = "/I3CDevice/";
const std::string i2cIntName = "/I2CDevice/";

// Use the list of BHS platform for now.
// TODO: get this from entity-manager or scan for all root busses, depending on
// future use cases.
const std::vector<uint8_t> interestedI3CRootBusList = {2 /*I3C_MNG*/,
                                                       5 /*I3C_PCIe*/};

std::unordered_map<
    std::string /*Hub path*/,
    std::pair<HubInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    hubList;

std::unordered_map<
    std::string,
    std::pair<I3cDevInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    i3cDeviceInfoList;

std::unordered_map<
    std::string,
    std::pair<I2cDevInfo, std::unique_ptr<sdbusplus::asio::dbus_interface>>>
    i2cDeviceInfoList;

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

void registerI3CToDbus(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& objPath, I3cDevInfo i3cDeviceinfo)
{
    auto interface =
        objectServer->add_unique_interface(objPath.c_str(), i3cInterfaceName);

    interface->register_property("BCR", i3cDeviceinfo.bcr);
    interface->register_property("Bus", i3cDeviceinfo.bus);
    interface->register_property("DCR", i3cDeviceinfo.dcr);
    interface->register_property("Devices", i3cDeviceinfo.devices);
    interface->register_property("PhysicalLocation", i3cDeviceinfo.phyLoc);
    interface->register_property("PID", i3cDeviceinfo.pid);
    interface->register_property("TargetPort", i3cDeviceinfo.targetPort);
    interface->register_property("TopMostRootBus",
                                 i3cDeviceinfo.topMostRootBus);
    interface->initialize();

    i3cDeviceInfoList[objPath] =
        std::make_pair(i3cDeviceinfo, std::move(interface));
}

void registerI2CToDbus(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    I2cDevInfo i2cDeviceinfo, const std::string& objPath)
{
    auto interface =
        objectServer->add_unique_interface(objPath.c_str(), i2cInterfaceName);

    interface->register_property("Address", i2cDeviceinfo.address);
    interface->register_property("Bus", i2cDeviceinfo.bus);
    interface->register_property("Device", i2cDeviceinfo.device);
    interface->register_property("LocationCode", i2cDeviceinfo.locationCode);
    interface->register_property("TargetPort", i2cDeviceinfo.targetPort);
    interface->register_property("TopMostRootBus",
                                 i2cDeviceinfo.topMostRootBus);
    interface->initialize();

    i2cDeviceInfoList[objPath] =
        std::make_pair(i2cDeviceinfo, std::move(interface));
}

void discoverI3cDevicesBehindHub(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& hubPath, const std::string& objPath,
    uint8_t topMostRootBus, uint8_t hubId)

{
    std::unordered_map<std::string, I3cDevInfo> i3cDevsTemp;

    try
    {
        for (const auto& entry : std::filesystem::directory_iterator(hubPath))
        {
            std::string mystring = entry.path().filename().string();

            if (entry.is_directory() &&
                entry.path().filename().string().find("i3c") == 0)
            {
                I3cDevInfo i3cDeviceinfo;
                std::string newDevPath = entry.path();

                i3cDeviceinfo.bcr = hw::aspeed::readBcr(newDevPath);
                i3cDeviceinfo.dcr = hw::aspeed::readDcr(newDevPath);
                i3cDeviceinfo.bus = hw::aspeed::extractI3cBus(newDevPath);
                i3cDeviceinfo.pid = hw::aspeed::readPid(newDevPath);

                i3cDeviceinfo.devices.push_back(
                    hw::aspeed::readI3cDevices(newDevPath, i3cDeviceinfo.pid));

                ConfigurationMap config =
                    hubConfig->findI3CHubConfig(hubId, topMostRootBus);

                std::vector<std::string> channelNames =
                        hubConfig->getChannelNames(config);
                std::string hubTgtports =
                        hw::aspeed::processDirectories(newDevPath);
                std::string devPath = newDevPath + "/";
                std::string currentTgtPort = hw::aspeed::readBusName(devPath);
  
                i3cDeviceinfo.targetPort = currentTgtPort + hubTgtports;
                if (!channelNames.empty())
                {
                    i3cDeviceinfo.phyLoc = channelNames[std::stoi(currentTgtPort)];
                }
                i3cDeviceinfo.topMostRootBus = topMostRootBus;

                std::string newObjPath =
                    objPath + i3cIntName + std::to_string(i3cDeviceinfo.bus) +
                    "_" + i3cDeviceinfo.targetPort + "_" + i3cDeviceinfo.pid;

                i3cDevsTemp.emplace(newObjPath, i3cDeviceinfo);

                for (auto it = i3cDeviceInfoList.begin();
                     it != i3cDeviceInfoList.end();)
                {
                    if (i3cDevsTemp.find(it->first) == i3cDevsTemp.end())
                    {
                        it = i3cDeviceInfoList.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }

                for (auto const& [i3cDevPath, i3cdevInfo] : i3cDevsTemp)
                {
                    if (i3cDeviceInfoList.find(i3cDevPath) ==
                        i3cDeviceInfoList.end())
                    {
                        registerI3CToDbus(objectServer, i3cDevPath, i3cdevInfo);
                    }
                }
            }
        }
    }

    catch (const std::filesystem::filesystem_error& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "discoverI3cDevicesBehindHub Loop Error.",
            phosphor::logging::entry("Exception:", e.what()));
    }
}

void discoverI2cDevicesBehindHub(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer,
    const std::string& hubPath, const std::string& objPath,
    uint8_t topMostRootBus, uint8_t hubId)

{
    std::unordered_map<std::string, I2cDevInfo> i2cDevsTemp;
    try
    {
        for (const auto& entry : std::filesystem::directory_iterator(hubPath))
        {
            if (entry.is_directory() &&
                entry.path().filename().string().find("i2c") == 0)
            {
                I2cDevInfo i2cDeviceinfo;
                std::string i2cDev = "/dev/i2c-";

                i2cDeviceinfo.bus = hw::aspeed::extractI2cBus(entry.path());
                i2cDeviceinfo.device =
                    i2cDev + std::to_string(i2cDeviceinfo.bus);

                std::string hubTgtports =
                    hw::aspeed::processDirectories(entry.path());
                std::vector<int> addresses =
                    hw::aspeed::findI2CAddress(i2cDeviceinfo.device);

                if (addresses.empty())
                {
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        ("No I2c slaves Addresses: " + i2cDeviceinfo.device)
                            .c_str());
                    continue;
                }
                else
                {
                    for (int address : addresses)
                    {
                        std::string printadd = std::to_string(address);

                        i2cDeviceinfo.address = address;

                        ConfigurationMap config =
                            hubConfig->findI3CHubConfig(hubId, topMostRootBus);
                        std::vector<std::string> channelNames =
                            hubConfig->getChannelNames(config);

                        std::string currentTgtPort = 
                            hw::aspeed::readI2cBusName(entry.path());

                        i2cDeviceinfo.targetPort = currentTgtPort + hubTgtports;
                        if (!channelNames.empty())
                        {
                            i2cDeviceinfo.locationCode =
                                channelNames[std::stoi(currentTgtPort)];
                        }

                        i2cDeviceinfo.topMostRootBus = topMostRootBus;
                        std::string newObjPath =
                            objPath + i2cIntName +
                            std::to_string(i2cDeviceinfo.bus) + "_" +
                            i2cDeviceinfo.targetPort + "_" +
                            std::to_string(i2cDeviceinfo.address);

                        i2cDevsTemp.emplace(newObjPath, i2cDeviceinfo);
                    }
                }

                for (auto it = i2cDeviceInfoList.begin();
                     it != i2cDeviceInfoList.end();)
                {
                    if (i2cDevsTemp.find(it->first) == i2cDevsTemp.end())
                    {
                        it = i2cDeviceInfoList.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }

                for (auto const& [i2cDevPath, i2cdevInfo] : i2cDevsTemp)
                {
                    if (i2cDeviceInfoList.find(i2cDevPath) ==
                        i2cDeviceInfoList.end())
                    {
                        registerI2CToDbus(objectServer, i2cdevInfo, i2cDevPath);
                    }
                }
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "discoverI2cDevicesBehindHub Loop Error.",
            phosphor::logging::entry("Exception:", e.what()));
    }
}

void checkForHubChanges(
    std::shared_ptr<sdbusplus::asio::object_server> objectServer)
{
    std::unordered_map<std::string, uint8_t> hubPaths;
    for (auto const& i3cRootBusNo : interestedI3CRootBusList)
    {
        std::set<std::string> hubPathsTemp =
            hw::aspeed::findI3CHubs(i3cRootBusNo);
        if (hubPathsTemp.empty())
        {
            std::string BusNo = std::to_string(i3cRootBusNo);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Failed to find the Bus:" + BusNo).c_str());
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

            discoverI3cDevicesBehindHub(objectServer, hubPath, objPath,
                                    hubInfo.topMostRootBus, hubInfo.deviceID);
            discoverI2cDevicesBehindHub(objectServer, hubPath, objPath,
                                    hubInfo.topMostRootBus, hubInfo.deviceID);
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
