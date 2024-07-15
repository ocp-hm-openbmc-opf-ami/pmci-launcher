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

#include <fcntl.h>

#include <filesystem>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <set>
#include <string>

void readFromFile(const std::string& filePath, std::string& data)
{
    if (std::filesystem::exists(filePath))
    {
        std::ifstream file(filePath);
        if (file.is_open())
        {
            std::getline(file, data);
            file.close();
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Failed to open file: " + filePath).c_str());
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("File does not exist: " + filePath).c_str());
    }
}

namespace hw
{
namespace aspeed
{

uint8_t readHubID(const std::string& hubPath)
{
    std::string idPath = hubPath + "/id";
    std::string data;
    readFromFile(idPath, data);
    return static_cast<uint8_t>(std::stoi(data)); // Expected to throw on error
}

std::string readTPConf(const std::string& hubPath)
{
    // Data read from 'tp_conf' will look something like "suuisuud".
    // Where,
    // 1. 's' is 'SMBus'. SMBus device present.
    // 2. 'u' is 'Undefined'. No device present.
    // 3. 'i' is 'I3C'. I3C device present.
    // 4. 'd' is 'Disabled'. Port is disabled.
    // And each character maps with I3C hub port numbers in little endian
    // order. For example, here "suuisuud" means I3C hub port 3 and 7
    // are configured as SMBus, port 4 is configured as I3C, port 0 is disabled
    // and 1, 2, 5, 6 are undefined.

    std::string tpConfPath = hubPath + "/tp_conf";
    std::string data;
    readFromFile(tpConfPath, data);
    if (data.empty())
    {
        throw std::runtime_error("Failed to read data from tp_conf");
    }
    return data;
}

int findRootBusNo(const std::string& hubPath)
{
    // A sample multilevel hubPath  may look like
    // '1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b'. The hub name
    // is prefixed with logical I3C bus number to which the hub is
    // connected. Extract the same from the path.
    std::string delimiter = "/";
    size_t pos = hubPath.rfind(delimiter);
    if (pos == std::string::npos)
    {
        throw std::runtime_error("Failed to find delimiter in hubPath");
    }
    std::string extracted = hubPath.substr(pos + delimiter.length());
    size_t hyphenPos = extracted.find("-");
    if (hyphenPos == std::string::npos)
    {
        throw std::runtime_error("Failed to find hyphen in hubPath");
    }
    std::string rootBus = extracted.substr(0, hyphenPos);
    return std::stoi(rootBus); // Expected to throw on error
}

std::string readRootBusName(const std::string& hubPath)
{
    std::size_t lastSlashPos = hubPath.find_last_of('/');
    if (lastSlashPos == std::string::npos)
    {
        throw std::runtime_error("Failed to find last slash in hubPath");
    }

    std::string rootBusNamePath = hubPath.substr(0, lastSlashPos) + "/name";
    std::string data;
    readFromFile(rootBusNamePath, data);
    if (data.empty())
    {
        throw std::runtime_error("Failed to read data from rootBusNamePath");
    }

    // Sample data will look like "3-4cd15771616.tp3" or "1e7a7000.i3c5".
    // Where, 'tp3' indicates target port 3 of root hub. 'i3c5' indicates
    // bus number 5 of a root bus.
    std::size_t lastDotPos = data.find_last_of('.');
    if (lastDotPos != std::string::npos)
    {
        std::string name = data.substr(lastDotPos + 1);
        return name;
    }
    else
    {
        throw std::runtime_error("Failed to find name of the port:" +
                                 rootBusNamePath);
    }
}

std::string getI3CRootBusPath(const uint8_t topMostRootI3CBusNum)
{
    auto search = i3cBusMap.find(topMostRootI3CBusNum);
    if (search == i3cBusMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "I3C bus not found in i3cBusMap");
        return {};
    }

    std::string busName = search->second;
    std::string deviceDirPath =
        "/sys/devices/platform/ahb/ahb:apb/ahb:apb:bus@1e7a0000/" + busName;
    if (!std::filesystem::exists(deviceDirPath))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("I3C bus not found in sysfs: " + deviceDirPath).c_str());
        return {};
    }

    for (const auto& entry : std::filesystem::directory_iterator(deviceDirPath))
    {
        std::string pathStr = entry.path().generic_string();
        if (pathStr.rfind(deviceDirPath + "/i3c") != std::string::npos)
        {
            return pathStr;
        }
    }

    phosphor::logging::log<phosphor::logging::level::WARNING>(
        ("Root I3C bus entry not found: " + deviceDirPath).c_str());
    return {};
}

std::set<std::string> findI3CHubs(const uint8_t topMostRootI3CBusNum)
{
    std::string i3cBusPath = getI3CRootBusPath(topMostRootI3CBusNum);

    if (!std::filesystem::exists(i3cBusPath))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Invalid I3C bus path: " + i3cBusPath).c_str());
        return {};
    }

    // we are interested only in particular hub which can be behind another
    // i3c hubs. so lets find the hubs staring from the root i3c bus at
    // first and find the i3c hubs behind them. Note: Hub entries are
    // started with prefix bus number followed by string "4cd"
    const std::regex hubMatchRegex("\\d+\\-4cd[0-9a-f]{8}");
    std::set<std::string> i3cHubPaths;

    for (const auto& entry : std::filesystem::directory_iterator(i3cBusPath))
    {
        std::string pathStr = entry.path().generic_string();
        if (std::regex_search(pathStr, hubMatchRegex))
        {
            i3cHubPaths.insert(pathStr);
        }
    }

    if (i3cHubPaths.empty())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("No I3C hub found under root bus:" + i3cBusPath).c_str());
        return {};
    }
    return i3cHubPaths;
}

void rescanI3CBus(const std::string& busPath)
{
    std::string rescanPath = busPath + "/rescan";
    if (!std::filesystem::exists(rescanPath))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Re-scan file not found: " + rescanPath).c_str());
        return;
    }

    int fd = open(rescanPath.c_str(), O_WRONLY);
    if (fd > 0)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Re-scanning bus:" + rescanPath).c_str());
        std::array<char, 1> writeData = {'1'};
        ssize_t status = write(fd, writeData.data(), writeData.size());
        if (status != 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Write status " + std::to_string(status) + " Errno " +
                 std::to_string(errno))
                    .c_str());
        }
        close(fd);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error re-scanning I3C driver");
        return;
    }
}

void rescanI3CRootBus(const uint8_t rootI3CBusNum)
{
    std::string i3cBusPath = getI3CRootBusPath(rootI3CBusNum);
    rescanI3CBus(i3cBusPath);
    // Ignore errors and try again in next iteration
}

} // namespace aspeed
} // namespace hw
