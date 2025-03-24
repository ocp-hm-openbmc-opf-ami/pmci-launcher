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

#include <dirent.h>
#include <fcntl.h>

#include <filesystem>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/kdev_t.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
}

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

int readBcr(const std::string& hubPath)
{
    std::string idPath = hubPath + "/bcr";
    std::string data;
    readFromFile(idPath, data);
    try
    {
        int result;
        result = std::stoi(data);
        return result;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read data from bcr"));
        return -1;
    }
}

std::string readDcr(const std::string& hubPath)
{
    std::string idPath = hubPath + "/dcr";
    std::string data;
    readFromFile(idPath, data);
    if (data.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read data from dcr"));
    }
    return data;
}

std::string readI2cBusName(const std::string& hubPath)
{
    std::string idPath = hubPath + "/name";
    std::string data;
    readFromFile(idPath, data);
    if (data.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read data from name"));
    }

    std::size_t pos = data.find(".tp");
    if (pos != std::string::npos)
    {
        pos += 3;
        std::string tpValue = data.substr(pos);

        return tpValue;
    }

    return data;
}

std::string readPid(const std::string& hubPath)
{
    std::string idPath = hubPath + "/pid";
    std::string data;
    readFromFile(idPath, data);
    return data;
}

int extractI3cBus(const std::string& path)
{
    std::filesystem::path fsPath(path);
    std::regex i3cPattern("i3c-(\\d+)");

    for (auto it = fsPath.end(); it != fsPath.begin();)
    {
        --it;
        std::smatch match;
        std::string element = it->string();

        if (std::regex_search(element, match, i3cPattern) && match.size() > 1)
        {
            return std::stoi(match[1].str());
        }
    }

    phosphor::logging::log<phosphor::logging::level::ERR>(
        "No matching i3c pattern found in the path.");
    return 0;
}

int extractI2cBus(const std::string& path)
{
    std::filesystem::path fsPath(path);
    std::regex i2cPattern("i2c-(\\d+)");

    for (auto it = fsPath.end(); it != fsPath.begin();)
    {
        --it;
        std::smatch match;
        std::string element = it->string();

        if (std::regex_search(element, match, i2cPattern) && match.size() > 1)
        {
            return std::stoi(match[1].str());
        }
    }

    phosphor::logging::log<phosphor::logging::level::ERR>(
        "No matching i2c pattern found in the path.");
    return 0;
}

std::vector<int> findI2CAddress(const std::string& devfd)
{
    int fd = 0;
    std::vector<int> detectedAddresses;

    fd = open(devfd.c_str(), O_RDWR);
    if (fd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read the I2c Device:" + devfd).c_str());
        return detectedAddresses;
    }

    for (int it = i2cStartAddress; it <= i2cEndAddress; ++it)
    {
        if (ioctl(fd, I2C_SLAVE, it) < 0)
        {
            continue;
        }
        else
        {
            if ((it >= readStartAddress1 && it <= readEndAddress1) ||
                (it >= readStartAddress2 && readEndAddress2 <= 0x5F))
            {
                if (i2c_smbus_read_byte(fd) < 0)
                {
                    continue;
                }
            }
            else
            {
                if (i2c_smbus_write_quick(fd, I2C_SMBUS_WRITE) < 0)
                {
                    continue;
                }
            }
        }

        detectedAddresses.push_back(it);
    }

    FileHandle handle(reinterpret_cast<int*>(fd), closeFileFromPointer);
    return detectedAddresses;
}

std::string readI3cDevices(const std::string& hubPath, const std::string& pid)
{
    std::string idPath = hubPath + "/dcr";
    std::string data;
    readFromFile(idPath, data);

    if (data == "CC")
    {
        // MCTP device as per the I3c Specification

        struct stat statBuf;
        if (stat(hubPath.c_str(), &statBuf))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Stat failed for path: " + hubPath).c_str());
            return {};
        }

        auto deviceMajor = MAJOR(statBuf.st_rdev);
        auto deviceMinor = MINOR(statBuf.st_rdev);

        std::string i3cDevice("/sys/dev/char/" + std::to_string(deviceMajor) +
                              ":" + std::to_string(deviceMinor) + "/device");

        if (i3cDevice.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("I3c device path is Null: " + i3cDevice).c_str());
        }
        else
        {
            std::string pidStr;
            std::string pidFile = i3cDevice + "/pid";

            std::ifstream readFile(pidFile.c_str());
            std::getline(readFile, pidStr);

            if (pid == pidStr)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("readI3cDevices DoNothing"));
                // TODO Waiting for the kernel changes to see how the 
                // i3c devices will be exposed in /sys/dev 
            }
        }
    }

    return {};
}

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
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read data from tp_conf"));
    }
    return data;
}

int findBusNo(const std::string& hubPath)
{
    // A sample multilevel hubPath  may look like
    // '1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b'. The hub name
    // is prefixed with logical I3C bus number to which the hub is
    // connected. Extract the same from the path.
    std::string delimiter = "/";
    size_t pos = hubPath.rfind(delimiter);
    if (pos == std::string::npos)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to find delimiter in hubPath"));
        return -1;
    }
    std::string extracted = hubPath.substr(pos + delimiter.length());
    size_t hyphenPos = extracted.find("-");
    if (hyphenPos == std::string::npos)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to find hyphen in hubPath"));
        return -1;
    }
    std::string bus = extracted.substr(0, hyphenPos);
    return std::stoi(bus); // Expected to throw on error
}

std::string readBusName(const std::string& hubPath)
{
    std::size_t lastSlashPos = hubPath.find_last_of('/');
    if (lastSlashPos == std::string::npos)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to find last slash in hubPath"));
        return {};
    }

    std::string busNamePath = hubPath.substr(0, lastSlashPos) + "/name";
    std::string data;
    readFromFile(busNamePath, data);
    if (data.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to read data from busNamePath" + busNamePath).c_str());
        return {};
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
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to find name of the port:" + busNamePath).c_str());
        return {};
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
    std::string deviceDirPath = "/sys/bus/platform/devices/" + busName;
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
        FileHandle handle(reinterpret_cast<int*>(fd), closeFileFromPointer);
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

// Function to recursively find all directories matching the pattern *4cd* under
// a given path
void findAllHubsFromPath(const std::string& basePath,
                             std::vector<std::string>& directories)
{
    DIR* dir;
    struct dirent* ent;
    if ((dir = opendir(basePath.c_str())) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            if (ent->d_type == DT_DIR)
            {
                std::string dirName = ent->d_name;
                // Skip . and .. directories
                if (dirName == "." || dirName == "..")
                {
                    continue;
                }
                std::string fullPath = basePath + "/" + dirName;
                // Check if the directory name contains "4cd"
                if (dirName.find("4cd") != std::string::npos)
                {
                    directories.push_back(fullPath);
                }
                // Recursively search in subdirectories
                findAllHubsFromPath(fullPath, directories);
            }
        }
        DirHandle dirHandle(dir, closeDirFromPointer);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Could not open directory:" + basePath).c_str());
    }
}

// Function to read the integer from the "name" file in the given directory
// concatenates to a string for multilevel hub
std::string readHubTargetPortNo(const std::string& directoryPath)
{
    std::string filePath = directoryPath + "/name";
    std::ifstream file(filePath);
    std::string line;
    if (file.is_open())
    {
        while (getline(file, line))
        {
            // Use regex to find integers immediately preceding ".tp"
            std::regex integerRegex("(\\d+)(?=\\.tp)");
            std::smatch match;
            if (std::regex_search(line, match, integerRegex) &&
                match.size() > 1)
            {
                return match[1]; // match[1] to get the first captured group
                                 // which is the integer
            }
        }
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Unable to open file::" + filePath).c_str());
    }
    return {};
}

// Function to process directories and concatenate integers
std::string processDirectories(const std::string& basePath)
{
    std::vector<std::string> directories;
    findAllHubsFromPath(basePath, directories);
    std::vector<std::string> integers;
    for (const std::string& dir : directories)
    {
        std::string integer = readHubTargetPortNo(dir);
        if (!integer.empty())
        {
            integers.push_back(integer);
        }
    }
    // Concatenate all integers with underscores
    std::ostringstream result;
    for (size_t i = 0; i < integers.size(); ++i)
    {
        if (i > 0)
        {
            result << "_";
        }
        result << integers[i];
    }
    return result.str();
}

} // namespace aspeed
} // namespace hw
