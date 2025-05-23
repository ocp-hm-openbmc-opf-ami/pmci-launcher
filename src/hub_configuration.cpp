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

#include <hub_configuration.hpp>
#include <phosphor-logging/log.hpp>

static constexpr int sleepIntervalSec = 5;
static constexpr int maxWaitTimeSec = 25;
static const std::string i3cHubTypeName =
    "xyz.openbmc_project.Configuration.I3CHub";

template <typename T>
bool getField(const ConfigurationMap& configuration,
              const std::string& fieldName, T& value)
{
    auto it = configuration.find(fieldName);
    if (it != configuration.end())
    {
        const T* ptrValue = std::get_if<T>(&it->second);
        if (ptrValue != nullptr)
        {
            value = *ptrValue;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Missing configuration field " + fieldName).c_str());
    return false;
}

std::vector<std::string> HubConfiguration::getConfigurationPaths()
{
    auto methodCall = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    methodCall.append("/xyz/openbmc_project/inventory/system/board", 2,
                      std::array<std::string, 1>({i3cHubTypeName}));

    auto reply = conn->call(methodCall);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths;
}

ConfigurationMap
    HubConfiguration::getConfigurationMap(const std::string& configurationPath)
{
    auto methodCall = conn->new_method_call(
        "xyz.openbmc_project.EntityManager", configurationPath.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    methodCall.append(i3cHubTypeName);

    // Note: This is a blocking call.
    // However, there is nothing to do until the configuration is retrieved.
    auto reply = conn->call(methodCall);
    ConfigurationMap map;
    reply.read(map);

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Configuration retrieved for " + configurationPath).c_str());
    return map;
}

std::vector<ConfigurationMap> HubConfiguration::getAllI3CHubConfigs()
{
    std::vector<std::string> configurationPaths;

    static int timeRemain = maxWaitTimeSec;
    while (timeRemain > 0)
    {
        try
        {
            configurationPaths = getConfigurationPaths();
            break;
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                (std::string("Could not retrieve existing configurations: ") +
                 e.what())
                    .c_str());
            if (timeRemain <= 0)
            {
                return {};
            }
            // ObjectMapper may take some time to start up. Retry after a delay.
            // Sleep is ok since we have nothing else to do until this is
            // successful.
            sleep(sleepIntervalSec);
            timeRemain -= sleepIntervalSec;
        }
    }

    for (const auto& objectPath : configurationPaths)
    {
        i3cHubConfigs.push_back(getConfigurationMap(objectPath));
    }
    return i3cHubConfigs;
}

ConfigurationMap
    HubConfiguration::findI3CHubConfig(const uint8_t hubID,
                                       const uint8_t topMostRootBus)
{
    for (const auto& config : i3cHubConfigs)
    {
        uint64_t hubIDConfig;
        uint64_t topMostRootBusConfig;
        if (getField(config, "DeviceID", hubIDConfig) &&
            getField(config, "Bus", topMostRootBusConfig))
        {
            if (hubIDConfig == hubID && topMostRootBusConfig == topMostRootBus)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Found matching configuration");
                return config;
            }
        }
    }
    return {};
}

std::string HubConfiguration::getHubName(const ConfigurationMap& config)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>("Getting hub name");
    std::string name;
    if (getField(config, "Name", name))
    {
        return name;
    }
    return {};
}

std::vector<std::string>
    HubConfiguration::getChannelNames(const ConfigurationMap& config)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Getting channel names");
    std::vector<std::string> channelNames;
    if (getField(config, "ChannelNames", channelNames))
    {
        return channelNames;
    }
    return {};
}

std::vector<uint8_t> HubConfiguration::getBusList()
{
    phosphor::logging::log<phosphor::logging::level::INFO>("Getting bus list");
    std::vector<uint8_t> busList;
    for (const auto& config : i3cHubConfigs)
    {
        std::vector<uint64_t> buses;
        if (getField(config, "Bus", buses))
        {
            for (const auto& bus : buses)
            {
                busList.push_back(static_cast<uint8_t>(bus));
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Bus: " + std::to_string(bus) + " added to list").c_str());
            }
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get bus list");
            return {};
        }
    }
    return busList;
}
