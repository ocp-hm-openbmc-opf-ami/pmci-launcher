#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <unordered_set>

static std::shared_ptr<sdbusplus::asio::connection> conn;

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string mctpTypeName =
    "xyz.openbmc_project.Configuration.MctpConfiguration";

static std::unordered_set<std::string> startedUnits;

static std::vector<std::string> getConfigurationPaths()
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    method_call.append("/xyz/openbmc_project/inventory/system/board", 2,
                       std::array<std::string, 1>({mctpTypeName}));

    auto reply = conn->call(method_call);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths;
}

template <typename Property>
static auto
    readPropertyValue(sdbusplus::bus::bus& bus, const std::string& service,
                      const std::string& path, const std::string& interface,
                      const std::string& property)
{
    auto msg = bus.new_method_call(service.c_str(), path.c_str(),
                                   "org.freedesktop.DBus.Properties", "Get");
    msg.append(interface.c_str(), property.c_str());
    auto reply = bus.call(msg);
    std::variant<Property> v;
    reply.read(v);
    return std::get<Property>(v);
}

static void startUnit(const std::string& objectPath)
{
    const auto serviceArgument = boost::algorithm::replace_all_copy(
        boost::algorithm::replace_first_copy(
            objectPath, "/xyz/openbmc_project/inventory/system/board/", ""),
        "/", "_2f");
    const auto unitName =
        "xyz.openbmc_project.mctpd@" + serviceArgument + ".service";

    try
    {
        auto method_call = conn->new_method_call(
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "StartUnit");
        method_call.append(unitName, "replace");
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Starting unit " + unitName).c_str());
        conn->call(method_call);
        startedUnits.emplace(objectPath);
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Started unit " + unitName).c_str());
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Error starting unit " + unitName).c_str());
    }
}

void readBMCModeAndRole(std::string& bmcMode, std::string& bmcRole)
{
    // Reading BMC mode and Role from the Modular service
    try
    {
        bmcMode = readPropertyValue<std::string>(
            *conn, "xyz.openbmc_project.modular",
            "/xyz/openbmc_project/modular", "xyz.openbmc_project.modular.state",
            "BMCMode");
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("BMC Mode" + bmcMode).c_str());
        bmcRole = readPropertyValue<std::string>(
            *conn, "xyz.openbmc_project.modular",
            "/xyz/openbmc_project/modular", "xyz.openbmc_project.modular.state",
            "BMCRole");
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("BMC Role " + bmcRole).c_str());
    }
    // Catch will execute only for the 2S Modular or non-modular  system Entity
    // manager configuartion
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            (std::string("Two Soket modular or Non modular system") + e.what())
                .c_str());
    }
}

void runModularConfiguartion(const std::string& objectPath,
                             const std::vector<std::string> entityBMCMode,
                             const std::string entityBMCRole,
                             const std::string bmcMode,
                             const std::string bmcRole)
{
    // Check whether modular service available
    if (!bmcMode.empty() && !bmcRole.empty())
    {
        // this block will execute for 4s and 8s modular systems
        auto it =
            std::find(entityBMCMode.begin(), entityBMCMode.end(), bmcMode);
        if (it != entityBMCMode.end() && entityBMCRole == bmcRole)
        {
            startUnit(objectPath);
        }
    }
    // Else part will cover 2S modular system services
    else
    {
        auto it =
            std::find(entityBMCMode.begin(), entityBMCMode.end(), "TwoSocket");
        if (it != entityBMCMode.end())
        {
            startUnit(objectPath);
        }
    }
}

void readEntityModularInterface(const std::string& objectPath,
                                std::vector<std::string>& entityBMCMode,
                                std::string& entityBMCRole)
{
    // Reading Modular interface BMC mode and role from entiy mangager
    // configuration
    try
    {
        entityBMCMode = readPropertyValue<std::vector<std::string>>(
            *conn, "xyz.openbmc_project.EntityManager", objectPath,
            "xyz.openbmc_project.Configuration.MctpConfiguration.Modular",
            "BMCMode");
        entityBMCRole = readPropertyValue<std::string>(
            *conn, "xyz.openbmc_project.EntityManager", objectPath,
            "xyz.openbmc_project.Configuration.MctpConfiguration.Modular",
            "BMCRole");
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            (std::string(
                 "Entity configuration paths not contain modular interface") +
             e.what())
                .c_str());
    }
}

void identifyAndStartUnit(const std::string& objectPath,
                          const std::string bmcMode, const std::string bmcRole)
{
    std::vector<std::string> entityBMCMode;
    std::string entityBMCRole;
    // Reading Modular interface from the entity manager configuration.
    readEntityModularInterface(objectPath, entityBMCMode, entityBMCRole);
    if (entityBMCMode.empty() || entityBMCRole.empty())
    {
        // Entity manager BMC mode and role will be absent for Non modular
        // services
        // start the  service
        startUnit(objectPath);
    }
    else
    {
        // Check for the type of modualr system
        runModularConfiguartion(objectPath, entityBMCMode, entityBMCRole,
                                bmcMode, bmcRole);
    }
}

static void startExistingConfigurations(const std::string bmcMode,
                                        const std::string bmcRole)
{
    std::vector<std::string> configurationPaths;
    try
    {
        configurationPaths = getConfigurationPaths();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Could not retrieve existing configurations: ") +
             e.what())
                .c_str());
        return;
    }
    for (const auto& objectPath : configurationPaths)
    {
        if (startedUnits.count(objectPath) != 0)
        {
            continue;
        }
        try
        {
            identifyAndStartUnit(objectPath, bmcMode, bmcRole);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("Could not start existing configuration at path " +
                 objectPath + ": " + e.what())
                    .c_str());
        }
    }
}

int main()
{
    boost::asio::io_context ioc;
    conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name("xyz.openbmc_project.PMCI_Launcher");
    std::string bmcMode;
    std::string bmcRole;
    readBMCModeAndRole(bmcMode, bmcRole);
    startExistingConfigurations(bmcMode, bmcRole);

    boost::asio::steady_timer timer(ioc);
    std::vector<std::string> units;
    namespace rules = sdbusplus::bus::match::rules;

    auto match = std::make_unique<sdbusplus::bus::match::match>(
        *conn,
        rules::interfacesAdded() +
            rules::path_namespace("/xyz/openbmc_project/inventory") +
            rules::sender("xyz.openbmc_project.EntityManager"),
        [&timer, &units, bmcMode,
         bmcRole](sdbusplus::message::message& message) {
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Callback method error");
                return;
            }
            sdbusplus::message::object_path unitPath;
            std::unordered_map<std::string, ConfigurationMap> interfacesAdded;
            try
            {
                message.read(unitPath, interfacesAdded);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Message read error");
                return;
            }

            if (startedUnits.count(unitPath) != 0)
            {
                return;
            }
            for (const auto& interface : interfacesAdded)
            {
                if (interface.first != mctpTypeName)
                {
                    continue;
                }

                // Note: Interfaces may take a while to be visible.
                // Let's wait a moment, otherwise mctpd might get UnknownObject
                units.emplace_back(unitPath);
                timer.expires_after(std::chrono::seconds(1));
                timer.async_wait([&units, bmcMode, bmcRole](
                                     const boost::system::error_code& ec) {
                    if (ec == boost::asio::error::operation_aborted)
                    {
                        return;
                    }
                    if (ec)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Timer error");
                        return;
                    }
                    for (const auto& unit : units)
                    {
                        identifyAndStartUnit(unit, bmcMode, bmcRole);
                    }
                    units.clear();
                });
            }
        });

    // Install signal handler so destructors are called upon finalization
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](const boost::system::error_code&, const int&) {
        // Stop processing events
        ioc.stop();
    });

    // Process events until stop is called
    ioc.run();
    return 0;
}
