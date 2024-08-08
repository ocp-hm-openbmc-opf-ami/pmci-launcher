/**
 * Copyright © 2024 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../hw/aspeed/i3c_utils.hpp"
#include "../include/i3c_hub_detector.hpp"

#include <boost/asio.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace fs = std::filesystem;
std::string currentPath = fs::current_path().string();

using namespace hw::aspeed;
using namespace testing;

class AspeedTests : public Test
{
};

class FileReadTest : public ::testing::Test
{
  protected:
    std::string data;
};

class I3CBusMap
{
  public:
    static std::map<uint8_t, std::string> i3cBusMap;
};

std::map<uint8_t, std::string> I3CBusMap::i3cBusMap = {{1, "bus1"},
                                                       {2, "bus2"}};

class I3CBusTests : public Test
{
  protected:
    void SetUp() override
    {
        I3CBusMap::i3cBusMap.clear();
        I3CBusMap::i3cBusMap[1] = "bus1";
        I3CBusMap::i3cBusMap[2] = "bus2";
    }
};

class I3CHubTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        conn = std::make_shared<sdbusplus::asio::connection>(ioc);
        objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    }

    void TearDown() override
    {
        objectServer.reset();
        conn.reset();
        fs::remove_all("1e7a4000.i3c2");
    }

    boost::asio::io_context ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<sdbusplus::asio::object_server> objectServer;
};

TEST_F(FileReadTest, SuccessfulRead)
{
    std::ofstream("valid_path.txt") << "Hello, world!";
    readFromFile("valid_path.txt", data);
    ASSERT_EQ(data, "Hello, world!");
    std::remove("valid_path.txt");
}

TEST_F(FileReadTest, FileOpenFailure)
{
    readFromFile("invalid_path.txt", data);
    ASSERT_TRUE(data.empty());
}

TEST_F(FileReadTest, FileDoesNotExist)
{
    readFromFile("nonexistent_path.txt", data);
    ASSERT_TRUE(data.empty());
}

TEST_F(AspeedTests, ReadHubID_Success)
{
    std::ofstream("id") << "12";
    ASSERT_EQ(readHubID(currentPath), 12);
    std::remove("id");
}

TEST_F(AspeedTests, ReadTPConf_Success)
{
    std::ofstream("tp_conf") << "suuisuud";
    EXPECT_EQ(readTPConf(currentPath), "suuisuud");
    std::remove("tp_conf");
}

TEST_F(AspeedTests, ReadTPConf_ThrowsWhenEmpty)
{
    EXPECT_THROW(readTPConf(currentPath), std::runtime_error);
}

TEST_F(AspeedTests, FindRootBusNo_Success)
{
    EXPECT_EQ(
        findBusNo("1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b"), 2);
}

TEST_F(AspeedTests, FindRootBusNo_InvalidPath)
{
    EXPECT_THROW(findBusNo("1e7a4000.i3c2"), std::runtime_error);
}

TEST_F(AspeedTests, ReadRootBusName_Success)
{
    std::ofstream("name") << "3-4cd15771616.tp3";
    std::string newPath = currentPath + "/";
    EXPECT_EQ(readBusName(newPath), "tp3");
    std::remove("name");
}

TEST_F(AspeedTests, ReadRootBusName_ThrowsWhenNoSlash)
{
    EXPECT_THROW(readBusName("invalidpath"), std::runtime_error);
}

TEST_F(AspeedTests, ReadRootBusName_ThrowsWhenNoDot)
{
    std::ofstream("name") << "3-4cd15771616";
    EXPECT_THROW(readBusName(currentPath), std::runtime_error);
}

TEST_F(I3CBusTests, BusNotFoundInMap)
{
    std::string result = getI3CRootBusPath(3);
    EXPECT_TRUE(result.empty());
}

TEST_F(I3CBusTests, BusNotFoundInSysfs)
{
    std::string result = getI3CRootBusPath(1);
    EXPECT_TRUE(result.empty());
}

TEST_F(I3CBusTests, RescanI3CBus_Success)
{
    std::ofstream("rescan") << "";
    const std::string newPath = currentPath + "/";
    rescanI3CBus(newPath);

    std::string RescanPath = currentPath + "/rescan";
    std::ifstream rescanFileRead(RescanPath);
    std::string rescanData;
    std::getline(rescanFileRead, rescanData);
    rescanFileRead.close();

    ASSERT_EQ(rescanData, "1");
    std::remove("rescan");
}

TEST_F(I3CHubTest, GetHubInfoReturnsCorrectInfo)
{
    const std::string testHubPath = currentPath + "/";
    uint8_t topMostRootBusNo = 1;
    struct HubInfo result;
    std::ofstream("id") << "12";
    std::ofstream("tp_conf") << "suud";
    std::ofstream("name") << "3-4cd15771616.tp3";
    EXPECT_THROW(getHubInfo(testHubPath, topMostRootBusNo), std::runtime_error);
    std::remove("id");
    std::remove("tp_conf");
    std::remove("name");
}

TEST_F(I3CHubTest, GeneratesCorrectObjectPath)
{
    std::string dirPath =
        "1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b";
    fs::create_directories(dirPath);

    std::string filePath = "1e7a4000.i3c2/i3c-1/1-4cd092c310a/id";
    std::string filePath1 = dirPath + "/id";
    std::ofstream file(filePath);
    std::ofstream file1(filePath1);
    file << "2";
    file1 << "2";
    file.close();
    file1.close();
    std::string hubPath =
        currentPath + "/1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b";
    std::string expectedObjectPath = "/xyz/openbmc_project/I3CHub/1_2/2_2";
    std::string objectPath = generateObjectPath(hubPath);

    ASSERT_EQ(objectPath, expectedObjectPath);
}

TEST_F(I3CHubTest, RemovesHubsNotPresentInScan)
{
    std::string hubPath1 =
        currentPath + "/1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310b";
    std::string hubPath2 =
        currentPath + "/1e7a4000.i3c2/i3c-1/1-4cd092c310a/i3c-2/2-4cd092c310c";
    hubList[hubPath1] = std::make_pair(
        HubInfo{1,
                1,
                "RootBus1",
                "TPConf1",
                0,
                "PCIe1 Hub",
                {"PCIe1_Conn1", "PCIe1_Conn2", "PCIe2_Conn1", "PCIe2_Conn2",
                 "PCIe3_Conn1", "PCIe3_Conn2", "PCIe4_Conn1", "PCIe4_Conn2"}},
        std::unique_ptr<sdbusplus::asio::dbus_interface>());
    hubList[hubPath2] = std::make_pair(
        HubInfo{2,
                2,
                "RootBus2",
                "TPConf2",
                0,
                "PCIe2 Hub",
                {"PCIe9_Conn1", "PCIe9_Conn2", "PCIe10_Conn1", "PCIe10_Conn2"}},
        std::unique_ptr<sdbusplus::asio::dbus_interface>());

    checkForHubChanges(objectServer);

    ASSERT_EQ(hubList.count(hubPath1), 0);
    ASSERT_EQ(hubList.count(hubPath2), 0);
}

TEST_F(I3CHubTest, I3CHubChangesDoublecallverifyFirstTime)
{
    auto ioc = std::make_shared<boost::asio::io_context>();
    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);

    pollI3CHubChanges(ioc, objectServer);

    pollI3CHubChanges(ioc, objectServer);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
