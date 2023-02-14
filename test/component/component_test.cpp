/*
 * Wazuh urlRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "component_test.hpp"
#include "curlWrapper.hpp"
#include "factoryRequestImplemetator.hpp"
#include "urlRequest.hpp"

/**
 * @brief This class is a simple HTTP server that provides a simple interface to perform HTTP requests.
 */
class FakeServer final
{
private:
    httplib::Server m_server;
    std::thread m_thread;
    bool m_forceError;

public:
    FakeServer()
        : m_thread(&FakeServer::run, this), m_forceError(true)
    {
        // Wait until server is ready
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeServer()
    {
        m_server.stop();
        m_thread.join();
    }

    /**
     * @brief This method is used to start the server.
     */
    void run()
    {
        m_server.Get("/",
                     [](const httplib::Request& /*req*/, httplib::Response& res)
                     { res.set_content("Hello World!", "text/json"); });

        m_server.Get("/testRetry/",
                     [&](const httplib::Request& /*req*/, httplib::Response& res)
                     {
                        if (m_forceError)
                        {
                            m_forceError = false;
                            throw std::runtime_error {"Something went wrong"};
                        }
                        else
                        {
                            res.set_content("Hello World!", "text/json");
                        }
                    });

        m_server.Post(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Put(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Delete(R"(/(\d+))",
                        [](const httplib::Request& req, httplib::Response& res)
                        { res.set_content(req.matches[1], "text/json"); });

        m_server.set_keep_alive_max_count(1);
        m_server.listen("localhost", 44441);
    }
};

/**
 * @brief Test the get request.
 */
TEST_F(ComponentTestInterface, GetHelloWorld)
{
    HTTPRequest::instance().get(HttpURL("http://localhost:44441/"),
                                [&](const std::string& result)
                                {
                                    EXPECT_EQ(result, "Hello World!");
                                    m_callbackComplete = true;
                                });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the get request from an incorrect port.
 */
TEST_F(ComponentTestInterface, GetIncorrectPort)
{
    HTTPRequest::instance().get(HttpURL("http://localhost:44442/"),
                                [](auto) {},
                                [&](const std::string& result)
                                {
                                    EXPECT_EQ(result, "Couldn't connect to server");
                                    m_callbackComplete = true;
                                });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the re-try feature of the get request.
 *
 * @details The first attempt to get() should fail, and the second one should success.
 */
TEST_F(ComponentTestInterface, GetWithRetry)
{
    auto onErrorCallback {false};

    HTTPRequest::instance().get(HttpURL("http://localhost:44441/testRetry/"),
                                [&](const std::string& result)
                                {
                                    EXPECT_EQ(result, "Hello World!");
                                    m_callbackComplete = true;
                                },
                                [&](const std::string& result)
                                {
                                    // This should not be executed
                                    onErrorCallback = true;
                                });

    EXPECT_TRUE(m_callbackComplete);
    EXPECT_FALSE(onErrorCallback);
}

/**
 * @brief Test the post request.
 */
TEST_F(ComponentTestInterface, PostHelloWorld)
{
    HTTPRequest::instance().post(HttpURL("http://localhost:44441/"),
                                 R"({"hello":"world"})"_json,
                                 [&](const std::string& result)
                                 {
                                     EXPECT_EQ(result, R"({"hello":"world"})");
                                     m_callbackComplete = true;
                                 });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the update request.
 */
TEST_F(ComponentTestInterface, PutHelloWorld)
{
    HTTPRequest::instance().update(HttpURL("http://localhost:44441/"),
                                   R"({"hello":"world"})"_json,
                                   [&](const std::string& result)
                                   {
                                       EXPECT_EQ(result, R"({"hello":"world"})");
                                       m_callbackComplete = true;
                                   });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the delete request.
 */
TEST_F(ComponentTestInterface, DeleteRandomID)
{
    auto random {std::to_string(std::rand())};

    HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/" + random),
                                    [&](const std::string& result)
                                    {
                                        EXPECT_EQ(result, random);
                                        m_callbackComplete = true;
                                    });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the download request.
 */
TEST_F(ComponentTestInterface, DownloadFile)
{
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/"),
                                     "./test.txt",
                                     [&](const std::string& result) { std::cout << result << std::endl; });

    std::ifstream file("./test.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, "Hello World!");
}

/**
 * @brief Test the download request with a invalid URL.
 */
TEST_F(ComponentTestInterface, DownloadFileError)
{
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/invalid_file"),
                                     "./test.txt",
                                     [&](const std::string& result)
                                     {
                                         EXPECT_EQ(result, "HTTP response code said error");
                                         m_callbackComplete = true;
                                     });

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the get request and check the file content.
 */
TEST_F(ComponentTestInterface, GetHelloWorldFile)
{
    HTTPRequest::instance().get(
        HttpURL("http://localhost:44441/"),
        [&](const std::string& result) { std::cout << result << std::endl; },
        [](auto) {},
        "./testGetHelloWorld.txt");

    std::ifstream file("./testGetHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, "Hello World!");
}

/**
 * @brief Test the post request and check the file content.
 */
TEST_F(ComponentTestInterface, PostHelloWorldFile)
{
    HTTPRequest::instance().post(
        HttpURL("http://localhost:44441/"),
        R"({"hello":"world"})"_json,
        [&](const std::string& result) { std::cout << result << std::endl; },
        [](auto) {},
        "./testPostHelloWorld.txt");

    std::ifstream file("./testPostHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, R"({"hello":"world"})");
}

/**
 * @brief Test the update request and check the file content.
 */
TEST_F(ComponentTestInterface, PutHelloWorldFile)
{
    HTTPRequest::instance().update(
        HttpURL("http://localhost:44441/"),
        R"({"hello":"world"})"_json,
        [&](const std::string& result) { std::cout << result << std::endl; },
        [](auto) {},
        "./testPutHelloWorld.txt");

    std::ifstream file("./testPutHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, R"({"hello":"world"})");
}

/**
 * @brief Test the delete request and check the file content.
 */
TEST_F(ComponentTestInterface, DeleteRandomIDFile)
{
    auto random {std::to_string(std::rand())};

    HTTPRequest::instance().delete_(
        HttpURL("http://localhost:44441/" + random),
        [&](const std::string& result) { std::cout << result << std::endl; },
        [](auto) {},
        "./testDeleteRandomID.txt");

    std::ifstream file("./testDeleteRandomID.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, random);
}

using wrapperType = cURLWrapper;

/**
 * @brief Test the download request with a empty URL.
 */
TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create()).url("").outputFile("test.txt").execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the download request with a invalid URL.
 */
TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl2)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://")
            .outputFile("test.txt")
            .execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the get request with a invalid file.
 */
TEST_F(ComponentTestInternalParameters, GetError)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the post request with a invalid file.
 */
TEST_F(ComponentTestInternalParameters, PostError)
{
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the put request with a invalid file.
 */
TEST_F(ComponentTestInternalParameters, PutError)
{
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the delete request with a invalid file.
 */
TEST_F(ComponentTestInternalParameters, DeleteError)
{
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the get request with no url.
 */
TEST_F(ComponentTestInternalParameters, ExecuteGetNoUrl)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create()).execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the post request with no url.
 */
TEST_F(ComponentTestInternalParameters, ExecutePostNoUrl)
{
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create()).execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the put request with no url.
 */
TEST_F(ComponentTestInternalParameters, ExecutePutNoUrl)
{
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create()).execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the delete request with no url.
 */
TEST_F(ComponentTestInternalParameters, ExecuteDeleteNoUrl)
{
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create()).execute();
    }
    catch (const std::exception& ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief This test checks the behavior of multiple threads.
 * This test create multiple threads that exceed the size of the queue where each thread will create a cURLWrapper
 * object.
 */
TEST_F(ComponentTestInternalParameters, MultipleThreads)
{
    std::vector<std::thread> threads;
    for (int i = 0; i < QUEUE_SIZE * 2; ++i)
    {
        threads.emplace_back(
            []()
            {
                EXPECT_NO_THROW(GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
                                    .url("http://localhost:44441/")
                                    .execute());
            });

        EXPECT_LE(HANDLER_QUEUE.size(), QUEUE_SIZE);
    }

    for (auto& thread : threads)
    {
        EXPECT_NO_THROW(thread.join());
    }
}
