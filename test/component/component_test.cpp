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

class EchoServer
{
    public:
        EchoServer()
        {
            std::thread t([&]()
            {
                httplib::Server server;

                server.Get("/", [](const httplib::Request& /*req*/, httplib::Response& res) {
                    res.set_content("Hello World!", "text/json");
                });

                server.Post("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Put("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Delete(R"(/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.matches[1], "text/json");
                });

                server.listen("localhost", 44441);
            });
            t.detach();
        }
};

EchoServer server;

TEST_F(ComponentTestInterface, GetHelloWorld)
{
    HTTPRequest::instance().get(HttpURL("http://localhost:44441/"),
                                [&](const std::string &result)
    {
        EXPECT_EQ(result, "Hello World!");
        m_callbackComplete = true;
    });

    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInterface, PostHelloWorld)
{
    HTTPRequest::instance().post(HttpURL("http://localhost:44441/"),
                                 R"({"hello":"world"})"_json,
                                 [&](const std::string &result)
    {
        EXPECT_EQ(result, R"({"hello":"world"})");
        m_callbackComplete = true;
    });

    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInterface, PutHelloWorld)
{
    HTTPRequest::instance().update(HttpURL("http://localhost:44441/"),
                                   R"({"hello":"world"})"_json,
                                   [&](const std::string &result)
    {
        EXPECT_EQ(result, R"({"hello":"world"})");
        m_callbackComplete = true;
    });

    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInterface, DeleteRandomID)
{
    auto random { std::to_string(std::rand()) };

    HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/"+random),
                                    [&](const std::string &result)
    {
        EXPECT_EQ(result, random);
        m_callbackComplete = true;
    });

    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInterface, DownloadFile)
{
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/"),
                                     "./test.txt",
                                     [&](const std::string &result)
    {
        std::cout << result << std::endl;
    });

    std::ifstream file("./test.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, "Hello World!");
}

TEST_F(ComponentTestInterface, DownloadFileError)
{
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/invalid_file"),
                                     "./test.txt",
                                     [&](const std::string &result)
    {
        EXPECT_EQ(result, "HTTP response code said error");
        m_callbackComplete = true;
    });

    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInterface, GetHelloWorldFile)
{
    HTTPRequest::instance().get(HttpURL("http://localhost:44441/"),
                                [&](const std::string &result)
    {
        std::cout << result << std::endl;
    }, [](auto){}, "./testGetHelloWorld.txt");

    std::ifstream file("./testGetHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, "Hello World!");
}

TEST_F(ComponentTestInterface, PostHelloWorldFile)
{
    HTTPRequest::instance().post(HttpURL("http://localhost:44441/"),
                                 R"({"hello":"world"})"_json,
                                 [&](const std::string &result)
    {
        std::cout << result << std::endl;
    }, [](auto){}, "./testPostHelloWorld.txt");

    std::ifstream file("./testPostHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, R"({"hello":"world"})");
}

TEST_F(ComponentTestInterface, PutHelloWorldFile)
{
    HTTPRequest::instance().update(HttpURL("http://localhost:44441/"),
                                   R"({"hello":"world"})"_json,
                                   [&](const std::string &result)
    {
        std::cout << result << std::endl;
    }, [](auto){}, "./testPutHelloWorld.txt");

    std::ifstream file("./testPutHelloWorld.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, R"({"hello":"world"})");
}

TEST_F(ComponentTestInterface, DeleteRandomIDFile)
{
    auto random { std::to_string(std::rand()) };

    HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/"+random),
                                    [&](const std::string &result)
    {
        std::cout << result << std::endl;
    }, [](auto){}, "./testDeleteRandomID.txt");

    std::ifstream file("./testDeleteRandomID.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, random);
}

using wrapperType = cURLWrapper;

TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("")
            .outputFile("test.txt")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl2)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://")
            .outputFile("test.txt")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, GetError)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, PostError)
{
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, PutError)
{
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, DeleteError)
{
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecuteGetNoUrl)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecutePostNoUrl)
{
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecutePutNoUrl)
{
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecuteDeleteNoUrl)
{
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        m_callbackComplete = true;
    }
    EXPECT_TRUE(m_callbackComplete);
}

