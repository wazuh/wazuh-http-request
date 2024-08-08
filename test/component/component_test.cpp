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
#include "curlHandlerCache.hpp"
#include "curlWrapper.hpp"
#include "factoryRequestImplemetator.hpp"
#include "json.hpp"
#include "urlRequest.hpp"
#include <map>
#include <string>

auto constexpr TEST_NET_IP {"192.0.2.1"};

/* Helpers */

void checkFileContent(const std::string& file, const std::string& expectedContent)
{
    if (!std::filesystem::exists(file))
    {
        FAIL() << "File does not exist: " << file;
    }

    std::ifstream fileStream(file);
    std::string line;
    std::getline(fileStream, line);
    if (fileStream.fail())
    {
        FAIL() << "Error reading file: " << file;
    }
    ASSERT_STREQ(line.c_str(), expectedContent.c_str());
}

void checkEmptyFile(const std::string& file)
{
    if (!std::filesystem::exists(file))
    {
        FAIL() << "File does not exist: " << file;
    }

    std::ifstream fileStream;
    fileStream.open(file, std::ios::binary);
    if (!fileStream.is_open())
    {
        FAIL() << "Error opening file: " << file;
    }
    fileStream.seekg(0, std::ios::end);
    auto fileSize = fileStream.tellg();
    fileStream.close();

    ASSERT_EQ(fileSize, 0) << "File is not empty: " << file;
}

/* Tests */

/**
 * @brief Test the get request.
 */
TEST_F(ComponentTestInterface, GetHelloWorld)
{
    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                       {
                                                           EXPECT_EQ(result, "Hello World!");
                                                           m_callbackComplete = true;
                                                       }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the get request with redirection.
 */
TEST_F(ComponentTestInterface, GetHelloWorldRedirection)
{
    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/redirect")},
                                PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                       {
                                                           EXPECT_EQ(result, "Hello World!");
                                                           m_callbackComplete = true;
                                                       }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the post request.
 */
TEST_F(ComponentTestInterface, PostHelloWorld)
{
    HTTPRequest::instance().post(
        RequestParameters {.url = HttpURL("http://localhost:44441/"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result)
                               {
                                   EXPECT_EQ(result, R"({"hello":"world"})");
                                   m_callbackComplete = true;
                               }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the update request.
 */
TEST_F(ComponentTestInterface, PutHelloWorld)
{
    HTTPRequest::instance().put(
        RequestParameters {.url = HttpURL("http://localhost:44441/"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result)
                               {
                                   EXPECT_EQ(result, R"({"hello":"world"})");
                                   m_callbackComplete = true;
                               }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the delete request.
 */
TEST_F(ComponentTestInterface, DeleteRandomID)
{
    auto random {std::to_string(std::rand())};

    HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL("http://localhost:44441/" + random)},
                                    PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                           {
                                                               EXPECT_EQ(result, random);
                                                               m_callbackComplete = true;
                                                           }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the download request.
 */
TEST_F(ComponentTestInterface, DownloadFile)
{
    HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                     PostRequestParameters {.outputFile = TEST_FILE_1});

    checkFileContent(TEST_FILE_1, "Hello World!");
}

/**
 * @brief Test the download request with empty URL.
 */
TEST_F(ComponentTestInterface, DownloadFileEmptyURL)
{
    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("")},
        PostRequestParameters {.onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1});
    checkEmptyFile(TEST_FILE_1);
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the download request with a invalid URL.
 */
TEST_F(ComponentTestInterface, DownloadFileError)
{
    HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/invalid_file")},
                                     PostRequestParameters {.onError =
                                                                [&](const std::string& result, const long responseCode)
                                                            {
                                                                EXPECT_EQ(result, "HTTP response code said error");
                                                                EXPECT_EQ(responseCode, 404);

                                                                m_callbackComplete = true;
                                                            },
                                                            .outputFile = TEST_FILE_1});

    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the custom download request using the single handler.
 */
TEST_F(ComponentTestInterface, DownloadFileUsingTheSingleHandler)
{
    HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                     PostRequestParameters {.outputFile = TEST_FILE_1},
                                     ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::SINGLE});

    checkFileContent(TEST_FILE_1, "Hello World!");
}

/**
 * @brief Test the custom download request using the single handler with empty URL.
 */
TEST_F(ComponentTestInterface, DownloadFileEmptyURLUsingTheSingleHandler)
{
    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("")},
        PostRequestParameters {.onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1},
        ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::SINGLE});

    checkEmptyFile(TEST_FILE_1);
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the custom download request using the single handler with a invalid URL.
 */
TEST_F(ComponentTestInterface, DownloadFileErrorUsingTheSingleHandler)
{
    HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/invalid_file")},
                                     PostRequestParameters {.onError =
                                                                [&](const std::string& result, const long responseCode)
                                                            {
                                                                EXPECT_EQ(result, "HTTP response code said error");
                                                                EXPECT_EQ(responseCode, 404);

                                                                m_callbackComplete = true;
                                                            },
                                                            .outputFile = TEST_FILE_1},
                                     ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::SINGLE});

    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the custom download request using the multi handler.
 */
TEST_F(ComponentTestInterface, DownloadFileUsingTheMultiHandler)
{
    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("http://localhost:44441/")},
        PostRequestParameters {.outputFile = TEST_FILE_1},
        ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});

    checkFileContent(TEST_FILE_1, "Hello World!");
}

/**
 * @brief Test the custom download request using the multi handler and interrupt the handler.
 */
TEST_F(ComponentTestInterface, InterruptMultiHandler)
{
    m_shouldRun.store(false);

    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("http://localhost:44441/")},
        PostRequestParameters {.outputFile = TEST_FILE_1},
        ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});

    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test two instances of the custom download request using the multi handler and interrupt the handler.
 *
 */
TEST_F(ComponentTestInterface, InterruptDownload)
{
    auto sleepFirstHandler {std::to_string(10)};
    auto sleepSecondHandler {std::to_string(40)};
    auto intervalToInterruptTheHandler {20};

    std::thread thread1(
        [&]()
        {
            HTTPRequest::instance().download(
                RequestParameters {.url = HttpURL("http://localhost:44441/sleep/" + sleepFirstHandler)},
                PostRequestParameters {.outputFile = TEST_FILE_1},
                ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
        });

    std::thread thread2(
        [&]()
        {
            HTTPRequest::instance().download(
                RequestParameters {.url = HttpURL("http://localhost:44441/sleep/" + sleepSecondHandler)},
                PostRequestParameters {.outputFile = TEST_FILE_2},
                ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
        });

    // Sleep interval to interrupt the second handler.
    std::this_thread::sleep_for(std::chrono::milliseconds(intervalToInterruptTheHandler));
    m_shouldRun.store(false);

    thread1.join();
    thread2.join();

    checkFileContent(TEST_FILE_1, "Hello World!");
    // As the second thread was interrupted, there is no response from the endpoint 'sleep'
    checkEmptyFile(TEST_FILE_2);
}

/**
 * @brief Test the custom download request using the multi handler with empty URL.
 */
TEST_F(ComponentTestInterface, DownloadFileEmptyURLUsingTheMultiHandler)
{
    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("")},
        PostRequestParameters {
            .onError =
                [&](const std::string& result, const long responseCode)
            {
                EXPECT_EQ(result, "cURLMultiHandler::execute() failed: URL using bad/illegal format or missing URL");
                EXPECT_EQ(responseCode, 3);

                m_callbackComplete = true;
            },
            .outputFile = TEST_FILE_1},
        ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});

    checkEmptyFile(TEST_FILE_1);
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the custom download request using the multi handler with a invalid URL.
 */
TEST_F(ComponentTestInterface, DownloadFileErrorUsingTheMultiHandler)
{
    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("http://localhost:44441/invalid_file")},
        PostRequestParameters {.onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result,
                                             "cURLMultiHandler::execute() failed: HTTP response code said error");
                                   EXPECT_EQ(responseCode, 22);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1},
        ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});

    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the get request and check the file content.
 */
TEST_F(ComponentTestInterface, GetHelloWorldFile)
{
    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                PostRequestParameters {.outputFile = TEST_FILE_1});

    checkFileContent(TEST_FILE_1, "Hello World!");
}

/**
 * @brief Test the get request with empty URL.
 */
TEST_F(ComponentTestInterface, GetHelloWorldFileEmptyURL)
{
    HTTPRequest::instance().get(
        RequestParameters {.url = HttpURL("")},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1});

    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the post request and check the file content.
 */
TEST_F(ComponentTestInterface, PostHelloWorldFile)
{
    HTTPRequest::instance().post(
        RequestParameters {.url = HttpURL("http://localhost:44441/"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .outputFile = TEST_FILE_1});

    checkFileContent(TEST_FILE_1, R"({"hello":"world"})");
}

/**
 * @brief Test the post request with empty URL.
 */
TEST_F(ComponentTestInterface, PostHelloWorldFileEmptyURL)
{
    HTTPRequest::instance().post(
        RequestParameters {.url = HttpURL(""), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1});

    checkEmptyFile(TEST_FILE_1);
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the update request and check the file content.
 */
TEST_F(ComponentTestInterface, PutHelloWorldFile)
{
    HTTPRequest::instance().put(
        RequestParameters {.url = HttpURL("http://localhost:44441/"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .outputFile = TEST_FILE_1});

    checkFileContent(TEST_FILE_1, R"({"hello":"world"})");
}

/**
 * @brief Test the update request and check the file content.
 */
TEST_F(ComponentTestInterface, PutHelloWorldFileEmptyURL)
{
    HTTPRequest::instance().put(
        RequestParameters {.url = HttpURL(""), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1});

    checkEmptyFile(TEST_FILE_1);
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the delete request and check the file content.
 */
TEST_F(ComponentTestInterface, DeleteRandomIDFile)
{
    auto random {std::to_string(std::rand())};

    HTTPRequest::instance().delete_(
        RequestParameters {.url = HttpURL("http://localhost:44441/" + random)},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .outputFile = TEST_FILE_1});

    checkFileContent(TEST_FILE_1, random);
}

/**
 * @brief Test the delete request with empty URL.
 */
TEST_F(ComponentTestInterface, DeleteRandomIDFileEmptyURL)
{
    HTTPRequest::instance().delete_(
        RequestParameters {.url = HttpURL("")},
        PostRequestParameters {.onSuccess = [&](const std::string& result) { std::cout << result << std::endl; },
                               .onError =
                                   [&](const std::string& result, const long responseCode)
                               {
                                   EXPECT_EQ(result, "URL using bad/illegal format or missing URL");
                                   EXPECT_EQ(responseCode, -1);

                                   m_callbackComplete = true;
                               },
                               .outputFile = TEST_FILE_1});

    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

using wrapperType = cURLWrapper;

/**
 * @brief Test the download request with a empty URL.
 */
TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create()).url("").outputFile(TEST_FILE_1).execute();
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
            .outputFile(TEST_FILE_1)
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
            .postData(R"({"hello":"world"})")
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
            .postData(R"({"hello":"world"})")
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
    const auto testTime {2};
    std::atomic<bool> stopTest {false};
    std::vector<std::thread> threads;
    for (int i = 0; i < QUEUE_MAX_SIZE * 2; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                do
                {
                    EXPECT_NO_THROW({
                        auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())};
                        req.url("http://localhost:44441/").execute();

                        EXPECT_STREQ(req.response().c_str(), "Hello World!");
                    });
                } while (!stopTest.load());
            });

        EXPECT_LE(cURLHandlerCache::instance().size(), QUEUE_MAX_SIZE);
    }

    std::this_thread::sleep_for(std::chrono::seconds(testTime));
    stopTest.store(true);
    for (auto& thread : threads)
    {
        EXPECT_NO_THROW(thread.join());
    }
}

/**
 * @brief This test checks the behavior of multiple threads for multi handler.
 * This test create multiple threads that exceed the size of the queue where each thread will create a cURLWrapper
 * object.
 */
TEST_F(ComponentTestInternalParameters, MultipleThreadsWithMultiHandlers)
{
    const auto testTime {2};
    std::atomic<bool> stopTest {false};
    std::vector<std::thread> threads;

    for (int i = 0; i < QUEUE_MAX_SIZE * 2; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                do
                {
                    EXPECT_NO_THROW({
                        auto req {GetRequest::builder(
                            FactoryRequestWrapper<wrapperType>::create(CurlHandlerTypeEnum::MULTI, m_shouldRun))};
                        req.url("http://localhost:44441/").execute();

                        EXPECT_STREQ(req.response().c_str(), "Hello World!");
                    });
                } while (!stopTest.load());
            });

        EXPECT_LE(cURLHandlerCache::instance().size(), QUEUE_MAX_SIZE);
    }

    std::this_thread::sleep_for(std::chrono::seconds(testTime));
    stopTest.store(true);
    for (auto& thread : threads)
    {
        EXPECT_NO_THROW(thread.join());
    }
}

/**
 * @brief Test the GET request appending a custom HTTP header. The header is expected to be on the server response.
 *
 */
TEST_F(ComponentTestInterface, GetWithCustomHeader)
{
    const std::string headerKey {"Custom-Key"};
    const std::string headerValue {"Custom-Value"};

    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"),
                                                   .httpHeaders = {headerKey + ":" + headerValue}},
                                PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                       {
                                                           ASSERT_EQ(nlohmann::json::parse(result).at(headerKey),
                                                                     headerValue);
                                                           m_callbackComplete = true;
                                                       }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the GET request without custom HTTP headers. The expected headers are the default ones.
 *
 */
TEST_F(ComponentTestInterface, GetWithDefaultHeaders)
{
    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/check-headers")},
                                PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                       {
                                                           const std::map<std::string, std::string> defaultHeaders = {
                                                               {"Content-Type", "application/json"},
                                                               {"Accept", "application/json"},
                                                               {"Accept-Charset", "utf-8"}};
                                                           const auto response = nlohmann::json::parse(result);

                                                           ASSERT_FALSE(response.empty());
                                                           for (const auto& [headerKey, headerValue] : defaultHeaders)
                                                           {
                                                               ASSERT_EQ(response.at(headerKey), headerValue);
                                                           }

                                                           m_callbackComplete = true;
                                                       }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the POST request appending two custom HTTP headers. The headers are expected to be on the server
 * response.
 *
 */
TEST_F(ComponentTestInterface, PostWithCustomHeaders)
{
    const std::string headerKeyA {"Custom-Key-A"};
    const std::string headerValueA {"Custom-Value-A"};
    const std::string headerKeyB {"Custom-Key-B"};
    const std::string headerValueB {"Custom-Value-B"};

    HTTPRequest::instance().post(
        RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"),
                           .httpHeaders = {headerKeyA + ":" + headerValueA, headerKeyB + ":" + headerValueB}},
        PostRequestParameters {.onSuccess = [&](const std::string& result)
                               {
                                   const auto response = nlohmann::json::parse(result);

                                   ASSERT_EQ(response.at(headerKeyA), headerValueA);
                                   ASSERT_EQ(response.at(headerKeyB), headerValueB);
                                   m_callbackComplete = true;
                               }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PUT request appending two equal custom HTTP headers. Because headers are inserted in a set (as
 * unique values), just one header is expected to be on the server response.
 *
 */
TEST_F(ComponentTestInterface, PutWithCustomHeaders)
{
    const std::string headerKey {"Custom-Key"};
    const std::string headerValue {"Custom-Value"};

    HTTPRequest::instance().put(
        RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"),
                           .httpHeaders = {headerKey + ":" + headerValue, headerKey + ":" + headerValue}},
        PostRequestParameters {.onSuccess = [&](const std::string& result)
                               {
                                   ASSERT_EQ(nlohmann::json::parse(result).at(headerKey), headerValue);
                                   m_callbackComplete = true;
                               }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the basic functionality of a PATCH request.
 *
 */
TEST_F(ComponentTestInterface, PatchSimpleFunctionality)
{
    const auto postData = R"({"hello":"world"})"_json;

    auto expectedResponse = R"(
        {
            "query": "patch"
        }
    )"_json;
    expectedResponse["payload"] = postData;

    HTTPRequest::instance().patch(RequestParameters {.url = HttpURL("http://localhost:44441/"), .data = postData},
                                  PostRequestParameters {.onSuccess = [&](const std::string& result)
                                                         {
                                                             EXPECT_EQ(nlohmann::json::parse(result), expectedResponse);
                                                             m_callbackComplete = true;
                                                         }});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the DOWNLOAD request setting a custom user-agent.
 */
TEST_F(ComponentTestInterface, DownloadWithCustomUserAgent)
{
    const std::string userAgent {"Custom-User-Agent"};

    HTTPRequest::instance().download(
        RequestParameters {.url = HttpURL("http://localhost:44441/"), .httpHeaders = DEFAULT_HEADERS},
        PostRequestParameters {.outputFile = TEST_FILE_1},
        ConfigurationParameters {.userAgent = userAgent});

    checkFileContent(TEST_FILE_1, "Hello World!");
}

/**
 * @brief Test the POST request setting a custom user-agent.
 */
TEST_F(ComponentTestInterface, PostWithCustomUserAgent)
{
    const std::string headerKey {"User-Agent"};
    const std::string userAgentValue {"Custom-User-Agent"};

    HTTPRequest::instance().post(
        RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess =
                                   [&](const std::string& result)
                               {
                                   ASSERT_EQ(nlohmann::json::parse(result).at(headerKey), userAgentValue);
                                   m_callbackComplete = true;
                               }},
        ConfigurationParameters {.userAgent = userAgentValue});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the GET request setting a custom user-agent.
 *
 */
TEST_F(ComponentTestInterface, GetWithCustomUserAgent)
{
    const std::string headerKey {"User-Agent"};
    const std::string userAgentValue {"Custom-User-Agent"};

    HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/check-headers")},
                                PostRequestParameters {.onSuccess =
                                                           [&](const std::string& result)
                                                       {
                                                           ASSERT_EQ(nlohmann::json::parse(result).at(headerKey),
                                                                     userAgentValue);
                                                           m_callbackComplete = true;
                                                       }},
                                ConfigurationParameters {.userAgent = userAgentValue});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PUT request setting a custom user-agent.
 *
 */
TEST_F(ComponentTestInterface, PutWithCustomUserAgent)
{
    const std::string headerKey {"User-Agent"};
    const std::string userAgentValue {"Custom-User-Agent"};

    HTTPRequest::instance().put(
        RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess =
                                   [&](const std::string& result)
                               {
                                   ASSERT_EQ(nlohmann::json::parse(result).at(headerKey), userAgentValue);
                                   m_callbackComplete = true;
                               }},
        ConfigurationParameters {.userAgent = userAgentValue});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PATCH request setting a custom user-agent.
 *
 */
TEST_F(ComponentTestInterface, PatchWithCustomUserAgent)
{
    const std::string headerKey {"User-Agent"};
    const std::string userAgentValue {"Custom-User-Agent"};

    HTTPRequest::instance().patch(
        RequestParameters {.url = HttpURL("http://localhost:44441/check-headers"), .data = R"({"hello":"world"})"_json},
        PostRequestParameters {.onSuccess =
                                   [&](const std::string& result)
                               {
                                   ASSERT_EQ(nlohmann::json::parse(result).at(headerKey), userAgentValue);
                                   m_callbackComplete = true;
                               }},
        ConfigurationParameters {.userAgent = userAgentValue});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the DELETE request setting a custom user-agent.
 *
 */
TEST_F(ComponentTestInterface, DeleteWithCustomUserAgent)
{
    const std::string headerKey {"User-Agent"};
    const std::string userAgentValue {"Custom-User-Agent"};

    HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL("http://localhost:44441/check-headers")},
                                    PostRequestParameters {.onSuccess =
                                                               [&](const std::string& result)
                                                           {
                                                               ASSERT_EQ(nlohmann::json::parse(result).at(headerKey),
                                                                         userAgentValue);
                                                               m_callbackComplete = true;
                                                           }},
                                    ConfigurationParameters {.userAgent = userAgentValue});

    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the DOWNLOAD request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, DownloadTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().download(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                         PostRequestParameters {.outputFile = TEST_FILE_1},
                                         ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().download(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   },
                                   .outputFile = TEST_FILE_1},
            ConfigurationParameters {.timeout = 10});
    });

    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the DOWNLOAD request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, DownloadTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().download(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                         PostRequestParameters {.outputFile = TEST_FILE_1},
                                         ConfigurationParameters {.timeout = 10,
                                                                  .handlerType = CurlHandlerTypeEnum::MULTI,
                                                                  .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().download(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   },
                                   .outputFile = TEST_FILE_1},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the GET request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, GetTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().get(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                    PostRequestParameters {.outputFile = TEST_FILE_1},
                                    ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().get(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   },
                                   .outputFile = TEST_FILE_1},
            ConfigurationParameters {.timeout = 10});
    });
    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the GET request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, GetTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().get(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                    PostRequestParameters {.outputFile = TEST_FILE_1},
                                    ConfigurationParameters {.timeout = 10,
                                                             .handlerType = CurlHandlerTypeEnum::MULTI,
                                                             .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().get(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   },
                                   .outputFile = TEST_FILE_1},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
    checkEmptyFile(TEST_FILE_1);
}

/**
 * @brief Test the PUT request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, PutTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().put(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                    PostRequestParameters {},
                                    ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().put(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {.timeout = 10});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PUT request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, PutTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().put(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                    PostRequestParameters {},
                                    ConfigurationParameters {.timeout = 10,
                                                             .handlerType = CurlHandlerTypeEnum::MULTI,
                                                             .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().put(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PATCH request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, PatchTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().patch(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                      PostRequestParameters {},
                                      ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().patch(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {.timeout = 10});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the PATCH request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, PatchTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().patch(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                      PostRequestParameters {},
                                      ConfigurationParameters {.timeout = 10,
                                                               .handlerType = CurlHandlerTypeEnum::MULTI,
                                                               .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().patch(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the DELETE request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, DeleteTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                        PostRequestParameters {},
                                        ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().delete_(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {.timeout = 10});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the DELETE request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, DeleteTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL(TEST_NET_IP)},
                                        PostRequestParameters {},
                                        ConfigurationParameters {.timeout = 10,
                                                                 .handlerType = CurlHandlerTypeEnum::MULTI,
                                                                 .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().delete_(
            RequestParameters {.url = HttpURL(TEST_NET_IP)},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the POST request with timeout for SINGLE handler.
 *
 */
TEST_F(ComponentTestInterface, PostTestTimeoutSingleHandler)
{
    try
    {
        HTTPRequest::instance().post(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                     PostRequestParameters {},
                                     ConfigurationParameters {.timeout = 10});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {.timeout = 10});
    });
    EXPECT_TRUE(m_callbackComplete);
}

/**
 * @brief Test the POST request with timeout for MULTI handler.
 *
 */
TEST_F(ComponentTestInterface, PostTestTimeoutMultiHandler)
{
    try
    {
        HTTPRequest::instance().post(RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
                                     PostRequestParameters {},
                                     ConfigurationParameters {.timeout = 10,
                                                              .handlerType = CurlHandlerTypeEnum::MULTI,
                                                              .shouldRun = m_shouldRun});
        FAIL() << "Expected exception, but no exception was thrown.";
    }
    catch (const std::exception& e)
    {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("Timeout was reached"))
            << std::string("A different exception was thrown: ") + e.what();
    }

    EXPECT_NO_THROW({
        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(TEST_NET_IP), .data = "{}"_json},
            PostRequestParameters {.onError =
                                       [&](const std::string& result, const long _)
                                   {
                                       EXPECT_NE(std::string::npos, result.find("Timeout was reached")) << result;
                                       m_callbackComplete = true;
                                   }},
            ConfigurationParameters {
                .timeout = 10, .handlerType = CurlHandlerTypeEnum::MULTI, .shouldRun = m_shouldRun});
    });
    EXPECT_TRUE(m_callbackComplete);
}
