/*
 * Wazuh urlRequest test component
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#include "httplib.h"
#pragma GCC diagnostic pop

#include "HTTPRequest.hpp"
#include "benchmark.h"
#include <iostream>

/**
 * @brief This class is a simple HTTP server that provides a simple interface to perform HTTP requests.
 */
namespace
{
class FakeServer final
{
private:
    httplib::Server m_server;
    std::thread m_thread;

public:
    FakeServer()
        : m_thread(&FakeServer::run, this)
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

        m_server.Post(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Put(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Patch(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Delete(R"(/(\d+))",
                        [](const httplib::Request& req, httplib::Response& res)
                        { res.set_content(req.matches[1], "text/json"); });

        m_server.set_keep_alive_max_count(1);
        m_server.listen("localhost", 44441);
    }
};
} // namespace

FakeServer g_server;

/**
 * @brief This function is a benchmark test for the HTTP GET request.
 *
 * @param state Benchmark state.
 */
static void BM_Get(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().get(RequestParameters {.url = HttpURL("http://localhost:44441/")});
    }
}
BENCHMARK(BM_Get);

/**
 * @brief This function is a benchmark test for the HTTP POST request.
 *
 * @param state Benchmark state.
 */
static void BM_Post(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().post(
            RequestParametersJson {.url = HttpURL("http://localhost:44441/"), .data = R"({"foo": "bar"})"_json});
    }
}
BENCHMARK(BM_Post);

/**
 * @brief This function is a benchmark test for the HTTP UPDATE request.
 *
 * @param state Benchmark state.
 */
static void BM_Update(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().put(
            RequestParametersJson {.url = HttpURL("http://localhost:44441/"), .data = R"({"foo": "bar"})"_json});
    }
}
BENCHMARK(BM_Update);

/**
 * @brief This function is a benchmark test for the HTTP PATCH request.
 *
 * @param state Benchmark state.
 */
static void BM_Patch(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().patch(
            RequestParametersJson {.url = HttpURL("http://localhost:44441/"), .data = R"({"foo": "bar"})"_json});
    }
}
BENCHMARK(BM_Patch);

/**
 * @brief This function is a benchmark test for the HTTP DELETE request.
 *
 * @param state Benchmark state.
 */
static void BM_Delete(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL("http://localhost:44441/12345")});
    }
}

BENCHMARK(BM_Delete);

/**
 * @brief This function is a benchmark test for the HTTP DOWNLOAD request.
 *
 * @param state Benchmark state.
 */
static void BM_Download(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                         PostRequestParameters {.outputFile = "out.txt"});
    }
}
BENCHMARK(BM_Download);

/**
 * @brief This function is a benchmark test for the HTTP DOWNLOAD request using the single handler.
 *
 * @param state Benchmark state.
 */
static void BM_DownloadUsingTheSingleHandler(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                         PostRequestParameters {.outputFile = "out.txt"},
                                         ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::SINGLE});
    }
}
BENCHMARK(BM_DownloadUsingTheSingleHandler);

/**
 * @brief This function is a benchmark test for the HTTP DOWNLOAD request using the multi handler.
 *
 * @param state Benchmark state.
 */
static void BM_CustomDownloadUsingTheMultiHandler(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().download(RequestParameters {.url = HttpURL("http://localhost:44441/")},
                                         PostRequestParameters {.outputFile = "out.txt"},
                                         ConfigurationParameters {.handlerType = CurlHandlerTypeEnum::MULTI});
    }
}
BENCHMARK(BM_CustomDownloadUsingTheMultiHandler);

static void BM_ReturnStringByValue(benchmark::State& state)
{
    SecureCommunication secureComm;
    secureComm.sslCertificate("path/to/certificate");

    for (auto _ : state)
    {
        std::string result = secureComm.getParameter(AuthenticationParameter::SSL_CERTIFICATE);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ReturnStringByValue);

BENCHMARK_MAIN();
