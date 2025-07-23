/*
 * Wazuh URLRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMPONENT_TEST_H
#define _COMPONENT_TEST_H

#include "IURLRequest.hpp"
#include "curlHandlerCache.hpp"
#include "json.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

auto constexpr TEST_FILE_1 {"test1.txt"};
auto constexpr TEST_FILE_2 {"test2.txt"};
auto constexpr SERVER_PID_FILE {"fake_server.pid"};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#include "httplib.h"
#pragma GCC diagnostic pop

#include "HTTPRequest.hpp"

/**
 * @brief This class is a simple HTTP server that provides a simple interface to perform HTTP requests.
 * The server runs in a separate process using fork() to avoid memory fragmentation issues.
 */
namespace
{
class FakeServer final
{
private:
    pid_t m_server_pid;
    bool m_is_running;

public:
    FakeServer()
        : m_server_pid(-1)
        , m_is_running(false)
    {
        startServer();
    }

    ~FakeServer()
    {
        stopServer();
    }

    /**
     * @brief Start the server in a separate process
     */
    void startServer()
    {
        m_server_pid = fork();

        if (m_server_pid == 0)
        {
            // Child process - run the server
            runServer();
            exit(0);
        }
        else if (m_server_pid > 0)
        {
            // Parent process - wait for server to be ready
            waitForServerReady();
            m_is_running = true;
        }
        else
        {
            // Fork failed
            throw std::runtime_error("Failed to fork server process");
        }
    }

    /**
     * @brief Stop the server process
     */
    void stopServer()
    {
        if (m_server_pid > 0 && m_is_running)
        {
            kill(m_server_pid, SIGTERM);

            // Wait for the process to terminate
            int status;
            waitpid(m_server_pid, &status, 0);

            // Clean up PID file
            std::filesystem::remove(SERVER_PID_FILE);

            m_is_running = false;
            m_server_pid = -1;
        }
    }

    /**
     * @brief Check if server is running
     */
    bool isRunning() const
    {
        return m_is_running && m_server_pid > 0;
    }

private:
    /**
     * @brief Wait for the server to be ready by checking if it's listening on the port
     */
    void waitForServerReady()
    {
        const int max_attempts = 100;
        int attempts = 0;

        httplib::Client client("localhost", 44441);
        client.set_connection_timeout(1); // 1 second timeout

        while (attempts < max_attempts)
        {
            auto result = client.Get("/");
            if (result && result->status == 200)
            {
                break; // Server is ready
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            attempts++;
        }

        if (attempts >= max_attempts)
        {
            throw std::runtime_error("Server failed to start within timeout");
        }
    }

    /**
     * @brief This method runs the server in the child process
     */
    void runServer()
    {
        // Write PID to file for cleanup
        std::ofstream pid_file(SERVER_PID_FILE);
        if (pid_file.is_open())
        {
            pid_file << getpid();
            pid_file.close();
        }

        httplib::Server server;

        // Lambda that returns a JSON holding all headers within a request.
        // For example, if the request has the headers "Key-1: Value-1" and "Key-2: Value-2",
        // this lambda will return the JSON '{"Key-1":"Value-1","Key-2":"Value-2"}'.
        const auto getHttpHeaders = [](const httplib::Request& req)
        {
            nlohmann::json httpHeaders;
            std::for_each(req.headers.begin(),
                          req.headers.end(),
                          [&httpHeaders](const auto& header) { httpHeaders[header.first] = header.second; });
            return httpHeaders;
        };

        server.Get("/",
                   [](const httplib::Request& /*req*/, httplib::Response& res)
                   { res.set_content("Hello World!", "text/json"); });

        server.Get("/redirect",
                   [](const httplib::Request& /*req*/, httplib::Response& res)
                   { res.set_redirect("http://localhost:44441/", 301); });

        server.Get("/check-headers",
                   [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                   { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        server.Post(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        server.Post("/check-headers",
                    [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                    { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        server.Put("/",
                   [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        server.Put("/check-headers",
                   [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                   { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        server.Patch("/",
                     [](const httplib::Request& req, httplib::Response& res)
                     {
                         nlohmann::json response;
                         response["query"] = "patch";
                         response["payload"] = nlohmann::json::parse(req.body);

                         res.set_content(response.dump(), "text/json");
                     });

        server.Patch("/check-headers",
                     [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                     { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        // This endpoint helps simulate the waiting time during an HTTP request.
        server.Get(R"(/sleep/(\d+))",
                   [](const httplib::Request& req, httplib::Response& res)
                   {
                       auto sleepInterval = std::stoi(req.matches[1]);
                       std::this_thread::sleep_for(std::chrono::milliseconds(sleepInterval));
                       res.set_content("Hello World!", "text/json");
                   });

        server.Get("/check-headers",
                   [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                   { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        server.Delete(R"(/(\d+))",
                      [](const httplib::Request& req, httplib::Response& res)
                      { res.set_content(req.matches[1], "text/json"); });

        server.Delete("/check-headers",
                      [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                      { res.set_content(getHttpHeaders(req).dump(), "text/json"); });

        server.set_keep_alive_max_count(1);
        server.listen("localhost", 44441);
    }
};
} // namespace

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTest : public ::testing::Test
{
protected:
    /**
     * @brief This variable is used as a flag to indicate if all the callbacks have been called.
     */
    bool m_callbackComplete = false;

    /**
     * @brief This variable is used as a flag to indicate if the test should run.
     */
    std::atomic<bool> m_shouldRun {true};

    virtual ~ComponentTest() = default;
    /**
     * @brief This method is called before each test to initialize the test environment.
     */

    void SetUp() override
    {
        fakeFileServer.reset(new FakeServer());
        m_callbackComplete = false;
        m_shouldRun.store(true);
    }

    /**
     * @brief This method removes the testing files after each test execution.
     *
     */
    void TearDown() override
    {
        m_shouldRun.store(false);
        std::filesystem::remove(TEST_FILE_1);
        std::filesystem::remove(TEST_FILE_2);
        cURLHandlerCache::instance().clear();
    }

    /**
     * @brief This variable is used to store the server instance.
     */
    inline static std::unique_ptr<FakeServer> fakeFileServer;
};

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTestInterface : public ComponentTest
{
protected:
    ComponentTestInterface() = default;
    virtual ~ComponentTestInterface() = default;
};

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTestInternalParameters : public ComponentTest
{
protected:
    ComponentTestInternalParameters() = default;
    virtual ~ComponentTestInternalParameters() = default;
};

#endif // _COMPONENT_TEST_H
