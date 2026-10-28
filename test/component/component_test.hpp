/*
 * Wazuh URLRequest test component
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _COMPONENT_TEST_H
#define _COMPONENT_TEST_H

#include "IURLRequest.hpp"
#include "curlHandlerCache.hpp"
#include "json.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <zlib.h>

auto constexpr TEST_FILE_1 {"test1.txt"};
auto constexpr TEST_FILE_2 {"test2.txt"};
auto constexpr SERVER_PID_FILE {"fake_server.pid"};
constexpr std::size_t LARGE_BODY_SIZE {4 * 1024 * 1024};

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
/**
 * @brief Compresses the input in gzip format.
 */
std::string gzipCompress(const std::string& input)
{
    z_stream stream {};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw std::runtime_error("deflateInit2 failed");
    }

    std::string output(deflateBound(&stream, input.size()), '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());

    const auto result {deflate(&stream, Z_FINISH)};
    output.resize(stream.total_out);
    deflateEnd(&stream);

    if (result != Z_STREAM_END)
    {
        throw std::runtime_error("deflate failed");
    }
    return output;
}

/**
 * @brief Decompresses a gzip payload.
 */
std::string gunzip(const std::string& input)
{
    z_stream stream {};
    if (inflateInit2(&stream, 15 + 16) != Z_OK)
    {
        throw std::runtime_error("inflateInit2 failed");
    }

    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());

    std::string output;
    char buffer[4096];
    int result {Z_OK};
    while (result == Z_OK)
    {
        stream.next_out = reinterpret_cast<Bytef*>(buffer);
        stream.avail_out = sizeof(buffer);
        result = inflate(&stream, Z_NO_FLUSH);
        output.append(buffer, sizeof(buffer) - stream.avail_out);
    }
    inflateEnd(&stream);

    if (result != Z_STREAM_END)
    {
        throw std::runtime_error("inflate failed");
    }
    return output;
}

/**
 * @brief Plain text behind BROTLI_FIXTURE_BYTES.
 */
const std::string BROTLI_FIXTURE_TEXT {
    "The quick brown fox jumps over the lazy dog, compressed with Brotli for the http-request component test."};

/**
 * @brief BROTLI_FIXTURE_TEXT compressed with Brotli (quality 11).
 */
const std::vector<unsigned char> BROTLI_FIXTURE_BYTES {
    0xa1, 0x38, 0x03, 0x40, 0x64, 0xa4, 0x5c, 0x2d, 0x67, 0x0b, 0x2a, 0xcb, 0x5b, 0xaa, 0xb7, 0xfe,
    0x94, 0x20, 0x55, 0xbc, 0xb7, 0xb1, 0x33, 0x2e, 0xd0, 0xc9, 0x81, 0xc3, 0xb7, 0x7f, 0x3f, 0x48,
    0x5e, 0x1c, 0x58, 0x81, 0x13, 0x0e, 0x22, 0xc9, 0x06, 0x81, 0x14, 0xd8, 0xe1, 0x13, 0x1d, 0x1c,
    0x9a, 0xa8, 0x9d, 0x1f, 0x09, 0xf5, 0x00, 0xf0, 0xac, 0xea, 0x47, 0xe3, 0x30, 0x54, 0xee, 0xbf,
    0x75, 0x6e, 0xb9, 0xd4, 0x9a, 0x70, 0x9a, 0x1b, 0xd2, 0x49, 0xa4, 0x96, 0xca, 0x52, 0x32};

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

        server.Delete("/check-headers-and-body",
                      [&getHttpHeaders](const httplib::Request& req, httplib::Response& res)
                      {
                          nlohmann::json out;
                          out["headers"] = getHttpHeaders(req);
                          out["body"] = req.body;
                          res.set_content(out.dump(), "text/json");
                      });

        server.Delete(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        // A few KiB on the wire that inflate to LARGE_BODY_SIZE bytes.
        server.Get("/large-gzip",
                   [](const httplib::Request& /*req*/, httplib::Response& res)
                   {
                       res.set_header("Content-Encoding", "gzip");
                       res.set_content(gzipCompress(std::string(LARGE_BODY_SIZE, 'A')), "application/octet-stream");
                   });

        // Small gzip reply, to tell whether the client decoded it or not.
        server.Get("/gzip-small",
                   [](const httplib::Request& /*req*/, httplib::Response& res)
                   {
                       res.set_header("Content-Encoding", "gzip");
                       res.set_content(gzipCompress("plain"), "application/octet-stream");
                   });

        // Brotli reply: only a curl built with Brotli can decode it.
        server.Get("/brotli",
                   [](const httplib::Request& /*req*/, httplib::Response& res)
                   {
                       res.set_header("Content-Encoding", "br");
                       res.set_content(std::string(BROTLI_FIXTURE_BYTES.begin(), BROTLI_FIXTURE_BYTES.end()),
                                       "application/octet-stream");
                   });

        server.set_keep_alive_max_count(1);
        server.listen("localhost", 44441);
    }
};
/**
 * @brief HTTP responder on a unix socket, in a forked process: echoes the request headers as JSON.
 */
class FakeUnixServer final
{
private:
    pid_t m_pid {-1};
    std::string m_socketPath;

public:
    FakeUnixServer()
        : m_socketPath("/tmp/http-request-ct-" + std::to_string(getpid()) + ".sock")
    {
        std::filesystem::remove(m_socketPath);
        const int listener {createListener()};
        m_pid = fork();
        if (m_pid == 0)
        {
            serve(listener);
            _exit(0);
        }
        close(listener);
        if (m_pid < 0)
        {
            throw std::runtime_error("Failed to fork unix server process");
        }
    }

    ~FakeUnixServer()
    {
        stop();
    }

    FakeUnixServer(const FakeUnixServer&) = delete;
    FakeUnixServer& operator=(const FakeUnixServer&) = delete;

    const std::string& socketPath() const
    {
        return m_socketPath;
    }

private:
    /**
     * @brief Binds and listens before forking, so the client can connect as soon as the constructor returns.
     * The bundled cpp-httplib has no unix-socket listener, hence this minimal HTTP/1.1 responder.
     */
    int createListener() const
    {
        const int fd {socket(AF_UNIX, SOCK_STREAM, 0)};
        sockaddr_un address {};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, m_socketPath.c_str(), sizeof(address.sun_path) - 1);
        if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(fd, 16) != 0)
        {
            throw std::runtime_error("Failed to create the unix listener on " + m_socketPath);
        }
        return fd;
    }

    /**
     * @brief GET /check-headers: answers a JSON with the request headers.
     */
    static void serve(int listener)
    {
        while (true)
        {
            const int client {accept(listener, nullptr, nullptr)};
            if (client < 0)
            {
                continue;
            }

            std::string request;
            char buffer[2048];
            while (request.find("\r\n\r\n") == std::string::npos)
            {
                const auto received {recv(client, buffer, sizeof(buffer), 0)};
                if (received <= 0)
                {
                    break;
                }
                request.append(buffer, static_cast<std::size_t>(received));
            }

            nlohmann::json headers = nlohmann::json::object();
            std::istringstream lines {request};
            std::string line;
            std::getline(lines, line); // request line
            while (std::getline(lines, line) && line != "\r" && !line.empty())
            {
                const auto colon {line.find(':')};
                if (colon == std::string::npos)
                {
                    continue;
                }
                auto value {line.substr(colon + 1)};
                value.erase(0, value.find_first_not_of(' '));
                while (!value.empty() && (value.back() == '\r' || value.back() == ' '))
                {
                    value.pop_back();
                }
                headers[line.substr(0, colon)] = value;
            }

            const auto body {headers.dump()};
            const auto reply {"HTTP/1.1 200 OK\r\nContent-Type: text/json\r\nContent-Length: " +
                              std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body};
            send(client, reply.data(), reply.size(), MSG_NOSIGNAL);
            close(client);
        }
    }

    void stop()
    {
        if (m_pid > 0)
        {
            kill(m_pid, SIGTERM);
            int status;
            waitpid(m_pid, &status, 0);
            m_pid = -1;
        }
        std::filesystem::remove(m_socketPath);
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
        // Stop the previous server before forking the next one: a child that binds while the old process still owns
        // the port fails silently, the readiness probe is answered by the old server, and the test then finds nobody.
        fakeFileServer.reset();
        fakeFileServer = std::make_unique<FakeServer>();
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
