/*
 * Wazuh urlRequest TestTool
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _ACTION_HPP
#define _ACTION_HPP
#include "HTTPRequest.hpp"
#include <iostream>
#include <optional>

/**
 * @brief Action interface.
 */
class IAction
{
public:
    virtual ~IAction() = default;

    /**
     * @brief Virtual method to execute the action.
     */
    virtual void execute() = 0;
};

/**
 * @brief This class is used to perform a DOWNLOAD action.
 */
class DownloadAction final : public IAction
{
private:
    std::string m_url;
    std::string m_outputFile;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor for DownloadAction class.
     * @param url URL to download.
     * @param outputFile Output file.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit DownloadAction(const std::string& url,
                            const std::string& outputFile,
                            const std::unordered_set<std::string>& headers,
                            const SecureCommunication& secureCommunication,
                            const long timeout,
                            const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_outputFile(outputFile)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief Executes the action.
     */
    void execute() override
    {
        HTTPRequest::instance().download(
            RequestParameters {
                .url = HttpURL(m_url), .secureCommunication = m_secureCommunication, .httpHeaders = m_headers},
            PostRequestParameters {
                .onError =
                    [](const std::string& msg, const long responseCode, const std::string& resultBody)
                {
                    std::cerr << msg << ": " << responseCode << ". Response body: " << resultBody << std::endl;
                    throw std::runtime_error(msg);
                },
                .outputFile = m_outputFile},
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

/**
 * @brief This class is used to perform a GET action.
 */
class GetAction final : public IAction
{
private:
    std::string m_url;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor of GetAction class.
     * @param url URL to perform the GET request.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit GetAction(const std::string& url,
                       const std::unordered_set<std::string>& headers,
                       const SecureCommunication& secureCommunication,
                       const long timeout,
                       const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief This method is used to perform the GET request.
     */
    void execute() override
    {
        HTTPRequest::instance().get(
            RequestParameters {
                .url = HttpURL(m_url), .secureCommunication = m_secureCommunication, .httpHeaders = m_headers},
            PostRequestParameters {
                .onSuccess = [](const std::string& msg) { std::cout << msg << std::endl; },
                .onError =
                    [](const std::string& msg, const long responseCode, const std::string& resultBody)
                {
                    std::cerr << msg << ": " << responseCode << ". Response body: " << resultBody << std::endl;
                    throw std::runtime_error(msg);
                }},
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

/**
 * @brief This class is used to perform a POST action.
 */
class PostAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor of PostAction class.
     * @param url URL to perform the POST request.
     * @param data Data to send in the POST request.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit PostAction(const std::string& url,
                        const nlohmann::json& data,
                        const std::unordered_set<std::string>& headers,
                        const SecureCommunication& secureCommunication,
                        const long timeout,
                        const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_data(data)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief This method is used to perform the POST request.
     */
    void execute() override
    {
        HTTPRequest::instance().post(
            RequestParameters {
                .url = HttpURL(m_url), .secureCommunication = m_secureCommunication, .httpHeaders = m_headers},
            PostRequestParameters {
                .onSuccess = [](const std::string& msg) { std::cout << msg << std::endl; },
                .onError =
                    [](const std::string& msg, const long responseCode, const std::string& resultBody)
                {
                    std::cerr << msg << ": " << responseCode << ". Response body: " << resultBody << std::endl;
                    throw std::runtime_error(msg);
                },
            },
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

/**
 * @brief This class is used to perform a PUT action.
 */
class PutAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor of PutAction class.
     * @param url URL to perform the PUT request.
     * @param data Data to send in the PUT request.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit PutAction(const std::string& url,
                       const nlohmann::json& data,
                       const std::unordered_set<std::string>& headers,
                       const SecureCommunication& secureCommunication,
                       const long timeout,
                       const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_data(data)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief This method is used to perform the PUT request.
     */
    void execute() override
    {
        HTTPRequest::instance().put(
            TRequestParameters<nlohmann::json> {.url = HttpURL(m_url),
                               .data = m_data,
                               .secureCommunication = m_secureCommunication,
                               .httpHeaders = m_headers},
            PostRequestParameters {
                .onSuccess = [](const std::string& msg) { std::cout << msg << std::endl; },
                .onError =
                    [](const std::string& msg, const long responseCode, const std::string& resultBody)
                {
                    std::cerr << msg << ": " << responseCode << ". Response body: " << resultBody << std::endl;
                    throw std::runtime_error(msg);
                }},
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

/**
 * @brief This class is used to perform a PATCH action.
 *
 */
class PatchAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor of PatchAction class.
     *
     * @param url URL to perform the PATCH request.
     * @param data Data to send in the PATCH request.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit PatchAction(const std::string& url,
                         const nlohmann::json& data,
                         const std::unordered_set<std::string>& headers,
                         const SecureCommunication& secureCommunication,
                         const long timeout,
                         const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_data(data)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief This method is used to perform the PATCH request.
     *
     */
    void execute() override
    {
        HTTPRequest::instance().patch(
            TRequestParameters<nlohmann::json> {.url = HttpURL(m_url),
                               .data = m_data,
                               .secureCommunication = m_secureCommunication,
                               .httpHeaders = m_headers},
            PostRequestParameters {
                .onSuccess = [](const std::string& msg) { std::cout << msg << std::endl; },
                .onError =
                    [](const std::string& msg, const long responseCode, const std::string& responseBody)
                {
                    std::cerr << msg << ": " << responseCode << ". Response body: " << responseBody << std::endl;
                    throw std::runtime_error(msg);
                }},
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

/**
 * @brief This class is used to perform a DELETE action.
 */
class DeleteAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;
    std::unordered_set<std::string> m_headers;
    SecureCommunication m_secureCommunication;
    long m_timeout;
    std::optional<std::string> m_acceptEncoding;

public:
    /**
     * @brief Constructor of DeleteAction class.
     * @param url URL to perform the DELETE request.
     * @param headers Headers to send in the request.
     * @param secureCommunication Secure communication settings.
     * @param timeout Timeout for the request.
     * @param acceptEncoding Accept-Encoding mode (std::nullopt: none, empty: all, otherwise verbatim).
     */
    explicit DeleteAction(const std::string& url,
                          const nlohmann::json& data,
                          const std::unordered_set<std::string>& headers,
                          const SecureCommunication& secureCommunication,
                          const long timeout,
                          const std::optional<std::string>& acceptEncoding = std::string {})
        : m_url(url)
        , m_data(data)
        , m_headers(headers)
        , m_secureCommunication(secureCommunication)
        , m_timeout(timeout)
        , m_acceptEncoding(acceptEncoding)
    {
    }

    /**
     * @brief This method is used to perform the DELETE request.
     */
    void execute() override
    {
        HTTPRequest::instance().delete_(
            TRequestParameters<nlohmann::json> {
                .url = HttpURL(m_url),
                .data = m_data,
                .secureCommunication = m_secureCommunication,
                .httpHeaders = m_headers
            },
            PostRequestParameters{
                .onSuccess = [](const std::string& msg) { std::cout << msg << std::endl; },
                .onError = [](const std::string& msg, const long code, const std::string& body)
                {
                    std::cerr << msg << ": " << code << ". Response body: " << body << std::endl;
                    throw std::runtime_error(msg);
                }
            },
            ConfigurationParameters {.timeout = m_timeout, .acceptEncoding = m_acceptEncoding});
    }
};

#endif // _ACTION_HPP
