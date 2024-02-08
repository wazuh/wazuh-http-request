/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UNIX_SOCKET_REQUEST_HPP
#define _UNIX_SOCKET_REQUEST_HPP

#include "IURLRequest.hpp"
#include "json.hpp"
#include "singleton.hpp"
#include <atomic>
#include <functional>
#include <iostream>
#include <string>
#include <unordered_set>

/**
 * @brief This class is an abstraction of HTTP Unix socket request.
 * It provides a simple interface to send HTTP requests.
 */
class UNIXSocketRequest final
    : public IURLRequest
    , public Singleton<UNIXSocketRequest>
{
public:
    /**
     * @brief Performs a UNIX SOCKET DOWNLOAD request.
     *
     * @param url
     * @param fileName
     * @param onError
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void download(
        const URL& url,
        const std::string& fileName,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET POST request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void post(
        const URL& url,
        const nlohmann::json& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);

    /**
     * @brief Performs a UNIX SOCKET POST request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void post(
        const URL& url,
        const std::string& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET GET request.
     *
     * @param url
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void get(
        const URL& url,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET PUT request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void put(
        const URL& url,
        const nlohmann::json& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET PUT request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void put(
        const URL& url,
        const std::string& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET PATCH request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void patch(
        const URL& url,
        const nlohmann::json& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET PATCH request.
     *
     * @param url
     * @param data
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void patch(
        const URL& url,
        const std::string& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
    /**
     * @brief Performs a UNIX SOCKET DELETE request.
     *
     * @param url
     * @param onSuccess
     * @param onError
     * @param fileName
     * @param httpHeaders
     * @param secureCommunication
     * @param handlerType
     * @param shouldRun
     */
    void delete_(
        const URL& url,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS,
        const SecureCommunication& secureCommunication = {},
        const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE,
        const std::atomic<bool>& shouldRun = true);
};

#endif // _UNIX_SOCKET_REQUEST_HPP
