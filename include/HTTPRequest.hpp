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

#ifndef _HTTP_REQUEST_HPP
#define _HTTP_REQUEST_HPP

#include "IURLRequest.hpp"
#include "json.hpp"
#include "singleton.hpp"
#include <functional>
#include <string>
#include <unordered_set>

/**
 * @brief This class is an implementation of IURLRequest.
 * It provides a simple interface to perform HTTP requests.
 */
class HTTPRequest final
    : public IURLRequest
    , public Singleton<HTTPRequest>
{
public:
    /**
     * @brief Performs a HTTP DOWNLOAD request.
     * @param url URL to send the request.
     * @param fileName Output file.
     * @param onError Callback to be called in case of error.
     * @param httpHeaders Headers to be added to the query.
     */
    void download(
        const URL& url,
        const std::string& fileName,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::unordered_set<std::string>& httpHeaders = std::unordered_set<std::string>());

    /**
     * @brief Performs a HTTP POST request.
     * @param url URL to send the request.
     * @param data Data to send.
     * @param onSuccess Callback to be called in case of success.
     * @param onError Callback to be called in case of error.
     * @param fileName File name of output file.
     * @param httpHeaders Headers to be added to the query.
     */
    void post(
        const URL& url,
        const nlohmann::json& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS);

    /**
     * @brief Performs a HTTP GET request.
     * @param url URL to send the request.
     * @param onSuccess Callback to be called in case of success.
     * @param onError Callback to be called in case of error.
     * @param fileName File name of output file.
     * @param httpHeaders Headers to be added to the query.
     */
    void get(
        const URL& url,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS);

    /**
     * @brief Performs a HTTP UPDATE request.
     * @param url URL to send the request.
     * @param data Data to send.
     * @param onSuccess Callback to be called in case of success.
     * @param onError Callback to be called in case of error.
     * @param fileName File name of output file.
     * @param httpHeaders Headers to be added to the query.
     */
    void update(
        const URL& url,
        const nlohmann::json& data,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS);

    /**
     * @brief Performs a HTTP DELETE request.
     * @param url URL to send the request.
     * @param onSuccess Callback to be called in case of success.
     * @param onError Callback to be called in case of error.
     * @param fileName File name of output file.
     * @param httpHeaders Headers to be added to the query.
     */
    void delete_(
        const URL& url,
        std::function<void(const std::string&)> onSuccess,
        std::function<void(const std::string&, const long)> onError = [](auto, auto) {},
        const std::string& fileName = "",
        const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS);
};

#endif // _HTTP_REQUEST_HPP
