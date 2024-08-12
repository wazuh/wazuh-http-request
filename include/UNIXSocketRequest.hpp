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
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void download(RequestParameters requestParameters,
                  PostRequestParameters postRequestParameters,
                  ConfigurationParameters configurationParameters);
    /**
     * @brief Performs a UNIX SOCKET POST request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void post(RequestParameters requestParameters,
              PostRequestParameters postRequestParameters,
              ConfigurationParameters configurationParameters);

    /**
     * @brief Performs a UNIX SOCKET GET request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void get(RequestParameters requestParameters,
             PostRequestParameters postRequestParameters,
             ConfigurationParameters configurationParameters);
    /**
     * @brief Performs a UNIX SOCKET PUT request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void put(RequestParameters requestParameters,
             PostRequestParameters postRequestParameters,
             ConfigurationParameters configurationParameters);

    /**
     * @brief Performs a UNIX SOCKET PATCH request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request..
     */
    void patch(RequestParameters requestParameters,
               PostRequestParameters postRequestParameters,
               ConfigurationParameters configurationParameters);

    /**
     * @brief Performs a UNIX SOCKET DELETE request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void delete_(RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters);
};

#endif // _UNIX_SOCKET_REQUEST_HPP
