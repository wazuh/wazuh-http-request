/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 27, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_SINGLE_HANDLER_HPP
#define _CURL_SINGLE_HANDLER_HPP

#include "ICURLHandler.hpp"
#include "curl.h"
#include "curlException.hpp"
#include "customDeleter.hpp"
#include <memory>
#include <stdexcept>

constexpr auto NOT_USED {-1};

using deleterCurlHandler = CustomDeleter<decltype(&curl_easy_cleanup), curl_easy_cleanup>;

//! cURLSingleHandler class
/**
 * @brief class implements the ICURLHandler interface to represent a single cURL handler.
 */
class cURLSingleHandler final : public ICURLHandler
{
public:
    /**
     * @brief Construct a new cURLSingleHandler object
     *
     * @param curlHandlerType Enum value of the cURL handler.
     */
    explicit cURLSingleHandler(CurlHandlerTypeEnum curlHandlerType)
        : ICURLHandler(curlHandlerType)
    {
        m_curlHandler = std::shared_ptr<CURL>(curl_easy_init(), deleterCurlHandler());
    }

    // LCOV_EXCL_START
    ~cURLSingleHandler() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief This method performs the request.
     */
    void execute() override
    {
        // Perform the HTTP request
        const CURLcode resPerform = curl_easy_perform(m_curlHandler.get());

        // Get HTTP status code before reset
        long responseCode = 0;
        const CURLcode resGetInfo = curl_easy_getinfo(m_curlHandler.get(), CURLINFO_RESPONSE_CODE, &responseCode);

        // Clean up cURL handle state
        curl_easy_reset(m_curlHandler.get());

        // Check for cURL-level errors (network, DNS, timeout, etc.)
        if (resPerform != CURLE_OK)
        {
            throw Curl::CurlException(curl_easy_strerror(resPerform), NOT_USED);
        }

        // Verify we got response code (should always succeed if resPerform OK)
        if (resGetInfo != CURLE_OK)
        {
            throw Curl::CurlException("Failed to retrieve HTTP response code", NOT_USED);
        }

        // Handle HTTP-level errors (4xx and 5xx)
        if (responseCode >= 400)
        {
            std::string errorMsg;
            if (responseCode >= 400 && responseCode < 500)
            {
                errorMsg = "Client error";
            }
            else if (responseCode >= 500)
            {
                errorMsg = "Server error";
            }

            throw Curl::CurlException(errorMsg, responseCode);
        }
    }
};

#endif // _CURL_SINGLE_HANDLER_HPP
