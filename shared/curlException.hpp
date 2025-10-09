/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_EXCEPTION_HPP
#define _CURL_EXCEPTION_HPP

#include <stdexcept>
#include <string>
#include <utility>

namespace Curl
{
/**
 * @brief Custom exception for Curl wrapper.
 *
 */
class CurlException : public std::exception
{
public:
    /**
     * @brief Returns HTTP response code ID.
     *
     * @return long HTTP response code ID.
     */
    long responseCode() const noexcept
    {
        return m_responseCode;
    }

    /**
     * @brief Returns HTTP response body.
     *
     * @return const std::string& HTTP response body.
     */
    const std::string& responseBody() const noexcept
    {
        return m_responseBody;
    }

    /**
     * @brief Return error message.
     *
     * @return const char* Error message.
     */
    const char* what() const noexcept override
    {
        return m_error.what();
    }

    /**
     * @brief Construct a new Curl Exception object
     *
     * @param errorMessage Error message to show.
     * @param responseCode HTTP response code ID.
     * @param responseBody HTTP response body (optional).
     */
    CurlException(const std::string& errorMessage, const long responseCode, std::string responseBody = "")
        : m_error {errorMessage}
        , m_responseCode {responseCode}
        , m_responseBody {std::move(responseBody)}
    {
    }

    /**
     * @brief Construct a new Curl Exception object
     *
     * @param curlException Pair object with an error message and a response code ID.
     */
    explicit CurlException(const std::pair<const std::string&, const long>& curlException)
        : m_error {curlException.first}
        , m_responseCode {curlException.second}
        , m_responseBody {}
    {
    }

private:
    std::runtime_error m_error;
    const long m_responseCode;
    const std::string m_responseBody;
};
} // namespace Curl

#endif // _CURL_EXCEPTION_HPP
