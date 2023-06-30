/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * June 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_EXCEPTION_HPP
#define _CURL_EXCEPTION_HPP

namespace Curl
{
    class CurlException : public std::exception
    {
        public:
            long responseCode() const noexcept
            {
                return m_responseCode;
            }

            const char* what() const noexcept override
            {
                return m_error.what();
            }

            CurlException(const std::string& errorMessage, const long responseCode = 0)
                : m_error {errorMessage}
                , m_responseCode {responseCode}
            {}

            explicit CurlException(const std::pair<const std::string&, const long>& curlException)
                : m_error {curlException.first}
                , m_responseCode {curlException.second}
            {}

        private:
            std::runtime_error m_error;
            const long m_responseCode;
    };
}

#endif // _CURL_EXCEPTION_HPP
