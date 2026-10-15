/*
 * Wazuh http request
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MOCKREQUESTIMPLEMENTATOR_HPP
#define _MOCKREQUESTIMPLEMENTATOR_HPP

#include "IRequestImplementator.hpp"
#include "gmock/gmock.h"
/**
 * @brief This class is a wrapper to perform requests.
 */
class RequestWrapper final : public IRequestImplementator
{
public:
    RequestWrapper() = default;
    virtual ~RequestWrapper() = default;

    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOptionPtr, (const OPTION_REQUEST_TYPE optIndex, void* ptr), (override));
    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOptionString, (const OPTION_REQUEST_TYPE optIndex, const std::string& opt), (override));
    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOptionLong, (const OPTION_REQUEST_TYPE optIndex, const long int opt), (override));
    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOptionStringView, (const OPTION_REQUEST_TYPE optIndex, std::string_view opt), (override));
    /**
     * @brief Mock method to set execute the request.
     */
    MOCK_METHOD(void, execute, (), (override));
    /**
     * @brief Mock method to append a header.
     */
    MOCK_METHOD(void, appendHeader, (const std::string& header), (override));
};

#endif // _MOCKREQUESTIMPLEMENTATOR_HPP
