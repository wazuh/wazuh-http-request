/*
 * Wazuh cURLHandlerCache unit tests
 * Copyright (C) Wazuh Inc.
 * December 28, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CURL_HANDLER_CACHE_TEST_HPP
#define _CURL_HANDLER_CACHE_TEST_HPP

#include "IURLRequest.hpp"
#include "curlHandlerCache.hpp"
#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for cURLHandlerCache class
 */
class cURLHandlerCacheTest : public ::testing::Test
{
protected:
    cURLHandlerCacheTest() = default;
    ~cURLHandlerCacheTest() override = default;

    /**
     * @brief Cleans the test environment
     *
     */
    void TearDown() override
    {
        cURLHandlerCache::instance().clear();
    }
};

#endif // _CURL_HANDLER_CACHE_TEST_HPP
