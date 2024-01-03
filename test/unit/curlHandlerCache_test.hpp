/*
 * Wazuh cURLHandlerCache unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 28, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_HANDLER_CACHE_TEST_HPP
#define _CURL_HANDLER_CACHE_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for cURLHandlerCache class
 */
class cURLHandlerCacheTest : public ::testing::Test
{
protected:
    cURLHandlerCacheTest() = default;
    ~cURLHandlerCacheTest() override = default;
};

#endif // _CURL_HANDLER_CACHE_TEST_HPP
