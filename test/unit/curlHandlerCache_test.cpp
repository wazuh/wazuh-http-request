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

#include "curlHandlerCache_test.hpp"
#include "curlHandlerType.hpp"
#include "curlMultiHandler.hpp"
#include "curlSingleHandler.hpp"
#include "curlWrapper.hpp"
#include <memory>

/*
 * @brief Test the creation of the Single handler.
 */
TEST_F(cURLHandlerCacheTest, SingleHandlerCreation)
{
    // Create the cURL handler and check that it is a Single handler.
    EXPECT_TRUE(std::dynamic_pointer_cast<cURLSingleHandler>(
        cURLHandlerCache::instance().getCurlHandler(CurlHandlerTypeEnum::SINGLE)));
}

/*
 * @brief Test the creation of the Multi handler.
 */
TEST_F(cURLHandlerCacheTest, MultiHandlerCreation)
{
    // Create the cURL handler and check that it is a Multi handler.
    EXPECT_TRUE(std::dynamic_pointer_cast<cURLMultiHandler>(
        cURLHandlerCache::instance().getCurlHandler(CurlHandlerTypeEnum::MULTI)));
}
