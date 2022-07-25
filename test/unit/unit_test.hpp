/*
 * Wazuh URLRequest unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UNIT_TEST_H
#define _UNIT_TEST_H

#include <memory>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "urlRequest.hpp"

class UrlRequestUnitTest : public ::testing::Test
{
    protected:

        UrlRequestUnitTest() = default;
        virtual ~UrlRequestUnitTest() = default;

        void SetUp() override;
        void TearDown() override;
};


#endif // _UNIT_TEST_H


