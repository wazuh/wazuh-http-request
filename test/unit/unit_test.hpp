/*
 * Wazuh URLRequest unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _UNIT_TEST_H
#define _UNIT_TEST_H

#include "gtest/gtest.h"
#include <memory>

/**
 * @brief This class is used to test the URLRequest class.
 */
class UrlRequestUnitTest : public ::testing::Test
{
protected:
    UrlRequestUnitTest() = default;
    virtual ~UrlRequestUnitTest() = default;
};

#endif // _UNIT_TEST_H
