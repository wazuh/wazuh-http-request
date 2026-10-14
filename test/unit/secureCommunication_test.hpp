/*
 * Wazuh URLRequest unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 30, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef __SECURE_COMMUNICATION_TEST_HPP
#define __SECURE_COMMUNICATION_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief SecureCommunicationTest class.
 *
 */
class SecureCommunicationTest : public ::testing::Test
{
protected:
    SecureCommunicationTest() = default;
    virtual ~SecureCommunicationTest() = default;
};

#endif // __SECURE_COMMUNICATION_TEST_HPP
