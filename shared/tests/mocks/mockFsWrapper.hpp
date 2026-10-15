/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * Jul 10, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MOCKFSWRAPPER_HPP
#define _MOCKFSWRAPPER_HPP

#include <gmock/gmock.h>
/**
 * @brief This class is a wrapper for the filesystem library.
 */
class MockFsWrapper
{
public:
    MockFsWrapper() = default;
    virtual ~MockFsWrapper() = default;

    /**
     * @brief Mock method to check if a file exists.
     */
    MOCK_METHOD(bool, exists, (const std::string& path));
};

#endif // _MOCKFSWRAPPER_HPP

