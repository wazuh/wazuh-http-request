/*
 * Wazuh urlRequest test component
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MOCKREQUEST_HPP
#define _MOCKREQUEST_HPP

#include "urlRequest.hpp"

/**
 * @brief This class is a wrapper for the cURL library.
 */
template<typename T>
class MockRequest : public cURLRequest<MockRequest<T>, T>
{
public:
    /**
     * @brief Constructor.
     * @param requestImplementator The request implementator instance.
     */
    explicit MockRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<MockRequest<T>, T>(requestImplementator)
    {
    }
};

#endif // _MOCKREQUEST_HPP
