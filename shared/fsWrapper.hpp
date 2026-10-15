/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _FSWRAPPER_HPP
#define _FSWRAPPER_HPP

#include <filesystem>

/**
 * @brief This class is a wrapper for the filesystem library.
 */
class FsWrapper
{
protected:
    FsWrapper() = default;
    virtual ~FsWrapper() = default;

public:
    /**
     * @brief Method to check if a file exists.
     * @param name The file name.
     */
    static bool exists(const std::string& name)
    {
        return std::filesystem::exists(name);
    }
};

#endif /* _FSWRAPPER_HPP */
