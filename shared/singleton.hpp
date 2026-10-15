/*
 * Wazuh Utils - Singleton template
 * Copyright (C) Wazuh Inc.
 * May 20, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SINGLETON_HPP
#define _SINGLETON_HPP

/**
 * @brief This class is a template for singleton classes.
 *
 * @tparam T Type of the singleton class.
 */
template<typename T>
class Singleton
{
    public:
        /**
         * @brief Returns the instance of the singleton class.
         * @return Instance of the singleton class.
         */
        static T& instance()
        {
            static T s_instance;
            return s_instance;
        }
    protected:
        Singleton() = default;
        virtual ~Singleton() = default;
        Singleton(const Singleton&) = delete;
        Singleton& operator=(const Singleton&) = delete;
};

#endif // _SINGLETON_HPP

