/*
 * Wazuh urlRequest TestTool
 * Copyright (C) Wazuh Inc.
 * July 13, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "cmdArgsParser.hpp"
#include "factoryAction.hpp"
#include <iostream>

int main(const int argc, const char* argv[])
{
    auto retVal {0};

    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);
        FactoryAction::create(cmdLineArgs)->execute();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        retVal = 1;
        CmdLineArgs::showHelp();
    }

    return retVal;
}
