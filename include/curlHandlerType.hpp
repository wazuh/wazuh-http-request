/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 27, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_HANDLER_TYPE_HPP
#define _CURL_HANDLER_TYPE_HPP

/**
 * @brief Valid types of cURL handler.
 */
enum CurlHandlerTypeEnum
{
    SINGLE,
    MULTI
};

#endif // _CURL_HANDLER_TYPE_HPP
