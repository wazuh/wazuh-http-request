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

#ifndef _CURL_HANDLER_HPP
#define _CURL_HANDLER_HPP

#include "curl.h"
#include "curlHandlerType.hpp"
#include <memory>

//! ICURLHandler abstract class
/**
 * This class serves as the interface that represents a curl handler.
 */
class ICURLHandler
{
protected:
    std::shared_ptr<CURL> m_curlHandler;   ///< Pointer to the CURL handle.
    CurlHandlerTypeEnum m_curlHandlerType; ///< Enum value for this curl handler type.

public:
    /**
     * @brief Construct a new ICURLHandler object
     *
     * @param curlHandlerType Enum value of the curl handler.
     */
    ICURLHandler(CurlHandlerTypeEnum curlHandlerType)
        : m_curlHandlerType(curlHandlerType) {};

    // LCOV_EXCL_START
    virtual ~ICURLHandler() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief This method performs the request.
     */
    virtual void execute() = 0;

    /**
     * @brief Returns the pointer to the CURL handle.
     *
     * @return std::shared_ptr<CURL>
     */
    [[nodiscard]] const std::shared_ptr<CURL>& getHandler() const
    {
        return m_curlHandler;
    }

    /**
     * @brief Returns the type of the curl handle.
     *
     * @return CurlHandlerTypeEnum
     */
    [[nodiscard]] CurlHandlerTypeEnum getHandlerType() const
    {
        return m_curlHandlerType;
    }
};

#endif // _CURL_HANDLER_HPP
