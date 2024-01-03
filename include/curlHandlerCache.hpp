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

#ifndef _CURL_HANDLER_CACHE_HPP
#define _CURL_HANDLER_CACHE_HPP

#include "ICURLHandler.hpp"
#include "curlHandlerType.hpp"
#include "curlMultiHandler.hpp"
#include "curlSingleHandler.hpp"
#include "customDeleter.hpp"
#include "singleton.hpp"
#include <algorithm>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

static const int QUEUE_MAX_SIZE = 5;

/**
 * @class cURLHandlerCache
 *
 * @brief Class responsible for storing the curl handlers.
 *
 */
class cURLHandlerCache final : public Singleton<cURLHandlerCache>
{
private:
    std::deque<std::pair<std::thread::id, std::shared_ptr<ICURLHandler>>>
        m_handlerQueue; ///< Container for the handlers and thread identifiers.
    std::mutex m_mutex; ///< Enum value for this content type.

public:
    /**
     * @brief Get the curl handler object
     * This method creates a single or multi curl handler and returns it, but ensures that only one curl handler is used
     * per thread and keeps the queue size to a maximum of QUEUE_MAX_SIZE.
     *
     * @param curlHandlerType Type of the curl handler. Default is 'SINGLE'.
     *
     * @return std::shared_ptr<ICURLHandler>
     */
    std::shared_ptr<ICURLHandler> getCurlHandler(CurlHandlerTypeEnum curlHandlerType = CurlHandlerTypeEnum::SINGLE)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it {std::find_if(
            m_handlerQueue.cbegin(),
            m_handlerQueue.cend(),
            [&curlHandlerType](const std::pair<std::thread::id, std::shared_ptr<ICURLHandler>>& pair)
            { return std::this_thread::get_id() == pair.first && curlHandlerType == pair.second->getHandlerType(); })};

        if (m_handlerQueue.end() != it)
        {
            return it->second;
        }
        else
        {
            if (QUEUE_MAX_SIZE <= m_handlerQueue.size())
            {
                m_handlerQueue.pop_front();
            }
            std::shared_ptr<ICURLHandler> handler;
            switch (curlHandlerType)
            {
                case CurlHandlerTypeEnum::SINGLE: handler = std::make_shared<cURLSingleHandler>(curlHandlerType); break;
                case CurlHandlerTypeEnum::MULTI: handler = std::make_shared<cURLMultiHandler>(curlHandlerType); break;
                default: throw std::invalid_argument("Invalid handler type.");
            }
            m_handlerQueue.emplace_back(std::this_thread::get_id(), handler);
            return m_handlerQueue.back().second;
        }
    }

    /**
     * @brief Returns the number of handlers in the 'm_handlerQueue'.
     *
     * @return std::size_t
     */
    std::size_t size()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_handlerQueue.size();
    }
};

#endif // _CURL_HANDLER_CACHE_HPP
