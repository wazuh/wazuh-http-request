/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_WRAPPER_HPP
#define _CURL_WRAPPER_HPP

#include "IRequestImplementator.hpp"
#include "curl.h"
#include "customDeleter.hpp"
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <queue>
#include <stdexcept>
#include <thread>

using deleterCurl = CustomDeleter<decltype(&curl_easy_cleanup), curl_easy_cleanup>;

static const std::map<OPTION_REQUEST_TYPE, CURLoption> OPTION_REQUEST_TYPE_MAP = {
    {OPT_URL, CURLOPT_URL},
    {OPT_CAINFO, CURLOPT_CAINFO},
    {OPT_TIMEOUT, CURLOPT_TIMEOUT},
    {OPT_WRITEDATA, CURLOPT_WRITEDATA},
    {OPT_USERAGENT, CURLOPT_USERAGENT},
    {OPT_POSTFIELDS, CURLOPT_POSTFIELDS},
    {OPT_WRITEFUNCTION, CURLOPT_WRITEFUNCTION},
    {OPT_POSTFIELDSIZE, CURLOPT_POSTFIELDSIZE},
    {OPT_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST},
    {OPT_UNIX_SOCKET_PATH, CURLOPT_UNIX_SOCKET_PATH},
    {OPT_FAILONERROR, CURLOPT_FAILONERROR}};

static std::deque<std::pair<std::thread::id, std::shared_ptr<CURL>>> HANDLER_QUEUE;

static std::mutex CURL_WRAPPER_MUTEX;

static const int QUEUE_SIZE = 5;

/**
 * @brief This class is a wrapper of the curl library.
 */
class cURLWrapper final : public IRequestImplementator
{
private:
    using deleterCurlStringList = CustomDeleter<decltype(&curl_slist_free_all), curl_slist_free_all>;
    std::unique_ptr<curl_slist, deleterCurlStringList> m_curlHeaders;

    static size_t writeData(char* data, size_t size, size_t nmemb, void* userdata)
    {
        const auto str {reinterpret_cast<std::string*>(userdata)};
        str->append(data, size * nmemb);
        return size * nmemb;
    }
    std::string m_returnValue;

    std::shared_ptr<CURL> m_curlHandle;

    /**
     * @brief Get the cURL Handle object
     * This method create a cURL handle and return it, but ensures that only one cURL handle is used per thread and
     * keeps the queue size to a maximum of QUEUE_SIZE.
     *
     * @return std::shared_ptr<CURL>
     */
    std::shared_ptr<CURL> curlHandleInit()
    {
        std::lock_guard<std::mutex> lock(CURL_WRAPPER_MUTEX);
        const auto it {std::find_if(HANDLER_QUEUE.begin(),
                                    HANDLER_QUEUE.end(),
                                    [](const std::pair<std::thread::id, std::shared_ptr<CURL>>& pair)
                                    { return std::this_thread::get_id() == pair.first; })};

        if (HANDLER_QUEUE.end() != it)
        {
            return it->second;
        }
        else
        {
            HANDLER_QUEUE.emplace_back(std::this_thread::get_id(),
                                       std::shared_ptr<CURL>(curl_easy_init(), deleterCurl()));

            if (QUEUE_SIZE <= HANDLER_QUEUE.size())
            {
                HANDLER_QUEUE.pop_front();
            }

            return HANDLER_QUEUE.back().second;
        }
    }

public:
    cURLWrapper()
    {
        m_curlHandle = curlHandleInit();

        if (!m_curlHandle)
        {
            throw std::runtime_error("cURL initialization failed");
        }

        this->setOption(OPT_WRITEFUNCTION, reinterpret_cast<void*>(cURLWrapper::writeData));

        this->setOption(OPT_WRITEDATA, &m_returnValue);

        this->setOption(OPT_FAILONERROR, 1l);
    }

    virtual ~cURLWrapper() = default;

    /**
     * @brief This method returns the value of the last request.
     * @return The value of the last request.
     */
    inline const std::string response() override
    {
        return m_returnValue;
    }

    /**
     * @brief This method sets an option to the curl handler.
     * @param optIndex The option index.
     * @param ptr The option value.
     */
    void setOption(const OPTION_REQUEST_TYPE optIndex, void* ptr) override
    {
        auto ret = curl_easy_setopt(m_curlHandle.get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), ptr);

        if (ret != CURLE_OK)
        {
            throw std::runtime_error("cURL set option failed");
        }
    }

    /**
     * @brief This method sets an option to the curl handler.
     * @param optIndex The option index.
     * @param opt The option value.
     */
    void setOption(const OPTION_REQUEST_TYPE optIndex, const std::string& opt) override
    {
        auto ret = curl_easy_setopt(m_curlHandle.get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), opt.c_str());

        if (ret != CURLE_OK)
        {
            throw std::runtime_error("cURLWrapper::setOption() failed");
        }
    }

    /**
     * @brief This method sets an option to the curl handler.
     * @param optIndex The option index.
     * @param opt The option value.
     */
    void setOption(const OPTION_REQUEST_TYPE optIndex, const long opt) override
    {
        auto ret = curl_easy_setopt(m_curlHandle.get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), opt);

        if (ret != CURLE_OK)
        {
            throw std::runtime_error("cURLWrapper::setOption() failed");
        }
    }

    /**
     * @brief This method adds an header to the curl handler.
     * @param header The header to be added.
     */
    void appendHeader(const std::string& header) override
    {
        if (!m_curlHeaders)
        {
            m_curlHeaders.reset(curl_slist_append(m_curlHeaders.get(), header.c_str()));
        }
        else
        {
            curl_slist_append(m_curlHeaders.get(), header.c_str());
        }
    }

    /**
     * @brief This method performs the request.
     */
    void execute() override
    {
        curl_easy_setopt(m_curlHandle.get(), CURLOPT_HTTPHEADER, m_curlHeaders.get());

        const auto result {curl_easy_perform(m_curlHandle.get())};
        curl_easy_reset(m_curlHandle.get());
        if (result != CURLE_OK)
        {
            throw std::runtime_error(curl_easy_strerror(result));
        }
    }
};

#endif // _CURL_WRAPPER_HPP
