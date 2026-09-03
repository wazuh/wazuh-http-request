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

#include "ICURLHandler.hpp"
#include "IRequestImplementator.hpp"
#include "curl.h"
#include "curlHandlerCache.hpp"
#include "customDeleter.hpp"
#include <atomic>
#include <map>
#include <memory>
#include <stdexcept>

static const std::map<OPTION_REQUEST_TYPE, CURLoption> OPTION_REQUEST_TYPE_MAP = {
    {OPT_URL, CURLOPT_URL},
    {OPT_CAINFO, CURLOPT_CAINFO},
    {OPT_TIMEOUT_MS, CURLOPT_TIMEOUT_MS},
    {OPT_WRITEDATA, CURLOPT_WRITEDATA},
    {OPT_USERAGENT, CURLOPT_USERAGENT},
    {OPT_POSTFIELDS, CURLOPT_POSTFIELDS},
    {OPT_WRITEFUNCTION, CURLOPT_WRITEFUNCTION},
    {OPT_POSTFIELDSIZE, CURLOPT_POSTFIELDSIZE},
    {OPT_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST},
    {OPT_UNIX_SOCKET_PATH, CURLOPT_UNIX_SOCKET_PATH},
    {OPT_FAILONERROR, CURLOPT_FAILONERROR},
    {OPT_FOLLOW_REDIRECT, CURLOPT_FOLLOWLOCATION},
    {OPT_MAX_REDIRECTIONS, CURLOPT_MAXREDIRS},
    {OPT_VERIFYPEER, CURLOPT_SSL_VERIFYPEER},
    {OPT_SSL_CERT, CURLOPT_SSLCERT},
    {OPT_SSL_KEY, CURLOPT_SSLKEY},
    {OPT_BASIC_AUTH, CURLOPT_USERPWD},
    {OPT_ACCEPT_ENCODING, CURLOPT_ACCEPT_ENCODING},
};

auto constexpr MAX_REDIRECTIONS {20l};

/**
 * @brief This class is a wrapper of the curl library.
 */
class cURLWrapper final : public IRequestImplementator
{
private:
    using deleterCurlStringList = CustomDeleter<decltype(&curl_slist_free_all), curl_slist_free_all>;
    std::unique_ptr<curl_slist, deleterCurlStringList> m_curlHeaders;
    std::shared_ptr<ICURLHandler> m_curlHandler;

    struct ResponseData
    {
        double contentLength = 0;
        std::string& m_returnValue;
        ICURLHandler* m_curlHandler;
    };
    ResponseData m_response;

    static size_t writeData(char* data, size_t size, size_t nmemb, void* userdata)
    {
        const auto response {static_cast<ResponseData*>(userdata)};
        if (response->contentLength == 0)
        {
            curl_easy_getinfo(response->m_curlHandler->getHandler().get(),
                              CURLINFO_CONTENT_LENGTH_DOWNLOAD,
                              &response->contentLength);
            if (response->contentLength > 0)
            {
                response->m_returnValue.reserve(static_cast<size_t>(response->contentLength));
            }
        }
        response->m_returnValue.append(data, size * nmemb);
        return size * nmemb;
    }

    /**
     * @brief Get the cURL Handler object.
     *
     * @param handlerType Type of the cURL handler. Default is 'SINGLE'.
     * @param shouldRun Flag used to interrupt the cURL handler.
     * @return std::shared_ptr<ICURLHandler>
     */
    std::shared_ptr<ICURLHandler> curlHandlerInit(CurlHandlerTypeEnum handlerType,
                                                  const std::atomic<bool>& shouldRun = true)
    {
        return cURLHandlerCache::instance().getCurlHandler(handlerType, shouldRun);
    }

public:
    /**
     * @brief Create a cURLWrapper.
     *
     * @param handlerType Type of the cURL handler. Default is 'SINGLE'.
     * @param shouldRun Flag used to interrupt the handler.
     */
    cURLWrapper(std::string& returnValue,
                CurlHandlerTypeEnum handlerType = CurlHandlerTypeEnum::SINGLE,
                const std::atomic<bool>& shouldRun = true)
        : m_response {0, returnValue, nullptr}
    {
        m_curlHandler = curlHandlerInit(handlerType, shouldRun);

        if (!m_curlHandler || !m_curlHandler->getHandler())
        {
            throw std::runtime_error("cURL initialization failed");
        }

        m_response.m_curlHandler = m_curlHandler.get();

        this->setOptionPtr(OPT_WRITEFUNCTION, reinterpret_cast<void*>(cURLWrapper::writeData));

        this->setOptionPtr(OPT_WRITEDATA, &m_response);

        // this->setOptionLong(OPT_FAILONERROR, 1l);

        // Note: OPT_FAILONERROR is intentionally NOT set. This option would cause cURL
        // to fail automatically on HTTP response codes >= 400, preventing us from
        // capturing the response body. We want to allow callers to handle HTTP errors
        // with full access to the server's response.

        this->setOptionLong(OPT_FOLLOW_REDIRECT, 1l);

        this->setOptionLong(OPT_MAX_REDIRECTIONS, MAX_REDIRECTIONS);

        this->setOptionString(OPT_ACCEPT_ENCODING, "gzip");
    }

    virtual ~cURLWrapper() = default;

    /**
     * @brief This method sets an option to the curl handler.
     * @param optIndex The option index.
     * @param ptr The option value.
     */
    void setOptionPtr(const OPTION_REQUEST_TYPE optIndex, void* ptr) override
    {
        auto ret = curl_easy_setopt(m_curlHandler->getHandler().get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), ptr);

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
    void setOptionString(const OPTION_REQUEST_TYPE optIndex, const std::string& opt) override
    {
        auto ret =
            curl_easy_setopt(m_curlHandler->getHandler().get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), opt.c_str());

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
    void setOptionStringView(const OPTION_REQUEST_TYPE optIndex, std::string_view opt) override
    {
        auto ret =
            curl_easy_setopt(m_curlHandler->getHandler().get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), opt.data());

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
    void setOptionLong(const OPTION_REQUEST_TYPE optIndex, const long opt) override
    {
        auto ret = curl_easy_setopt(m_curlHandler->getHandler().get(), OPTION_REQUEST_TYPE_MAP.at(optIndex), opt);

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
        CURLcode setOptResult =
            curl_easy_setopt(m_curlHandler->getHandler().get(), CURLOPT_HTTPHEADER, m_curlHeaders.get());
        if (CURLE_OK != setOptResult)
        {
            throw std::runtime_error("cURLWrapper::execute() failed: Couldn't set HTTP headers");
        }

        try
        {
            m_curlHandler->execute();
        }
        catch (Curl::CurlException& ex)
        {
            // Note: m_returnValue contains the response body, even for errors. Could be empty if
            // the server didn't send any body.
            throw Curl::CurlException(ex.what(), ex.responseCode(), m_response.m_returnValue);
        }
    }
};

#endif // _CURL_WRAPPER_HPP
