/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "UNIXSocketRequest.hpp"
#include "factoryRequestImplemetator.hpp"
#include "urlRequest.hpp"
#include <atomic>
#include <string>
#include <unordered_set>

using wrapperType = cURLWrapper;

void UNIXSocketRequest::download(RequestParameters requestParameters,
                                 PostRequestParameters postRequestParameters = {},
                                 ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, _, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))
            .url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .outputFile(outputFile)
            .execute();
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void UNIXSocketRequest::post(RequestParameters requestParameters,
                             PostRequestParameters postRequestParameters = {},
                             ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, data, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        std::string dataString = std::holds_alternative<std::string>(data) ? std::get<std::string>(data)
                                                                           : std::get<nlohmann::json>(data).dump();

        auto req {PostRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
        req.url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .postData(data)
            .outputFile(outputFile)
            .execute();

        onSuccess(req.response());
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void UNIXSocketRequest::get(RequestParameters requestParameters,
                            PostRequestParameters postRequestParameters = {},
                            ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, _, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
        req.url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .outputFile(outputFile)
            .execute();

        onSuccess(req.response());
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void UNIXSocketRequest::put(RequestParameters requestParameters,
                            PostRequestParameters postRequestParameters = {},
                            ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, data, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        std::string dataString = std::holds_alternative<std::string>(data) ? std::get<std::string>(data)
                                                                           : std::get<nlohmann::json>(data).dump();

        auto req {PutRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
        req.url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .postData(data)
            .outputFile(outputFile)
            .execute();

        onSuccess(req.response());
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void UNIXSocketRequest::patch(RequestParameters requestParameters,
                              PostRequestParameters postRequestParameters = {},
                              ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, data, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        std::string dataString = std::holds_alternative<std::string>(data) ? std::get<std::string>(data)
                                                                           : std::get<nlohmann::json>(data).dump();

        auto req {PatchRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
        req.url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .postData(data)
            .outputFile(outputFile)
            .execute();

        onSuccess(req.response());
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void UNIXSocketRequest::delete_(RequestParameters requestParameters,
                                PostRequestParameters postRequestParameters = {},
                                ConfigurationParameters configurationParameters = {})
{
    // Request parameters
    const auto& [url, _, secureCommunication, httpHeaders] = requestParameters;
    // Post request parameters
    const auto& [onSuccess, onError, outputFile] = postRequestParameters;
    // Request parameters
    const auto& [handlerType, shouldRun, userAgent] = configurationParameters;

    try
    {
        auto req {DeleteRequest::builder(FactoryRequestWrapper<cURLWrapper>::create())};
        req.url(url.url(), secureCommunication)
            .unixSocketPath(url.unixSocketPath())
            .userAgent(userAgent)
            .outputFile(outputFile)
            .execute();

        onSuccess(req.response());
    }
    catch (const Curl::CurlException& ex)
    {
        onError(ex.what(), ex.responseCode());
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}
