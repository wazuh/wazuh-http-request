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

#include "HTTPRequest.hpp"
#include "factoryRequestImplemetator.hpp"
#include "json.hpp"
#include "urlRequest.hpp"
#include <algorithm>
#include <string>
#include <unordered_set>

using wrapperType = cURLWrapper;

void HTTPRequest::download(const URL& url,
                           const std::string& outputFile,
                           std::function<void(const std::string&, const long)> onError,
                           const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())};

        std::for_each(
            httpHeaders.begin(), httpHeaders.end(), [&req](const std::string& header) { req.appendHeader(header); });

        req.url(url.url()).outputFile(outputFile).execute();
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

void HTTPRequest::post(const URL& url,
                       const nlohmann::json& data,
                       std::function<void(const std::string&)> onSuccess,
                       std::function<void(const std::string&, const long)> onError,
                       const std::string& fileName,
                       const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())};

        std::for_each(
            httpHeaders.begin(), httpHeaders.end(), [&req](const std::string& header) { req.appendHeader(header); });

        req.url(url.url()).postData(data).outputFile(fileName).execute();

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

void HTTPRequest::get(const URL& url,
                      std::function<void(const std::string&)> onSuccess,
                      std::function<void(const std::string&, const long)> onError,
                      const std::string& fileName,
                      const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())};

        std::for_each(
            httpHeaders.begin(), httpHeaders.end(), [&req](const std::string& header) { req.appendHeader(header); });

        req.url(url.url()).outputFile(fileName).execute();

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

void HTTPRequest::update(const URL& url,
                         const nlohmann::json& data,
                         std::function<void(const std::string&)> onSuccess,
                         std::function<void(const std::string&, const long)> onError,
                         const std::string& fileName,
                         const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())};

        std::for_each(
            httpHeaders.begin(), httpHeaders.end(), [&req](const std::string& header) { req.appendHeader(header); });

        req.url(url.url()).postData(data).outputFile(fileName).execute();

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

void HTTPRequest::delete_(const URL& url,
                          std::function<void(const std::string&)> onSuccess,
                          std::function<void(const std::string&, const long)> onError,
                          const std::string& fileName,
                          const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {DeleteRequest::builder(FactoryRequestWrapper<cURLWrapper>::create())};

        std::for_each(
            httpHeaders.begin(), httpHeaders.end(), [&req](const std::string& header) { req.appendHeader(header); });

        req.url(url.url()).outputFile(fileName).execute();

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
