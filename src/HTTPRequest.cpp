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
#include <string>
#include <unordered_set>

using wrapperType = cURLWrapper;

void HTTPRequest::download(const URL& url,
                           const std::string& outputFile,
                           std::function<void(const std::string&, const long)> onError,
                           const std::unordered_set<std::string>& httpHeaders,
                           std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url(url.url(), secureCommunication)
            .outputFile(outputFile)
            .appendHeaders(httpHeaders)
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

void HTTPRequest::post(const URL& url,
                       const nlohmann::json& data,
                       std::function<void(const std::string&)> onSuccess,
                       std::function<void(const std::string&, const long)> onError,
                       const std::string& fileName,
                       const std::unordered_set<std::string>& httpHeaders,
                       std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        post(url, data.dump(), onSuccess, onError, fileName, httpHeaders, secureCommunication);
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void HTTPRequest::post(const URL& url,
                       const std::string& data,
                       std::function<void(const std::string&)> onSuccess,
                       std::function<void(const std::string&, const long)> onError,
                       const std::string& fileName,
                       const std::unordered_set<std::string>& httpHeaders,
                       std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        auto req {PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())};
        req.url(url.url(), secureCommunication)
            .postData(data)
            .appendHeaders(httpHeaders)
            .outputFile(fileName)
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

void HTTPRequest::get(const URL& url,
                      std::function<void(const std::string&)> onSuccess,
                      std::function<void(const std::string&, const long)> onError,
                      const std::string& fileName,
                      const std::unordered_set<std::string>& httpHeaders,
                      std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())};
        req.url(url.url(), secureCommunication).appendHeaders(httpHeaders).outputFile(fileName).execute();

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

void HTTPRequest::put(const URL& url,
                      const nlohmann::json& data,
                      std::function<void(const std::string&)> onSuccess,
                      std::function<void(const std::string&, const long)> onError,
                      const std::string& fileName,
                      const std::unordered_set<std::string>& httpHeaders,
                      std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        put(url, data.dump(), onSuccess, onError, fileName, httpHeaders, secureCommunication);
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void HTTPRequest::put(const URL& url,
                      const std::string& data,
                      std::function<void(const std::string&)> onSuccess,
                      std::function<void(const std::string&, const long)> onError,
                      const std::string& fileName,
                      const std::unordered_set<std::string>& httpHeaders,
                      std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        auto req {PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())};
        req.url(url.url(), secureCommunication)
            .postData(data)
            .appendHeaders(httpHeaders)
            .outputFile(fileName)
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

void HTTPRequest::patch(const URL& url,
                        const nlohmann::json& data,
                        std::function<void(const std::string&)> onSuccess,
                        std::function<void(const std::string&, const long)> onError,
                        const std::string& fileName,
                        const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        patch(url, data.dump(), onSuccess, onError, fileName, httpHeaders);
    }
    catch (const std::exception& ex)
    {
        onError(ex.what(), NOT_USED);
    }
}

void HTTPRequest::patch(const URL& url,
                        const std::string& data,
                        std::function<void(const std::string&)> onSuccess,
                        std::function<void(const std::string&, const long)> onError,
                        const std::string& fileName,
                        const std::unordered_set<std::string>& httpHeaders)
{
    try
    {
        auto req {PatchRequest::builder(FactoryRequestWrapper<wrapperType>::create())};
        req.url(url.url()).postData(data).appendHeaders(httpHeaders).outputFile(fileName).execute();

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
                          const std::unordered_set<std::string>& httpHeaders,
                          std::shared_ptr<SecureCommunication> secureCommunication)
{
    try
    {
        auto req {DeleteRequest::builder(FactoryRequestWrapper<cURLWrapper>::create())};
        req.url(url.url(), secureCommunication).appendHeaders(httpHeaders).outputFile(fileName).execute();

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
