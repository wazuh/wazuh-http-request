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
#include "curlWrapper.hpp"
#include "factoryRequestImplemetator.hpp"
#include "json.hpp"
#include "urlRequest.hpp"
#include <atomic>
#include <string>
#include <unordered_set>
#include <variant>

using wrapperType = cURLWrapper;

void HTTPRequest::download(std::variant<TRequestParameters<std::string>,
                                        TRequestParameters<nlohmann::json>,
                                        TRequestParameters<std::string_view>> requestParameters,
                           std::variant<TPostRequestParameters<const std::string&>,
                                        TPostRequestParameters<std::string&&>> postRequestParameters,
                           ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string returnValue;
        std::visit(
            [&](auto&& arg)
            {
                GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(returnValue, handlerType, shouldRun))
                    .url(arg.url.url(), arg.secureCommunication)
                    .outputFile(outputFile)
                    .appendHeaders(arg.httpHeaders)
                    .timeout(timeout)
                    .userAgent(userAgent)
                    .execute();
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void HTTPRequest::post(std::variant<TRequestParameters<std::string>,
                                    TRequestParameters<nlohmann::json>,
                                    TRequestParameters<std::string_view>> requestParameters,
                       std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>
                           postRequestParameters,
                       ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string response;
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {PostRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<std::string_view>>)
                {
                    auto req {PostRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<std::string_view>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const std::string data = arg.data.dump();
                    auto req {PostRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void HTTPRequest::get(std::variant<TRequestParameters<std::string>,
                                   TRequestParameters<nlohmann::json>,
                                   TRequestParameters<std::string_view>> requestParameters,
                      std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>
                          postRequestParameters,
                      ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string response;
        std::visit(
            [&](auto&& arg)
            {
                auto req {
                    GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                req.url(arg.url.url(), arg.secureCommunication)
                    .appendHeaders(arg.httpHeaders)
                    .timeout(timeout)
                    .userAgent(userAgent)
                    .outputFile(outputFile)
                    .execute();

                std::visit(
                    [&](auto&& arg)
                    {
                        using Tb = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                        {
                            arg.onSuccess(response);
                        }
                        else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                        {
                            arg.onSuccess(std::move(response));
                        }
                    },
                    postRequestParameters);
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void HTTPRequest::put(std::variant<TRequestParameters<std::string>,
                                   TRequestParameters<nlohmann::json>,
                                   TRequestParameters<std::string_view>> requestParameters,
                      std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>
                          postRequestParameters,
                      ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string response;
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {PutRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<std::string_view>>)
                {
                    auto req {PutRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<std::string_view>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const std::string data = arg.data.dump();
                    auto req {PutRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void HTTPRequest::patch(std::variant<TRequestParameters<std::string>,
                                     TRequestParameters<nlohmann::json>,
                                     TRequestParameters<std::string_view>> requestParameters,
                        std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>
                            postRequestParameters,
                        ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string response;
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {PatchRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<std::string_view>>)
                {
                    auto req {PatchRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<std::string_view>(arg.data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const std::string data = arg.data.dump();
                    auto req {PatchRequest::builder(
                        FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .template postData<const std::string&>(data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    std::visit(
                        [&](auto&& arg)
                        {
                            using Tb = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                            {
                                arg.onSuccess(response);
                            }
                            else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                            {
                                arg.onSuccess(std::move(response));
                            }
                        },
                        postRequestParameters);
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void HTTPRequest::delete_(std::variant<TRequestParameters<std::string>,
                                       TRequestParameters<nlohmann::json>,
                                       TRequestParameters<std::string_view>> requestParameters,
                          std::variant<TPostRequestParameters<const std::string&>,
                                       TPostRequestParameters<std::string&&>> postRequestParameters,
                          ConfigurationParameters configurationParameters)
{
    // Post request parameters
    const auto& onError {std::visit([](auto&& arg) { return arg.onError; }, postRequestParameters)};
    const auto& outputFile {std::visit([](auto&& arg) { return arg.outputFile; }, postRequestParameters)};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::string response;
        std::visit(
            [&](auto&& arg)
            {
                auto req {DeleteRequest::builder(
                    FactoryRequestWrapper<wrapperType>::create(response, handlerType, shouldRun))};
                req.url(arg.url.url(), arg.secureCommunication)
                    .appendHeaders(arg.httpHeaders)
                    .timeout(timeout)
                    .userAgent(userAgent)
                    .outputFile(outputFile)
                    .execute();

                std::visit(
                    [&](auto&& arg)
                    {
                        using Tb = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<Tb, TPostRequestParameters<const std::string&>>)
                        {
                            arg.onSuccess(response);
                        }
                        else if constexpr (std::is_same_v<Tb, TPostRequestParameters<std::string&&>>)
                        {
                            arg.onSuccess(std::move(response));
                        }
                    },
                    postRequestParameters);
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}
