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

#ifndef _URL_REQUEST_HPP
#define _URL_REQUEST_HPP

#include "json.hpp"
#include "secureCommunication.hpp"
#include <atomic>
#include <functional>
#include <string>
#include <unordered_set>
#include <variant>

enum SOCKET_TYPE
{
    SOCKET_UNIX,
    SOCKET_TCP
};

enum class CurlHandlerTypeEnum
{
    SINGLE,
    MULTI
};

// HTTP headers used by default in queries.
const std::unordered_set<std::string> DEFAULT_HEADERS {
    "Content-Type: application/json", "Accept: application/json", "Accept-Charset: utf-8"};

/**
 * @brief This class is an abstraction of URL.
 * It is a base class to store the type/configuration of the request to made.
 */
class URL
{
public:
    virtual ~URL() = default;
    /**
     * @brief Returns the socket path.
     * @return Socket path.
     */
    std::string unixSocketPath() const
    {
        return m_sock;
    }

    /**
     * @brief Returns the URL host.
     * @return URL host.
     */
    std::string url() const
    {
        return m_url;
    };

    /**
     * @brief Returns the socket type.
     * @return Socket type.
     */
    SOCKET_TYPE socketType() const
    {
        return m_socketType;
    };

protected:
    /**
     * @brief Variable to store the socket type.
     */
    SOCKET_TYPE m_socketType;
    /**
     * @brief Variable to store the socket URL.
     */
    std::string m_url;
    /**
     * @brief Variable to store the socket path.
     */
    std::string m_sock;
};

/**
 * @brief This class is used to configure a HTTP Unix socket.
 */
class HttpUnixSocketURL final : public URL
{
public:
    /**
     * @brief Constructor for HttpUnixSocketURL class.

     * @param sock Unix socket path.
     * @param url Socket URL.
     */
    HttpUnixSocketURL(const std::string& sock, const std::string& url)
    {
        m_socketType = SOCKET_UNIX;
        m_sock = sock;
        m_url = url;
    }
};

/**
 * @brief This class is used to configure a TCP socket.
 */
class HttpURL final : public URL
{
public:
    /**
     * @brief Constructor for HttpURL class.
     * @param url Socket URL.
     */
    HttpURL(const std::string& url)
    {
        m_socketType = SOCKET_TCP;
        m_url = url;
    }
};

/**
 * @struct RequestParameters
 * @brief The structure groups all the parameters required for the request, like the URL, the data to be sent, the
 * headers, etc. They can be thought of as "what" to do.
 */

struct RequestParameters
{
    /**
     * @brief URL to send the request.
     *
     */
    const URL& url;

    /**
     * @brief Data to send (string or nlohmann::json).
     *
     */
    const std::variant<std::string, nlohmann::json> data = {};

    /**
     * @brief Secure communication object.
     *
     */
    const SecureCommunication& secureCommunication = {};

    /**
     * @brief Headers to be added to the query.
     *
     */
    const std::unordered_set<std::string>& httpHeaders = DEFAULT_HEADERS;
};

/**
 * @struct ConfigurationParameters
 * @brief The structure groups all the parameters that modify the behavior of the request, like the timeout, library
 * parameters configuration, etc; and everything that changes the way the request is performed.
 * They can be thought of as "how" to do.
 */
struct ConfigurationParameters
{
    /**
     * @brief Type of the cURL handler. Default is 'SINGLE'.
     *
     */
    const CurlHandlerTypeEnum& handlerType = CurlHandlerTypeEnum::SINGLE;

    /**
     * @brief Flag used to interrupt the handler when the 'handlerType' is set to 'MULTI'.
     *
     */
    const std::atomic<bool>& shouldRun = true;

    /**
     * @brief User agent to be used in the request.
     *
     */
    const std::string& userAgent = {};
};

/**
 * @struct PostRequestParameters
 * @brief The structure groups all the parameters related to the actions to be performed after the request is made, like
 * error handling, results processing, etc. They can be thought of as "what to do after".
 */
struct PostRequestParameters
{
    /**
     * @brief Callback to be called when the request is successful.
     *
     */
    std::function<void(const std::string&)> onSuccess = [](auto) {
    };

    /**
     * @brief Callback to be called when an error occurs.
     *
     */
    std::function<void(const std::string&, const long)> onError = [](auto, auto) {
    };

    /**
     * @brief File name of to store the output data.
     *
     */
    const std::string& outputFile = "";
};

/**
 * @brief This class is an interface to perform URL requests.
 * It provides a simple interface to send HTTP requests.
 */
class IURLRequest
{
public:
    virtual ~IURLRequest() = default;
    /**
     * @brief Virtual method to download a file from a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    virtual void download(RequestParameters requestParameters,
                          PostRequestParameters postRequestParameters,
                          ConfigurationParameters configurationParameters) = 0;

    /**
     * @brief Virtual method to send a POST request to a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    virtual void post(RequestParameters requestParameters,
                      PostRequestParameters postRequestParameters,
                      ConfigurationParameters configurationParameters) = 0;

    /**
     * @brief Virtual method to send a GET request to a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request..
     */
    virtual void get(RequestParameters requestParameters,
                     PostRequestParameters postRequestParameters,
                     ConfigurationParameters configurationParameters) = 0;

    /**
     * @brief Virtual method to send a UPDATE request to a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    virtual void put(RequestParameters requestParameters,
                     PostRequestParameters postRequestParameters,
                     ConfigurationParameters configurationParameters) = 0;

    /**
     * @brief Virtual method to send a PATCH request to a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    virtual void patch(RequestParameters requestParameters,
                       PostRequestParameters postRequestParameters,
                       ConfigurationParameters configurationParameters) = 0;

    /**
     * @brief Virtual method to send a DELETE request to a URL.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    virtual void delete_(RequestParameters requestParameters,
                         PostRequestParameters postRequestParameters,
                         ConfigurationParameters configurationParameters) = 0;
};

#endif // _URL_REQUEST_HPP
