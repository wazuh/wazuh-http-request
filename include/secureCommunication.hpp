/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __SECURE_COMMUNICATION_HPP
#define __SECURE_COMMUNICATION_HPP

#include <map>
#include <string>

namespace urlrequest
{
enum class AuthenticationParameter
{
    SSL_CERTIFICATE,
    SSL_KEY,
    CA_ROOT_CERTIFICATE,
    BASIC_AUTH_CREDS
};
/**
 * @brief This class provides a simple interface to construct an object using a Builder pattern.
 *
 * @tparam T Type of the object to be built.
 * @tparam Ts Arguments.
 */
template<typename T, class... Ts>
class Builder
{
public:
    /**
     * @brief This method is used to build an object.
     *
     * @param args Arguments.
     * @return T Object built.
     */
    static T builder(Ts... args)
    {
        return T(std::move(args)...); // Default constructor
    }

    /**
     * @brief This method returns a reference to the object.
     * @return T Reference to the object.
     */
    T& build()
    {
        return static_cast<T&>(*this); // Return reference to self
    }
};
} // namespace urlrequest

/**
 * @brief SecureCommunication class.
 *
 */
class SecureCommunication final : public urlrequest::Builder<SecureCommunication>
{
private:
    std::map<urlrequest::AuthenticationParameter, std::string> m_parameters;

public:
    /**
     * @brief Set the Client Authentication.
     *
     * @param sslCertificate SSL certificate path.
     */
    SecureCommunication& sslCertificate(const std::string& sslCertificate)
    {
        m_parameters[urlrequest::AuthenticationParameter::SSL_CERTIFICATE] = sslCertificate;

        return (*this);
    }

    /**
     * @brief Set the client key.
     *
     * @param sslKey SSL key path.
     */
    SecureCommunication& sslKey(const std::string& sslKey)
    {
        m_parameters[urlrequest::AuthenticationParameter::SSL_KEY] = sslKey;

        return (*this);
    }

    /**
     * @brief Set the CA Root Certificate.
     *
     * @param caRootCertificate CA certificate path.
     */
    SecureCommunication& caRootCertificate(const std::string& caRootCertificate)
    {
        m_parameters[urlrequest::AuthenticationParameter::CA_ROOT_CERTIFICATE] = caRootCertificate;

        return (*this);
    }

    /**
     * @brief Set the Basic Authentication credentials.
     *
     * @param basicAuthCreds Username and password.
     */
    SecureCommunication& basicAuth(const std::string& basicAuthCreds)
    {
        m_parameters[urlrequest::AuthenticationParameter::BASIC_AUTH_CREDS] = basicAuthCreds;

        return (*this);
    }

    /**
     * @brief Get parameters.
     *
     * @param parameter AuthenticationParameter Parameter to get.
     *
     * @return std::string Parameter value.
     */
    std::string getParameter(const urlrequest::AuthenticationParameter parameter) const
    {
        auto it = m_parameters.find(parameter);
        if (it != m_parameters.end())
        {
            return it->second;
        }
        return {};
    }
};

#endif // __SECURE_COMMUNICATION_HPP
