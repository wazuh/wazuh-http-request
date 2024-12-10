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
#include <variant>

namespace urlrequest
{
enum class AuthenticationParameter
{
    SSL_CERTIFICATE,
    SSL_KEY,
    CA_ROOT_CERTIFICATE,
    BASIC_AUTH_CREDS,
    SKIP_PEER_VERIFICATION
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
    std::map<urlrequest::AuthenticationParameter, std::variant<std::string, bool>> m_parameters;

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
     * @brief Set the Skip Peer Verification.
     *
     * @param skipPeerVerification Skip peer verification.
     */
    SecureCommunication& skipPeerVerification(const bool skipPeerVerification)
    {
        m_parameters[urlrequest::AuthenticationParameter::SKIP_PEER_VERIFICATION] = skipPeerVerification;

        return (*this);
    }

    /**
     * @brief Get parameters.
     *
     * @tparam T Type of the parameter, std::string or bool.
     * @param parameter AuthenticationParameter Parameter to get.
     *
     * @return T Parameter value.
     */
    template<typename T = std::string>
    T getParameter(const urlrequest::AuthenticationParameter parameter) const
    {
        auto it = m_parameters.find(parameter);
        if (it != m_parameters.end())
        {
            return std::get<T>(it->second);
        }
        return {};
    }
};

#endif // __SECURE_COMMUNICATION_HPP
