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

#include "builder.hpp"
#include <string>

/**
 * @brief SecureCommunication class.
 *
 */
class SecureCommunication final : public Utils::Builder<SecureCommunication, std::string>
{
private:
    std::string m_caRootCertificate;
    std::string m_sslCertificate;
    std::string m_sslKey;
    std::string m_basicAuthCreds;

public:
    /**
     * @brief Construct a new Secure Communication object.
     *
     * @param caRootCertificate CA certificate path.
     */
    SecureCommunication(const std::string& caRootCertificate)
        : m_caRootCertificate {caRootCertificate}
    {
    }

    /**
     * @brief Destroy the Secure Communication object.
     *
     */
    ~SecureCommunication() = default;

    /**
     * @brief Return the CA certificate path.
     *
     * @return std::string
     */
    std::string getCARootCert()
    {
        return m_caRootCertificate;
    }

    /**
     * @brief Returns the credentials for basic authentication.
     *
     * @return std::string
     */
    std::string getBasicAuthCreds()
    {
        return m_basicAuthCreds;
    }

    /**
     * @brief Get the Ssl Certificate path.
     *
     * @return std::string
     */
    std::string getSslCertificate()
    {
        return m_sslCertificate;
    }

    /**
     * @brief Get the Ssl Key pah.
     *
     * @return std::string
     */
    std::string getSslKey()
    {
        return m_sslKey;
    }

    /**
     * @brief Set the Client Authentication.
     *
     * @param sslCertificate SSL certificate path.
     * @param sslKey SSL key path.
     */
    SecureCommunication& setClientAuth(const std::string& sslCertificate, const std::string& sslKey)
    {
        m_sslCertificate = sslCertificate;
        m_sslKey = sslKey;

        return (*this);
    }

    /**
     * @brief Set the Basic Authentication credentials.
     *
     * @param basicAuthCreds Username and password.
     */
    SecureCommunication& setBasicAuth(const std::string& basicAuthCreds)
    {
        m_basicAuthCreds = basicAuthCreds;

        return (*this);
    }
};

#endif // __SECURE_COMMUNICATION_HPP
