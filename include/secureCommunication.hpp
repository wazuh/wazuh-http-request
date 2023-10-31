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

class SecureCommunication final : public Utils::Builder<SecureCommunication, std::string>
{
private:
    std::string m_caRootCertificate;
    std::string m_sslCertificate;
    std::string m_sslKey;
    std::string m_basicAuthCreds;

public:
    SecureCommunication(const std::string& caRootCertificate)
    {
        m_caRootCertificate = caRootCertificate;
    }
    ~SecureCommunication() = default;

    std::string getCARootCert()
    {
        return m_caRootCertificate;
    }

    std::string getBasicAuthCreds()
    {
        return m_basicAuthCreds;
    }

    std::string getSslCertificate()
    {
        return m_sslCertificate;
    }

    std::string getSslKey()
    {
        return m_sslKey;
    }

    SecureCommunication& setClientAuth(const std::string& sslCertificate, const std::string& sslKey)
    {
        m_sslCertificate = sslCertificate;
        m_sslKey = sslKey;

        return (*this);
    }

    SecureCommunication& setBasicAuth(const std::string& basicAuthCreds)
    {
        m_basicAuthCreds = basicAuthCreds;

        return (*this);
    }
};

#endif // __SECURE_COMMUNICATION_HPP
