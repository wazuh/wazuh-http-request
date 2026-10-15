/*
 * Wazuh URLRequest unit tests
 * Copyright (C) Wazuh Inc.
 * October 30, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "secureCommunication_test.hpp"
#include "secureCommunication.hpp"

TEST_F(SecureCommunicationTest, CACertificate)
{
    auto secureCom = SecureCommunication::builder().caRootCertificate("root-ca.pem");

    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::CA_ROOT_CERTIFICATE), "root-ca.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::BASIC_AUTH_CREDS), "");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_CERTIFICATE), "");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_KEY), "");
}

TEST_F(SecureCommunicationTest, BasicAuth)
{
    auto secureCom = SecureCommunication::builder().basicAuth("user:pass").caRootCertificate("root-ca.pem");

    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::CA_ROOT_CERTIFICATE), "root-ca.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::BASIC_AUTH_CREDS), "user:pass");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_CERTIFICATE), "");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_KEY), "");
}

TEST_F(SecureCommunicationTest, ClientAuthentication)
{
    auto secureCom = SecureCommunication::builder()
                         .sslCertificate("ssl_cert.pem")
                         .sslKey("ssl_key.pem")
                         .caRootCertificate("root-ca.pem");

    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::CA_ROOT_CERTIFICATE), "root-ca.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::BASIC_AUTH_CREDS), "");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_CERTIFICATE), "ssl_cert.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_KEY), "ssl_key.pem");
}

TEST_F(SecureCommunicationTest, BasicAndClientAuth)
{
    auto secureCom = SecureCommunication::builder()
                         .basicAuth("user:pass")
                         .sslCertificate("ssl_cert.pem")
                         .sslKey("ssl_key.pem")
                         .caRootCertificate("root-ca.pem");

    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::CA_ROOT_CERTIFICATE), "root-ca.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::BASIC_AUTH_CREDS), "user:pass");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_CERTIFICATE), "ssl_cert.pem");
    EXPECT_EQ(secureCom.getParameter(AuthenticationParameter::SSL_KEY), "ssl_key.pem");
}
