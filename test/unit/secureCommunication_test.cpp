/*
 * Wazuh URLRequest unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "secureCommunication_test.hpp"
#include "secureCommunication.hpp"

TEST_F(SecureCommunicationTest, CACertificate)
{
    auto secureCom {std::make_shared<SecureCommunication>("root-ca.pem")};
    EXPECT_EQ(secureCom->getCARootCert(), "root-ca.pem");
    EXPECT_EQ(secureCom->getBasicAuthCreds(), "");
    EXPECT_EQ(secureCom->getSslCertificate(), "");
    EXPECT_EQ(secureCom->getSslKey(), "");
}

TEST_F(SecureCommunicationTest, BasicAuth)
{
    auto secureCom {std::make_shared<SecureCommunication>("root-ca.pem")};
    secureCom->setBasicAuth("user:pass");
    EXPECT_EQ(secureCom->getCARootCert(), "root-ca.pem");
    EXPECT_EQ(secureCom->getBasicAuthCreds(), "user:pass");
    EXPECT_EQ(secureCom->getSslCertificate(), "");
    EXPECT_EQ(secureCom->getSslKey(), "");
}

TEST_F(SecureCommunicationTest, ClientAuthentication)
{
    auto secureCom {std::make_shared<SecureCommunication>("root-ca.pem")};
    secureCom->setClientAuth("ssl_cert.pem", "ssl_key.pem");
    EXPECT_EQ(secureCom->getCARootCert(), "root-ca.pem");
    EXPECT_EQ(secureCom->getBasicAuthCreds(), "");
    EXPECT_EQ(secureCom->getSslCertificate(), "ssl_cert.pem");
    EXPECT_EQ(secureCom->getSslKey(), "ssl_key.pem");
}

TEST_F(SecureCommunicationTest, BasicAndClientAuth)
{
    auto secureCom {std::make_shared<SecureCommunication>("root-ca.pem")};
    secureCom->setBasicAuth("user:pass");
    secureCom->setClientAuth("ssl_cert.pem", "ssl_key.pem");
    EXPECT_EQ(secureCom->getCARootCert(), "root-ca.pem");
    EXPECT_EQ(secureCom->getBasicAuthCreds(), "user:pass");
    EXPECT_EQ(secureCom->getSslCertificate(), "ssl_cert.pem");
    EXPECT_EQ(secureCom->getSslKey(), "ssl_key.pem");
}
