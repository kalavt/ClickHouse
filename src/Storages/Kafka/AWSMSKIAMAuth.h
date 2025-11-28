#pragma once

#include <base/types.h>
#include <memory>
#include <string>

namespace cppkafka
{
class Configuration;
}

namespace DB
{

class LoggerPtr;

/// AWS MSK IAM SASL/OAUTHBEARER authentication handler
/// This class generates OAuth tokens for AWS MSK using IAM credentials
class AWSMSKIAMAuth
{
public:
    /// Initialize AWS MSK IAM authentication
    /// @param region AWS region where MSK cluster is located
    /// @param log Logger instance for logging
    AWSMSKIAMAuth(const String & region, LoggerPtr log);

    /// Generate OAuth token for AWS MSK
    /// Returns the signed OAuth token string
    String generateToken();

    /// Configure Kafka client with AWS MSK IAM OAuth callbacks
    /// @param config Kafka configuration object to update
    /// @param region AWS region for the MSK cluster
    /// @param broker_list Comma-separated list of broker addresses
    /// @param log Logger instance
    static void configureOAuthCallbacks(cppkafka::Configuration & config, const String & region, const String & broker_list, LoggerPtr log);
    
    /// Extract AWS region from MSK broker address
    /// @param broker_address A broker address like "b-1.cluster.kafka.us-east-1.amazonaws.com:9098"
    /// @return The extracted region (e.g., "us-east-1") or empty string if not found
    static String extractRegionFromBroker(const String & broker_address);

private:
    String aws_region;
    LoggerPtr log;
    
    /// Generate the OAuth token payload for AWS MSK
    String generateTokenPayload();
    
    /// Sign the token payload using AWS SigV4
    String signToken(const String & payload);
};

}
