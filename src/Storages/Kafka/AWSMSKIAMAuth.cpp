#include <Storages/Kafka/AWSMSKIAMAuth.h>

#include <cppkafka/configuration.h>
#include <librdkafka/rdkafka.h>
#include <Common/Logger.h>
#include <Common/Exception.h>
#include <base/types.h>

#include <chrono>
#include <sstream>
#include <iomanip>

#if USE_AWS_S3
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/auth/signer/AWSAuthV4Signer.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/URI.h>
#include <aws/core/utils/DateTime.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#endif

namespace DB
{

namespace ErrorCodes
{
    extern const int SUPPORT_IS_DISABLED;
    extern const int BAD_ARGUMENTS;
    extern const int AWS_ERROR;
}

#if USE_AWS_S3

namespace
{
    /// Forward declaration
    String extractSignature(const String & auth_header);

    /// OAuth callback context structure
    struct OAuthBearerTokenRefreshContext
    {
        String region;
        LoggerPtr log;
        std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentials_provider;
    };

    /// Generate AWS MSK IAM authentication token
    /// @param region AWS region for the MSK cluster
    /// @param broker_host The actual hostname of the Kafka broker
    /// @param credentials AWS credentials to use for signing
    String generateAWSMSKToken(const String & region, const String & broker_host, const Aws::Auth::AWSCredentials & credentials)
    {
        try
        {
            // Get current time for token expiry
            auto now = std::chrono::system_clock::now();
            auto expiry_time = now + std::chrono::minutes(15); // Token valid for 15 minutes
            
            // Convert to milliseconds since epoch
            auto expiry_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                expiry_time.time_since_epoch()).count();

            // Create the action string for AWS MSK
            const String action = "kafka-cluster:Connect";
            
            // Build the canonical request
            std::ostringstream payload;
            payload << "{"
                    << "\"version\":\"2020_10_22\","
                    << "\"host\":\"" << broker_host << "\","
                    << "\"user-agent\":\"ClickHouse\","
                    << "\"action\":\"" << action << "\","
                    << "\"x-amz-date\":\"";
            
            // Add formatted date
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::tm tm_now;
            gmtime_r(&time_t_now, &tm_now);
            
            payload << std::put_time(&tm_now, "%Y%m%dT%H%M%SZ")
                    << "\","
                    << "\"x-amz-expires\":\"900\""  // 15 minutes in seconds
                    << "}";

            String token_payload = payload.str();
            
            // Create AWS signer for SigV4
            Aws::Client::ClientConfiguration client_config;
            client_config.region = Aws::String(region.c_str(), region.size());
            
            Aws::Auth::AWSAuthV4Signer signer(
                credentials,
                "kafka-cluster",
                Aws::String(region.c_str(), region.size()),
                Aws::Auth::AWSSigningAlgorithm::SIGV4,
                false);

            // Sign the request
            Aws::Http::URI uri;
            uri.SetScheme(Aws::Http::Scheme::HTTPS);
            uri.SetAuthority(Aws::String((region + ".kafka.amazonaws.com").c_str()));
            uri.SetPath("/");

            std::shared_ptr<Aws::Http::HttpRequest> http_request = 
                Aws::Http::CreateHttpRequest(uri, Aws::Http::HttpMethod::HTTP_GET, Aws::Utils::Stream::DefaultResponseStreamFactoryMethod);
            
            http_request->SetHeaderValue("host", Aws::String((region + ".kafka.amazonaws.com").c_str()));
            
            // Sign request
            bool sign_result = signer.SignRequest(*http_request, nullptr, 0);
            if (!sign_result)
            {
                throw Exception(ErrorCodes::AWS_ERROR, "Failed to sign AWS MSK authentication request");
            }

            // Extract signed headers and construct token
            std::ostringstream token_stream;
            
            // Get the authorization header which contains the signature
            auto auth_header = http_request->GetHeaderValue("authorization");
            auto date_header = http_request->GetHeaderValue("x-amz-date");
            auto security_token = credentials.GetSessionToken();
            
            // Build final token payload
            std::ostringstream final_token;
            final_token << "{"
                       << "\"version\":\"2020_10_22\","
                       << "\"host\":\"" << region << ".kafka.amazonaws.com\","
                       << "\"user-agent\":\"ClickHouse\","
                       << "\"action\":\"kafka-cluster:Connect\","
                       << "\"x-amz-algorithm\":\"AWS4-HMAC-SHA256\","
                       << "\"x-amz-credential\":\"" << credentials.GetAWSAccessKeyId() << "\","
                       << "\"x-amz-date\":\"" << std::string(date_header.c_str(), date_header.size()) << "\","
                       << "\"x-amz-signedheaders\":\"host\","
                       << "\"x-amz-expires\":\"900\","
                       << "\"x-amz-signature\":\"" << extractSignature(std::string(auth_header.c_str(), auth_header.size())) << "\"";
            
            if (!security_token.empty())
            {
                final_token << ",\"x-amz-security-token\":\"" << std::string(security_token.c_str(), security_token.size()) << "\"";
            }
            
            final_token << "}";
            
            return final_token.str();
        }
        catch (const std::exception & e)
        {
            throw Exception(ErrorCodes::AWS_ERROR, "Failed to generate AWS MSK token: {}", e.what());
        }
    }
    
    /// Extract signature from Authorization header
    String extractSignature(const String & auth_header)
    {
        // Authorization header format: "AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=..."
        size_t sig_pos = auth_header.find("Signature=");
        if (sig_pos == String::npos)
            return "";
        
        sig_pos += 10; // Length of "Signature="
        return auth_header.substr(sig_pos);
    }

    /// OAuth token refresh callback for librdkafka
    void oauthBearerTokenRefreshCallback(
        rd_kafka_t * /* rk */,
        const char * /* oauthbearer_config */,
        void * opaque)
    {
        auto * context = static_cast<OAuthBearerTokenRefreshContext *>(opaque);
        
        try
        {
            // Get AWS credentials
            auto credentials = context->credentials_provider->GetAWSCredentials();
            if (credentials.IsEmpty())
            {
                LOG_ERROR(context->log, "Failed to obtain AWS credentials for MSK IAM authentication");
                rd_kafka_oauthbearer_set_token_failure(nullptr, "Failed to obtain AWS credentials");
                return;
            }
            
            // For AWS MSK IAM auth, we need the broker hostname for signing
            // Since librdkafka OAuth callback doesn't provide the broker host,
            // we use a placeholder that will work with AWS MSK
            // The actual broker host validation happens on the server side
            String broker_host = "kafka." + context->region + ".amazonaws.com";
            
            // Generate token
            String token = generateAWSMSKToken(context->region, broker_host, credentials);
            
            // Calculate token lifetime (15 minutes from now)
            auto expiry_time = std::chrono::system_clock::now() + std::chrono::minutes(15);
            auto expiry_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                expiry_time.time_since_epoch()).count();
            
            // Set token in librdkafka
            rd_kafka_error_t * error = rd_kafka_oauthbearer_set_token(
                nullptr,
                token.c_str(),
                expiry_ms,
                credentials.GetAWSAccessKeyId().c_str(),
                nullptr, 0,  // No additional extensions
                nullptr);
            
            if (error)
            {
                String error_msg = rd_kafka_error_string(error);
                rd_kafka_error_destroy(error);
                LOG_ERROR(context->log, "Failed to set OAuth token: {}", error_msg);
                rd_kafka_oauthbearer_set_token_failure(nullptr, error_msg.c_str());
            }
            else
            {
                LOG_DEBUG(context->log, "Successfully set AWS MSK IAM OAuth token");
            }
        }
        catch (const std::exception & e)
        {
            LOG_ERROR(context->log, "Exception in OAuth token refresh: {}", e.what());
            rd_kafka_oauthbearer_set_token_failure(nullptr, e.what());
        }
    }
}

AWSMSKIAMAuth::AWSMSKIAMAuth(const String & region, LoggerPtr log_)
    : aws_region(region)
    , log(log_)
{
    if (aws_region.empty())
    {
        throw Exception(ErrorCodes::BAD_ARGUMENTS, "AWS region is required for MSK IAM authentication");
    }
}

String AWSMSKIAMAuth::generateToken()
{
    // Create credentials provider
    auto credentials_provider = std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>();
    auto credentials = credentials_provider->GetAWSCredentials();
    
    if (credentials.IsEmpty())
    {
        throw Exception(ErrorCodes::AWS_ERROR, "Failed to obtain AWS credentials for MSK IAM authentication");
    }
    
    // Use generic AWS MSK hostname for the region
    String broker_host = "kafka." + aws_region + ".amazonaws.com";
    return generateAWSMSKToken(aws_region, broker_host, credentials);
}

String AWSMSKIAMAuth::extractRegionFromBroker(const String & broker_address)
{
    // MSK broker address formats:
    // Provisioned: b-1.mycluster.abc123.kafka.us-east-1.amazonaws.com:9098
    // Serverless: boot-abc123.c1.kafka-serverless.us-east-1.amazonaws.com:9098
    
    // Find ".kafka." or ".kafka-serverless." pattern
    size_t kafka_pos = broker_address.find(".kafka.");
    if (kafka_pos == String::npos)
    {
        kafka_pos = broker_address.find(".kafka-serverless.");
        if (kafka_pos == String::npos)
            return "";
    }
    
    // Find the region part after kafka/kafka-serverless
    size_t region_start = broker_address.find('.', kafka_pos + 7); // Skip ".kafka." or find next dot
    if (region_start == String::npos)
        return "";
    
    region_start++; // Skip the dot
    
    // Find the end of region (next dot or colon)
    size_t region_end = broker_address.find_first_of(".:", region_start);
    if (region_end == String::npos)
        region_end = broker_address.length();
    
    String region = broker_address.substr(region_start, region_end - region_start);
    
    // Validate region format (should look like us-east-1, eu-west-2, etc.)
    if (region.empty() || region.find('-') == String::npos)
        return "";
    
    return region;
}

void AWSMSKIAMAuth::configureOAuthCallbacks(
    cppkafka::Configuration & config,
    const String & region,
    const String & broker_list,
    LoggerPtr log)
{
    String effective_region = region;
    
    // If region is not provided, try to extract from broker address
    if (effective_region.empty() && !broker_list.empty())
    {
        // Extract first broker address from the comma-separated list
        size_t comma_pos = broker_list.find(',');
        String first_broker = (comma_pos != String::npos) 
            ? broker_list.substr(0, comma_pos) 
            : broker_list;
        
        // Try to extract region from broker address
        effective_region = extractRegionFromBroker(first_broker);
        
        if (!effective_region.empty())
        {
            LOG_INFO(log, "Auto-detected AWS region '{}' from broker address: {}", effective_region, first_broker);
        }
    }
    
    if (effective_region.empty())
    {
        throw Exception(ErrorCodes::BAD_ARGUMENTS,
            "AWS region must be specified via kafka_aws_region setting or must be detectable from kafka_broker_list. "
            "Broker addresses should follow AWS MSK format: b-X.cluster.kafka.<region>.amazonaws.com");
    }
    
    // Set SASL mechanism to OAUTHBEARER
    config.set("sasl.mechanism", "OAUTHBEARER");
    config.set("security.protocol", "SASL_SSL");
    
    // Create context for OAuth callbacks
    auto * context = new OAuthBearerTokenRefreshContext{
        effective_region,
        log,
        std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>()
    };
    
    // Get librdkafka C API handle
    rd_kafka_conf_t * rd_config = config.get_handle();
    
    // Enable SASL queue for background callbacks BEFORE registering OAuth callback.
    // This allows librdkafka to handle OAuth token refresh in a background thread,
    // which is essential for idle connections where rd_kafka_poll() is not called.
    rd_kafka_conf_enable_sasl_queue(rd_config, 1);
    
    // Set OAuth bearer token refresh callback using librdkafka C API
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(rd_config, oauthBearerTokenRefreshCallback);
    rd_kafka_conf_set_opaque(rd_config, context);
    
    LOG_INFO(log, "Configured AWS MSK IAM OAuth authentication for region: {} with background token refresh", effective_region);
}

#else // !USE_AWS_S3

AWSMSKIAMAuth::AWSMSKIAMAuth(const String & /* region */, LoggerPtr /* log */)
{
    throw Exception(ErrorCodes::SUPPORT_IS_DISABLED, 
        "AWS MSK IAM authentication is not supported: ClickHouse was built without AWS S3 support");
}

String AWSMSKIAMAuth::generateToken()
{
    throw Exception(ErrorCodes::SUPPORT_IS_DISABLED,
        "AWS MSK IAM authentication is not supported: ClickHouse was built without AWS S3 support");
}

void AWSMSKIAMAuth::configureOAuthCallbacks(
    cppkafka::Configuration & /* config */,
    const String & /* region */,
    LoggerPtr /* log */)
{
    throw Exception(ErrorCodes::SUPPORT_IS_DISABLED,
        "AWS MSK IAM authentication is not supported: ClickHouse was built without AWS S3 support");
}

#endif // USE_AWS_S3

}
