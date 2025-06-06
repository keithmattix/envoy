#include "source/extensions/filters/http/oauth2/config.h"

#include <chrono>
#include <memory>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/extensions/filters/http/oauth2/v3/oauth.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/oauth2/filter.h"
#include "source/extensions/filters/http/oauth2/oauth.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oauth2 {

namespace {
Secret::GenericSecretConfigProviderSharedPtr
secretsProvider(const envoy::extensions::transport_sockets::tls::v3::SdsSecretConfig& config,
                Server::Configuration::ServerFactoryContext& server_context,
                Init::Manager& init_manager) {
  if (config.has_sds_config()) {
    return server_context.secretManager().findOrCreateGenericSecretProvider(
        config.sds_config(), config.name(), server_context, init_manager);
  } else {
    return server_context.secretManager().findStaticGenericSecretProvider(config.name());
  }
}
} // namespace

absl::StatusOr<Http::FilterFactoryCb> OAuth2Config::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  if (!proto.has_config()) {
    return absl::InvalidArgumentError("config must be present for global config");
  }

  const auto& proto_config = proto.config();
  const auto& credentials = proto_config.credentials();

  const auto& client_secret = credentials.token_secret();
  const auto& hmac_secret = credentials.hmac_secret();

  auto& server_context = context.serverFactoryContext();
  auto& cluster_manager = context.serverFactoryContext().clusterManager();

  auto secret_provider_client_secret =
      secretsProvider(client_secret, server_context, context.initManager());
  if (secret_provider_client_secret == nullptr) {
    return absl::InvalidArgumentError("invalid token secret configuration");
  }
  auto secret_provider_hmac_secret =
      secretsProvider(hmac_secret, server_context, context.initManager());
  if (secret_provider_hmac_secret == nullptr) {
    return absl::InvalidArgumentError("invalid HMAC secret configuration");
  }

  if (proto_config.preserve_authorization_header() && proto_config.forward_bearer_token()) {
    return absl::InvalidArgumentError(
        "invalid combination of forward_bearer_token and preserve_authorization_header "
        "configuration. If forward_bearer_token is set to true, then "
        "preserve_authorization_header must be false");
  }

  auto secret_reader = std::make_shared<SDSSecretReader>(
      std::move(secret_provider_client_secret), std::move(secret_provider_hmac_secret),
      context.serverFactoryContext().threadLocal(), context.serverFactoryContext().api());
  auto config = std::make_shared<FilterConfig>(proto_config, context.serverFactoryContext(),
                                               secret_reader, context.scope(), stats_prefix);

  return
      [&context, config, &cluster_manager](Http::FilterChainFactoryCallbacks& callbacks) -> void {
        std::unique_ptr<OAuth2Client> oauth_client =
            std::make_unique<OAuth2ClientImpl>(cluster_manager, config->oauthTokenEndpoint(),
                                               config->retryPolicy(), config->defaultExpiresIn());
        callbacks.addStreamFilter(std::make_shared<OAuth2Filter>(
            config, std::move(oauth_client), context.serverFactoryContext().timeSource(),
            context.serverFactoryContext().api().randomGenerator()));
      };
}

/*
 * Static registration for the OAuth2 filter. @see RegisterFactory.
 */
REGISTER_FACTORY(OAuth2Config, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace Oauth2
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
