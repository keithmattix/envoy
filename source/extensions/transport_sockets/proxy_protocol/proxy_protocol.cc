#include "source/extensions/transport_sockets/proxy_protocol/proxy_protocol.h"

#include <sstream>

#include "envoy/config/core/v3/proxy_protocol.pb.h"
#include "envoy/extensions/transport_sockets/proxy_protocol/v3/upstream_proxy_protocol.pb.h"
#include "envoy/extensions/transport_sockets/proxy_protocol/v3/upstream_proxy_protocol.pb.validate.h"
#include "envoy/network/transport_socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/hex.h"
#include "source/common/common/scalar_to_byte_vector.h"
#include "source/common/common/utility.h"
#include "source/common/config/well_known_names.h"
#include "source/common/network/address_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/common/proxy_protocol/proxy_protocol_header.h"

using envoy::config::core::v3::PerHostConfig;
using envoy::config::core::v3::ProxyProtocolConfig;
using envoy::config::core::v3::ProxyProtocolConfig_Version;
using envoy::config::core::v3::ProxyProtocolPassThroughTLVs;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace ProxyProtocol {

UpstreamProxyProtocolSocket::UpstreamProxyProtocolSocket(
    Network::TransportSocketPtr&& transport_socket,
    Network::TransportSocketOptionsConstSharedPtr options, ProxyProtocolConfig config,
    const UpstreamProxyProtocolStats& stats)
    : PassthroughSocket(std::move(transport_socket)), options_(options), version_(config.version()),
      stats_(stats),
      pass_all_tlvs_(config.has_pass_through_tlvs() ? config.pass_through_tlvs().match_type() ==
                                                          ProxyProtocolPassThroughTLVs::INCLUDE_ALL
                                                    : false) {
  if (config.has_pass_through_tlvs() &&
      config.pass_through_tlvs().match_type() == ProxyProtocolPassThroughTLVs::INCLUDE) {
    for (const auto& tlv_type : config.pass_through_tlvs().tlv_type()) {
      pass_through_tlvs_.insert(0xFF & tlv_type);
    }
  }
  for (const auto& entry : config.added_tlvs()) {
    added_tlvs_.push_back(Network::ProxyProtocolTLV{
        static_cast<uint8_t>(entry.type()),
        std::vector<unsigned char>(entry.value().begin(), entry.value().end())});
  }
}

void UpstreamProxyProtocolSocket::setTransportSocketCallbacks(
    Network::TransportSocketCallbacks& callbacks) {
  transport_socket_->setTransportSocketCallbacks(callbacks);
  callbacks_ = &callbacks;
}

Network::IoResult UpstreamProxyProtocolSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (header_buffer_.length() > 0) {
    auto header_res = writeHeader();
    if (header_buffer_.length() == 0 && header_res.action_ == Network::PostIoAction::KeepOpen) {
      auto inner_res = transport_socket_->doWrite(buffer, end_stream);
      return {inner_res.action_, header_res.bytes_processed_ + inner_res.bytes_processed_, false};
    }
    return header_res;
  } else {
    return transport_socket_->doWrite(buffer, end_stream);
  }
}

void UpstreamProxyProtocolSocket::generateHeader() {
  if (version_ == ProxyProtocolConfig_Version::ProxyProtocolConfig_Version_V1) {
    generateHeaderV1();
  } else {
    generateHeaderV2();
  }
}

void UpstreamProxyProtocolSocket::generateHeaderV1() {
  // Default to local addresses. Used if no downstream connection exists or
  // downstream address info is not set e.g. health checks
  auto src_addr = callbacks_->connection().connectionInfoProvider().localAddress();
  auto dst_addr = callbacks_->connection().connectionInfoProvider().remoteAddress();

  if (options_ && options_->proxyProtocolOptions().has_value()) {
    const auto options = options_->proxyProtocolOptions().value();
    src_addr = options.src_addr_;
    dst_addr = options.dst_addr_;
  }

  Common::ProxyProtocol::generateV1Header(*src_addr->ip(), *dst_addr->ip(), header_buffer_);
}

namespace {
std::string toHex(const Buffer::Instance& buffer) {
  std::string bufferStr = buffer.toString();
  return Hex::encode(reinterpret_cast<uint8_t*>(bufferStr.data()), bufferStr.length());
}
} // namespace

void UpstreamProxyProtocolSocket::generateHeaderV2() {
  if (!options_ || !options_->proxyProtocolOptions().has_value()) {
    Common::ProxyProtocol::generateV2LocalHeader(header_buffer_);
  } else {
    std::vector<Envoy::Network::ProxyProtocolTLV> custom_tlvs = buildCustomTLVs();

    const auto options = options_->proxyProtocolOptions().value();
    if (!Common::ProxyProtocol::generateV2Header(options, header_buffer_, pass_all_tlvs_,
                                                 pass_through_tlvs_, custom_tlvs)) {
      // There is a warn log in generateV2Header method.
      stats_.v2_tlvs_exceed_max_length_.inc();
    }

    ENVOY_LOG(trace, "generated proxy protocol v2 header, length: {}, buffer: {}",
              header_buffer_.length(), toHex(header_buffer_));
  }
}

Network::IoResult UpstreamProxyProtocolSocket::writeHeader() {
  Network::PostIoAction action = Network::PostIoAction::KeepOpen;
  uint64_t bytes_written = 0;
  do {
    if (header_buffer_.length() == 0) {
      break;
    }

    Api::IoCallUint64Result result = callbacks_->ioHandle().write(header_buffer_);

    if (result.ok()) {
      ENVOY_CONN_LOG(trace, "write returns: {}", callbacks_->connection(), result.return_value_);
      bytes_written += result.return_value_;
    } else {
      ENVOY_CONN_LOG(trace, "write error: {}", callbacks_->connection(),
                     result.err_->getErrorDetails());
      if (result.err_->getErrorCode() != Api::IoError::IoErrorCode::Again) {
        action = Network::PostIoAction::Close;
      }
      break;
    }
  } while (true);

  return {action, bytes_written, false};
}

void UpstreamProxyProtocolSocket::onConnected() {
  generateHeader();
  transport_socket_->onConnected();
}

UpstreamProxyProtocolSocketFactory::UpstreamProxyProtocolSocketFactory(
    Network::UpstreamTransportSocketFactoryPtr transport_socket_factory, ProxyProtocolConfig config,
    Stats::Scope& scope)
    : PassthroughFactory(std::move(transport_socket_factory)), config_(config),
      stats_(generateUpstreamProxyProtocolStats(scope)) {}

Network::TransportSocketPtr UpstreamProxyProtocolSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    Upstream::HostDescriptionConstSharedPtr host) const {
  auto inner_socket = transport_socket_factory_->createTransportSocket(options, host);
  if (inner_socket == nullptr) {
    return nullptr;
  }
  return std::make_unique<UpstreamProxyProtocolSocket>(std::move(inner_socket), options, config_,
                                                       stats_);
}

void UpstreamProxyProtocolSocketFactory::hashKey(
    std::vector<uint8_t>& key, Network::TransportSocketOptionsConstSharedPtr options) const {
  PassthroughFactory::hashKey(key, options);
  // Proxy protocol options should only be included in the hash if the upstream
  // socket intends to use them.
  if (options) {
    const auto& proxy_protocol_options = options->proxyProtocolOptions();
    if (proxy_protocol_options.has_value()) {
      pushScalarToByteVector(
          StringUtil::CaseInsensitiveHash()(proxy_protocol_options.value().asStringForHash()), key);
    }
  }
}

std::vector<Envoy::Network::ProxyProtocolTLV> UpstreamProxyProtocolSocket::buildCustomTLVs() const {
  std::vector<Envoy::Network::ProxyProtocolTLV> custom_tlvs;
  absl::flat_hash_set<uint8_t> processed_tlv_types;

  // Attempt to parse host-level TLVs first.
  const auto& upstream_info = callbacks_->connection().streamInfo().upstreamInfo();
  if (upstream_info && upstream_info->upstreamHost()) {
    auto metadata = upstream_info->upstreamHost()->metadata();
    if (metadata) {
      const auto filter_it = metadata->typed_filter_metadata().find(
          Envoy::Config::MetadataFilters::get().ENVOY_TRANSPORT_SOCKETS_PROXY_PROTOCOL);
      if (filter_it != metadata->typed_filter_metadata().end()) {
        PerHostConfig host_tlv_metadata;
        auto status = MessageUtil::unpackTo(filter_it->second, host_tlv_metadata);
        if (!status.ok()) {
          ENVOY_LOG(warn,
                    "Failed to unpack custom TLVs from upstream host metadata for host {}. "
                    "Error: {}. Will still use config-level TLVs.",
                    upstream_info->upstreamHost()->address()->asString(), status.message());
        } else {
          // Insert host-level TLVs.
          for (const auto& entry : host_tlv_metadata.added_tlvs()) {
            if (processed_tlv_types.contains(entry.type())) {
              ENVOY_LOG_EVERY_POW_2_MISC(info, "Skipping duplicate TLV type from host metadata {}",
                                         entry.type());
              continue;
            }
            custom_tlvs.push_back(Network::ProxyProtocolTLV{
                static_cast<uint8_t>(entry.type()),
                std::vector<unsigned char>(entry.value().begin(), entry.value().end())});
            processed_tlv_types.insert(entry.type());
          }
        }
      }
    }
  }

  // If host-level parse failed or was not present, we still read config-level TLVs.
  for (const auto& tlv : added_tlvs_) {
    if (processed_tlv_types.contains(tlv.type)) {
      ENVOY_LOG_EVERY_POW_2_MISC(info, "Skipping duplicate TLV type from added_tlvs {}", tlv.type);
      continue;
    }
    custom_tlvs.push_back(tlv);
    processed_tlv_types.insert(tlv.type);
  }

  return custom_tlvs;
}

} // namespace ProxyProtocol
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
