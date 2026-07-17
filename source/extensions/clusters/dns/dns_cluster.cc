#include "source/extensions/clusters/dns/dns_cluster.h"

// The purpose of these two headers is purely for backward compatibility.
// Never create new dependencies to symbols declared in these headers!
#include <chrono>

#include "envoy/common/exception.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/endpoint/v3/endpoint_components.pb.h"
#include "envoy/extensions/clusters/dns/v3/dns_cluster.pb.h"

#include "source/common/common/dns_utils.h"
#include "source/common/network/dns_resolver/dns_factory_util.h"
#include "source/extensions/clusters/common/dns_cluster_backcompat.h"
#include "source/extensions/clusters/common/logical_host.h"
#include "source/extensions/clusters/logical_dns/logical_dns_cluster.h"
#include "source/extensions/clusters/strict_dns/strict_dns_cluster.h"
#include "source/extensions/load_balancing_policies/round_robin/round_robin_lb.h"

namespace Envoy {
namespace Upstream {

namespace {

class OnDemandDnsLoadBalancerFactory : public LoadBalancerFactory {
public:
  OnDemandDnsLoadBalancerFactory(std::weak_ptr<DnsClusterImpl> cluster)
      : cluster_(std::move(cluster)) {}

  // Upstream::LoadBalancerFactory
  LoadBalancerPtr create(LoadBalancerParams params) override;
  bool recreateOnHostChangeDeprecated() const override { return false; }

private:
  std::weak_ptr<DnsClusterImpl> cluster_;
};

bool usesClusterProvidedLoadBalancing(const envoy::config::cluster::v3::Cluster& cluster) {
  if (cluster.has_load_balancing_policy()) {
    const auto& policies = cluster.load_balancing_policy().policies();
    if (policies.empty()) {
      return false;
    }
    return policies[0].typed_extension_config().name() ==
           "envoy.load_balancing_policies.cluster_provided";
  }

  return cluster.lb_policy() == envoy::config::cluster::v3::Cluster::CLUSTER_PROVIDED;
}

} // namespace

absl::StatusOr<std::pair<ClusterImplBaseSharedPtr, ThreadAwareLoadBalancerPtr>>
DnsClusterFactory::createClusterWithConfig(
    const envoy::config::cluster::v3::Cluster& cluster,
    const envoy::extensions::clusters::dns::v3::DnsCluster& proto_config,
    Upstream::ClusterFactoryContext& context) {
  if (proto_config.on_demand() && !usesClusterProvidedLoadBalancing(cluster)) {
    return absl::InvalidArgumentError(
        "DNS cluster on_demand requires cluster-provided load balancing");
  }

  auto dns_resolver_or_error = selectDnsResolver(proto_config.typed_dns_resolver_config(), context);

  RETURN_IF_NOT_OK(dns_resolver_or_error.status());

  absl::StatusOr<std::unique_ptr<ClusterImplBase>> cluster_or_error;

  if (proto_config.on_demand() ||
      Runtime::runtimeFeatureEnabled("envoy.reloadable_features.enable_new_dns_implementation")) {
    cluster_or_error =
        DnsClusterImpl::create(cluster, proto_config, context, std::move(*dns_resolver_or_error));
  } else if (proto_config.all_addresses_in_single_endpoint()) {
    cluster_or_error = LogicalDnsCluster::create(cluster, proto_config, context,
                                                 std::move(*dns_resolver_or_error));
  } else {
    cluster_or_error = StrictDnsClusterImpl::create(cluster, proto_config, context,
                                                    std::move(*dns_resolver_or_error));
  }

  RETURN_IF_NOT_OK(cluster_or_error.status());
  ClusterImplBaseSharedPtr new_cluster(std::move(*cluster_or_error));
  if (proto_config.on_demand()) {
    auto dns_cluster = std::static_pointer_cast<DnsClusterImpl>(new_cluster);
    auto lb = std::make_unique<DnsClusterImpl::ThreadAwareLoadBalancer>(dns_cluster);
    return std::make_pair(std::move(new_cluster), std::move(lb));
  }
  return std::make_pair(std::move(new_cluster), nullptr);
}

REGISTER_FACTORY(DnsClusterFactory, ClusterFactory);

class LegacyDnsClusterFactory : public ClusterFactoryImplBase {
public:
  LegacyDnsClusterFactory(const std::string& name, bool set_all_addresses_in_single_endpoint)
      : ClusterFactoryImplBase(name),
        set_all_addresses_in_single_endpoint_(set_all_addresses_in_single_endpoint) {}
  absl::StatusOr<std::pair<ClusterImplBaseSharedPtr, ThreadAwareLoadBalancerPtr>>
  createClusterImpl(const envoy::config::cluster::v3::Cluster& cluster,
                    ClusterFactoryContext& context) override {
    absl::StatusOr<Network::DnsResolverSharedPtr> dns_resolver_or_error =
        selectDnsResolver(cluster, context);
    RETURN_IF_NOT_OK(dns_resolver_or_error.status());

    envoy::extensions::clusters::dns::v3::DnsCluster typed_config;
    createDnsClusterFromLegacyFields(cluster, typed_config);

    typed_config.set_all_addresses_in_single_endpoint(set_all_addresses_in_single_endpoint_);

    absl::StatusOr<std::unique_ptr<ClusterImplBase>> cluster_or_error;

    if (Runtime::runtimeFeatureEnabled("envoy.reloadable_features.enable_new_dns_implementation")) {
      cluster_or_error =
          DnsClusterImpl::create(cluster, typed_config, context, std::move(*dns_resolver_or_error));
    } else if (set_all_addresses_in_single_endpoint_) {
      cluster_or_error = LogicalDnsCluster::create(cluster, typed_config, context,
                                                   std::move(*dns_resolver_or_error));
    } else {
      cluster_or_error = StrictDnsClusterImpl::create(cluster, typed_config, context,
                                                      std::move(*dns_resolver_or_error));
    }

    RETURN_IF_NOT_OK(cluster_or_error.status());
    return std::make_pair(ClusterImplBaseSharedPtr(std::move(*cluster_or_error)), nullptr);
  }

private:
  bool set_all_addresses_in_single_endpoint_{false};
};

/**
 * LogicalDNSFactory: making it back compatible with ClusterFactoryImplBase.
 */

class LogicalDNSFactory : public LegacyDnsClusterFactory {
public:
  LogicalDNSFactory() : LegacyDnsClusterFactory("envoy.cluster.logical_dns", true) {}
};

REGISTER_FACTORY(LogicalDNSFactory, ClusterFactory);

/**
 * StrictDNSFactory: making it back compatible with ClusterFactoryImplBase
 */

class StrictDNSFactory : public LegacyDnsClusterFactory {
public:
  StrictDNSFactory() : LegacyDnsClusterFactory("envoy.cluster.strict_dns", false) {}
};

REGISTER_FACTORY(StrictDNSFactory, ClusterFactory);

envoy::config::endpoint::v3::ClusterLoadAssignment
DnsClusterImpl::extractAndProcessLoadAssignment(const envoy::config::cluster::v3::Cluster& cluster,
                                                bool all_addresses_in_single_endpoint) {
  // In Logical DNS we convert the priority set by the configuration back to zero.
  // This helps ensure that we don't blow up later when using zone aware routing,
  // as it only supports load assignments with priority 0.
  //
  // Since Logical DNS is limited to exactly one host declared per load_assignment
  // (enforced in DnsClusterImpl::DnsClusterImpl), we can safely just rewrite the priority
  // to zero.
  if (all_addresses_in_single_endpoint) {
    envoy::config::endpoint::v3::ClusterLoadAssignment converted;
    converted.MergeFrom(cluster.load_assignment());
    for (auto& endpoint : *converted.mutable_endpoints()) {
      endpoint.set_priority(0);
    }
    return converted;
  }

  return cluster.load_assignment();
}

/**
 * DnsClusterImpl: implementation for both logical and strict DNS.
 */

class DnsClusterImpl::ThreadLocalState : public ThreadLocal::ThreadLocalObject {
public:
  ~ThreadLocalState() override;
  void add(OnDemandHostSelectionHandle& handle) { pending_handles_.insert(&handle); }
  void remove(OnDemandHostSelectionHandle& handle) { pending_handles_.erase(&handle); }
  void onResolveComplete(const std::string& details);

private:
  absl::flat_hash_set<OnDemandHostSelectionHandle*> pending_handles_;
};

absl::StatusOr<std::unique_ptr<DnsClusterImpl>>
DnsClusterImpl::create(const envoy::config::cluster::v3::Cluster& cluster,
                       const envoy::extensions::clusters::dns::v3::DnsCluster& dns_cluster,
                       ClusterFactoryContext& context, Network::DnsResolverSharedPtr dns_resolver) {
  absl::Status creation_status = absl::OkStatus();
  auto ret = std::unique_ptr<DnsClusterImpl>(
      new DnsClusterImpl(cluster, dns_cluster, context, std::move(dns_resolver), creation_status));

  RETURN_IF_NOT_OK(creation_status);
  return ret;
}

DnsClusterImpl::DnsClusterImpl(const envoy::config::cluster::v3::Cluster& cluster,
                               const envoy::extensions::clusters::dns::v3::DnsCluster& dns_cluster,
                               ClusterFactoryContext& context,
                               Network::DnsResolverSharedPtr dns_resolver,
                               absl::Status& creation_status)
    : BaseDynamicClusterImpl(cluster, context, creation_status),
      load_assignment_(
          extractAndProcessLoadAssignment(cluster, dns_cluster.all_addresses_in_single_endpoint())),
      local_info_(context.serverFactoryContext().localInfo()),
      main_thread_dispatcher_(context.serverFactoryContext().mainThreadDispatcher()),
      time_source_(context.serverFactoryContext().timeSource()), dns_resolver_(dns_resolver),
      tls_slot_(context.serverFactoryContext().threadLocal()),
      dns_refresh_rate_ms_(std::chrono::milliseconds(
          PROTOBUF_GET_MS_OR_DEFAULT(dns_cluster, dns_refresh_rate, 5000))),
      dns_min_refresh_rate_ms_(std::chrono::milliseconds(
          PROTOBUF_GET_MS_OR_DEFAULT(dns_cluster, dns_min_refresh_rate, 0))),
      dns_jitter_ms_(PROTOBUF_GET_MS_OR_DEFAULT(dns_cluster, dns_jitter, 0)),
      respect_dns_ttl_(dns_cluster.respect_dns_ttl()),
      dns_lookup_family_(
          Envoy::DnsUtils::getDnsLookupFamilyFromEnum(dns_cluster.dns_lookup_family())),
      all_addresses_in_single_endpoint_(dns_cluster.all_addresses_in_single_endpoint()),
      on_demand_(dns_cluster.on_demand()) {
  failure_backoff_strategy_ = Config::Utility::prepareDnsRefreshStrategy(
      dns_cluster, dns_refresh_rate_ms_.count(),
      context.serverFactoryContext().api().randomGenerator());

  if (on_demand_) {
    tls_slot_.set([](Event::Dispatcher&) { return std::make_shared<ThreadLocalState>(); });
  }

  std::list<ResolveTargetPtr> resolve_targets;
  const auto& locality_lb_endpoints = load_assignment_.endpoints();

  if (all_addresses_in_single_endpoint_) { // Logical DNS
    // For Logical DNS, we make sure we have just a single endpoint.
    if (locality_lb_endpoints.size() != 1 || locality_lb_endpoints[0].lb_endpoints().size() != 1) {
      if (cluster.has_load_assignment()) {
        creation_status =
            absl::InvalidArgumentError("LOGICAL_DNS clusters must have a single "
                                       "locality_lb_endpoint and a single lb_endpoint");
      } else {
        creation_status =
            absl::InvalidArgumentError("LOGICAL_DNS clusters must have a single host");
      }
      return;
    }
  } else { // Strict DNS
    // Strict DNS clusters must ensure that the priority for all localities
    // are set to zero when using zone-aware routing. Zone-aware routing only
    // works for localities with priority zero (the highest).
    SET_AND_RETURN_IF_NOT_OK(validateEndpoints(locality_lb_endpoints, {}), creation_status);
  }

  for (const auto& locality_lb_endpoint : locality_lb_endpoints) {
    for (const auto& lb_endpoint : locality_lb_endpoint.lb_endpoints()) {
      const auto& socket_address = lb_endpoint.endpoint().address().socket_address();
      if (!socket_address.resolver_name().empty()) {
        creation_status = absl::InvalidArgumentError(
            all_addresses_in_single_endpoint_
                ? "LOGICAL_DNS clusters must NOT have a custom resolver name set"
                : "STRICT_DNS clusters must NOT have a custom resolver name set");
        return;
      }

      resolve_targets.emplace_back(new ResolveTarget(
          *this, context.serverFactoryContext().mainThreadDispatcher(), socket_address.address(),
          socket_address.port_value(), locality_lb_endpoint, lb_endpoint));
    }
  }
  resolve_targets_ = std::move(resolve_targets);

  overprovisioning_factor_ = PROTOBUF_GET_WRAPPED_OR_DEFAULT(
      load_assignment_.policy(), overprovisioning_factor, kDefaultOverProvisioningFactor);
  weighted_priority_health_ = load_assignment_.policy().weighted_priority_health();
}

void DnsClusterImpl::startPreInit() {
  if (on_demand_) {
    onPreInitComplete();
    return;
  }
  for (const ResolveTargetPtr& target : resolve_targets_) {
    target->startResolve();
  }
  // If the config provides no endpoints, the cluster is initialized immediately as if all hosts are
  // resolved in failure.
  if (resolve_targets_.empty() || !wait_for_warm_on_init_) {
    onPreInitComplete();
  }
}

class DnsClusterImpl::LoadBalancer : public Upstream::LoadBalancer {
public:
  LoadBalancer(std::weak_ptr<DnsClusterImpl> cluster, LoadBalancerParams params)
      : cluster_(std::move(cluster)) {
    auto locked_cluster = cluster_.lock();
    if (locked_cluster) {
      envoy::extensions::load_balancing_policies::round_robin::v3::RoundRobin config;
      lb_ = std::make_unique<RoundRobinLoadBalancer>(
          params.priority_set, params.local_priority_set, locked_cluster->info()->lbStats(),
          locked_cluster->runtime_, locked_cluster->random_,
          PROTOBUF_PERCENT_TO_ROUNDED_INTEGER_OR_DEFAULT(locked_cluster->info()->lbConfig(),
                                                         healthy_panic_threshold, 100, 50),
          config, locked_cluster->time_source_);
    }
  }
  ~LoadBalancer() override;

  // Upstream::LoadBalancer
  HostSelectionResponse chooseHost(LoadBalancerContext* context) override;
  HostConstSharedPtr peekAnotherHost(LoadBalancerContext* context) override {
    return chooseResolvedHost(context).host;
  }
  OptRef<Http::ConnectionPool::ConnectionLifetimeCallbacks> lifetimeCallbacks() override {
    return std::nullopt;
  }
  std::optional<SelectedPoolAndConnection>
  selectExistingConnection(LoadBalancerContext*, const Host&, std::vector<uint8_t>&) override {
    return std::nullopt;
  }

  HostSelectionResponse chooseResolvedHost(LoadBalancerContext*);
  void add(OnDemandHostSelectionHandle& handle) { pending_host_selection_handles_.insert(&handle); }
  void remove(OnDemandHostSelectionHandle& handle) {
    pending_host_selection_handles_.erase(&handle);
  }

private:
  std::weak_ptr<DnsClusterImpl> cluster_;
  LoadBalancerPtr lb_;
  absl::flat_hash_set<OnDemandHostSelectionHandle*> pending_host_selection_handles_;
};

class DnsClusterImpl::OnDemandHostSelectionHandle : public AsyncHostSelectionHandle {
public:
  OnDemandHostSelectionHandle(LoadBalancerContext& context, LoadBalancer& load_balancer,
                              ThreadLocalState& thread_local_state)
      : context_(context), load_balancer_(load_balancer), thread_local_state_(thread_local_state) {
    thread_local_state_.add(*this);
    load_balancer_.add(*this);
  }
  ~OnDemandHostSelectionHandle() override { cancel(); }

  // Upstream::AsyncHostSelectionHandle
  void cancel() override {
    if (registered_) {
      thread_local_state_.remove(*this);
      load_balancer_.remove(*this);
      registered_ = false;
    }
  }

  void onResolveComplete(const std::string& details) {
    if (!registered_) {
      return;
    }
    thread_local_state_.remove(*this);
    load_balancer_.remove(*this);
    registered_ = false;
    auto host_selection = load_balancer_.chooseResolvedHost(&context_);
    context_.onAsyncHostSelection(std::move(host_selection.host), host_selection.details.empty()
                                                                      ? std::string(details)
                                                                      : host_selection.details);
  }

  void onLoadBalancerDestroyed() {
    if (!registered_) {
      return;
    }
    thread_local_state_.remove(*this);
    load_balancer_.remove(*this);
    registered_ = false;
    context_.onAsyncHostSelection(nullptr, "load_balancer_destroyed");
  }

  void onThreadLocalStateDestroyed() {
    if (!registered_) {
      return;
    }
    load_balancer_.remove(*this);
    registered_ = false;
  }

private:
  LoadBalancerContext& context_;
  LoadBalancer& load_balancer_;
  ThreadLocalState& thread_local_state_;
  bool registered_{true};
};

DnsClusterImpl::LoadBalancer::~LoadBalancer() {
  while (!pending_host_selection_handles_.empty()) {
    (*pending_host_selection_handles_.begin())->onLoadBalancerDestroyed();
  }
}

HostSelectionResponse DnsClusterImpl::LoadBalancer::chooseHost(LoadBalancerContext* context) {
  auto host_selection = chooseResolvedHost(context);
  if (host_selection.host != nullptr || context == nullptr) {
    return host_selection;
  }

  auto cluster = cluster_.lock();
  if (!cluster) {
    return {nullptr, "on_demand_dns_cluster_destroyed"};
  }

  ThreadLocalState& thread_local_state = *cluster->tls_slot_;
  auto handle = std::make_unique<OnDemandHostSelectionHandle>(*context, *this, thread_local_state);
  cluster->main_thread_dispatcher_.post([cluster]() { cluster->startOnDemandResolve(); });
  return {nullptr, std::move(handle)};
}

HostSelectionResponse
DnsClusterImpl::LoadBalancer::chooseResolvedHost(LoadBalancerContext* context) {
  if (lb_ == nullptr) {
    return {nullptr, "on_demand_dns_cluster_destroyed"};
  }
  auto host_selection = lb_->chooseHost(context);
  if (host_selection.host == nullptr && host_selection.details.empty()) {
    host_selection.details = "on_demand_dns_not_resolved";
  }
  return host_selection;
}

DnsClusterImpl::ThreadLocalState::~ThreadLocalState() {
  while (!pending_handles_.empty()) {
    (*pending_handles_.begin())->onThreadLocalStateDestroyed();
  }
}

void DnsClusterImpl::ThreadLocalState::onResolveComplete(const std::string& details) {
  std::vector<OnDemandHostSelectionHandle*> handles(pending_handles_.begin(),
                                                    pending_handles_.end());
  for (auto* handle : handles) {
    handle->onResolveComplete(details);
  }
}

LoadBalancerPtr OnDemandDnsLoadBalancerFactory::create(LoadBalancerParams params) {
  return std::make_unique<DnsClusterImpl::LoadBalancer>(cluster_, params);
}

LoadBalancerFactorySharedPtr DnsClusterImpl::ThreadAwareLoadBalancer::factory() {
  return std::make_shared<OnDemandDnsLoadBalancerFactory>(cluster_);
}

void DnsClusterImpl::startOnDemandResolve() {
  ASSERT(main_thread_dispatcher_.isThreadSafe());
  if (on_demand_resolve_in_progress_) {
    return;
  }
  if (resolve_targets_.empty()) {
    notifyPendingOnDemandHostSelections("on_demand_dns_no_resolve_targets");
    return;
  }
  on_demand_resolve_in_progress_ = true;
  pending_on_demand_resolve_targets_ = resolve_targets_.size();
  on_demand_resolve_details_ = "on_demand_dns_not_resolved";
  for (const ResolveTargetPtr& target : resolve_targets_) {
    target->startResolve();
  }
}

void DnsClusterImpl::onDemandResolveTargetComplete(std::string details) {
  if (!on_demand_ || !on_demand_resolve_in_progress_) {
    return;
  }
  if (!details.empty()) {
    on_demand_resolve_details_ = std::move(details);
  }
  ASSERT(pending_on_demand_resolve_targets_ > 0);
  --pending_on_demand_resolve_targets_;
  if (pending_on_demand_resolve_targets_ > 0) {
    return;
  }
  on_demand_resolve_in_progress_ = false;
  notifyPendingOnDemandHostSelections(std::move(on_demand_resolve_details_));
}

void DnsClusterImpl::notifyPendingOnDemandHostSelections(std::string details) {
  if (!on_demand_) {
    return;
  }
  tls_slot_.runOnAllThreads([details = std::move(details)](OptRef<ThreadLocalState> local_state) {
    if (!local_state.has_value()) {
      return;
    }
    local_state->onResolveComplete(details);
  });
}

void DnsClusterImpl::updateAllHosts(const HostVector& hosts_added, const HostVector& hosts_removed,
                                    uint32_t current_priority) {
  PriorityStateManager priority_state_manager(*this, local_info_, nullptr);
  // At this point we know that we are different so make a new host list and notify.
  //
  // TODO(dio): The uniqueness of a host address resolved in STRICT_DNS cluster per priority is not
  // guaranteed. Need a clear agreement on the behavior here, whether it is allowable to have
  // duplicated hosts inside a priority. And if we want to enforce this behavior, it should be done
  // inside the priority state manager.
  for (const ResolveTargetPtr& target : resolve_targets_) {
    priority_state_manager.initializePriorityFor(target->locality_lb_endpoints_);
    for (const HostSharedPtr& host : target->hosts_) {
      if (target->locality_lb_endpoints_.priority() == current_priority) {
        priority_state_manager.registerHostForPriority(host, target->locality_lb_endpoints_);
      }
    }
  }

  // TODO(dio): Add assertion in here.
  priority_state_manager.updateClusterPrioritySet(
      current_priority, std::move(priority_state_manager.priorityState()[current_priority].first),
      hosts_added, hosts_removed, std::nullopt, weighted_priority_health_,
      overprovisioning_factor_);
}

DnsClusterImpl::ResolveTarget::ResolveTarget(
    DnsClusterImpl& parent, Event::Dispatcher& dispatcher, const std::string& dns_address,
    const uint32_t dns_port,
    const envoy::config::endpoint::v3::LocalityLbEndpoints& locality_lb_endpoint,
    const envoy::config::endpoint::v3::LbEndpoint& lb_endpoint)
    : parent_(parent), locality_lb_endpoints_(locality_lb_endpoint), lb_endpoint_(lb_endpoint),
      dns_address_(dns_address),
      hostname_(lb_endpoint_.endpoint().hostname().empty() ? dns_address_
                                                           : lb_endpoint_.endpoint().hostname()),
      port_(dns_port),
      resolve_timer_(dispatcher.createTimer([this]() -> void { startResolve(); })) {}

DnsClusterImpl::ResolveTarget::~ResolveTarget() {
  if (active_query_) {
    active_query_->cancel(Network::ActiveDnsQuery::CancelReason::QueryAbandoned);
  }
}

bool DnsClusterImpl::ResolveTarget::isSuccessfulResponse(
    const std::list<Network::DnsResponse>& response,
    const Network::DnsResolver::ResolutionStatus& status) {
  if (parent_.all_addresses_in_single_endpoint_) {
    // Logical DNS doesn't accept empty responses.
    return status == Network::DnsResolver::ResolutionStatus::Completed && !response.empty();
  } else {
    // For Strict DNS, an empty response just means no available hosts.
    return status == Network::DnsResolver::ResolutionStatus::Completed;
  }
}

absl::StatusOr<DnsClusterImpl::ResolveTarget::ParsedHosts>
DnsClusterImpl::ResolveTarget::createLogicalDnsHosts(
    const std::list<Network::DnsResponse>& response) {
  ParsedHosts result;
  const auto& addrinfo = response.front().addrInfo();
  Network::Address::InstanceConstSharedPtr new_address =
      Network::Utility::getAddressWithPort(*(addrinfo.address_), port_);
  auto address_list = DnsUtils::generateAddressList(response, port_);
  auto logical_host_or_error =
      LogicalHost::create(parent_.info_, hostname_, new_address, address_list,
                          locality_lb_endpoints_, lb_endpoint_, nullptr);

  RETURN_IF_NOT_OK(logical_host_or_error.status());

  result.hosts.emplace_back(std::move(logical_host_or_error.value()));
  result.host_addresses.emplace(new_address->asString());
  result.ttl_refresh_rate = min(result.ttl_refresh_rate, addrinfo.ttl_);
  return result;
}

absl::StatusOr<DnsClusterImpl::ResolveTarget::ParsedHosts>
DnsClusterImpl::ResolveTarget::createStrictDnsHosts(
    const std::list<Network::DnsResponse>& response) {
  ParsedHosts result;
  for (const auto& resp : response) {
    const auto& addrinfo = resp.addrInfo();
    // TODO(mattklein123): Currently the DNS interface does not consider port. We need to
    // make a new address that has port in it. We need to both support IPv6 as well as
    // potentially move port handling into the DNS interface itself, which would work
    // better for SRV.
    ASSERT(addrinfo.address_ != nullptr);
    auto address = Network::Utility::getAddressWithPort(*(addrinfo.address_), port_);
    if (result.host_addresses.count(address->asString()) > 0) {
      continue;
    }

    auto host_or_error = HostImpl::create(
        parent_.info_, hostname_, address,
        // TODO(zyfjeff): Created through metadata shared pool
        std::make_shared<const envoy::config::core::v3::Metadata>(lb_endpoint_.metadata()),
        std::make_shared<const envoy::config::core::v3::Metadata>(
            locality_lb_endpoints_.metadata()),
        lb_endpoint_.load_balancing_weight().value(),
        parent_.constLocalitySharedPool()->getObject(locality_lb_endpoints_.locality()),
        lb_endpoint_.endpoint().health_check_config(), locality_lb_endpoints_.priority(),
        lb_endpoint_.health_status());

    RETURN_IF_NOT_OK(host_or_error.status());

    result.hosts.emplace_back(std::move(host_or_error.value()));
    result.host_addresses.emplace(address->asString());
    result.ttl_refresh_rate = min(result.ttl_refresh_rate, addrinfo.ttl_);
  }
  return result;
}

void DnsClusterImpl::ResolveTarget::updateLogicalDnsHosts(
    const std::list<Network::DnsResponse>& response, const ParsedHosts& new_hosts) {
  Network::Address::InstanceConstSharedPtr primary_address =
      Network::Utility::getAddressWithPort(*(response.front().addrInfo().address_), port_);
  auto all_addresses = DnsUtils::generateAddressList(response, port_);
  if (!logic_dns_cached_address_ ||
      (*primary_address != *logic_dns_cached_address_ ||
       DnsUtils::listChanged(logic_dns_cached_address_list_, all_addresses))) {
    logic_dns_cached_address_ = primary_address;
    logic_dns_cached_address_list_ = std::move(all_addresses);
    ENVOY_LOG(debug, "DNS hosts have changed for {}", dns_address_);
    const auto previous_hosts = std::move(hosts_);
    hosts_ = std::move(new_hosts.hosts);
    // For logical DNS, we remove the unique logical host, and add the new one.
    parent_.updateAllHosts(new_hosts.hosts, previous_hosts, locality_lb_endpoints_.priority());
  } else {
    parent_.info_->configUpdateStats().update_no_rebuild_.inc();
  }
}

void DnsClusterImpl::ResolveTarget::updateStrictDnsHosts(const ParsedHosts& new_hosts) {
  HostVector hosts_added;
  HostVector hosts_removed;
  if (parent_.updateDynamicHostList(new_hosts.hosts, hosts_, hosts_added, hosts_removed, all_hosts_,
                                    new_hosts.host_addresses)) {
    ENVOY_LOG(debug, "DNS hosts have changed for {}", dns_address_);
    ASSERT(std::all_of(hosts_.begin(), hosts_.end(), [&](const auto& host) {
      return host->priority() == locality_lb_endpoints_.priority();
    }));

    // Update host map for current resolve target.
    for (const auto& host : hosts_removed) {
      all_hosts_.erase(host->address()->asString());
    }
    for (const auto& host : hosts_added) {
      all_hosts_.insert({host->address()->asString(), host});
    }

    parent_.updateAllHosts(hosts_added, hosts_removed, locality_lb_endpoints_.priority());
  } else {
    parent_.info_->configUpdateStats().update_no_rebuild_.inc();
  }
}

void DnsClusterImpl::ResolveTarget::startResolve() {
  if (active_query_ != nullptr) {
    return;
  }
  ENVOY_LOG(trace, "starting async DNS resolution for {}", dns_address_);
  parent_.info_->configUpdateStats().update_attempt_.inc();

  active_query_ = parent_.dns_resolver_->resolve(
      dns_address_, parent_.dns_lookup_family_,
      [this](Network::DnsResolver::ResolutionStatus status, absl::string_view details,
             std::list<Network::DnsResponse>&& response) -> void {
        active_query_ = nullptr;
        ENVOY_LOG(trace, "async DNS resolution complete for {} details {}", dns_address_, details);

        std::chrono::milliseconds final_refresh_rate = parent_.dns_refresh_rate_ms_;

        if (isSuccessfulResponse(response, status)) {
          parent_.info_->configUpdateStats().update_success_.inc();

          absl::StatusOr<ParsedHosts> new_hosts_or_error;

          if (parent_.all_addresses_in_single_endpoint_) {
            new_hosts_or_error = createLogicalDnsHosts(response);
          } else {
            new_hosts_or_error = createStrictDnsHosts(response);
          }

          if (!new_hosts_or_error.ok()) {
            ENVOY_LOG(error, "Failed to process DNS response for {} with error: {}", dns_address_,
                      new_hosts_or_error.status().message());
            parent_.info_->configUpdateStats().update_failure_.inc();
            parent_.onDemandResolveTargetComplete(
                std::string(new_hosts_or_error.status().message()));
            return;
          }

          const auto& new_hosts = new_hosts_or_error.value();

          if (parent_.all_addresses_in_single_endpoint_) {
            updateLogicalDnsHosts(response, new_hosts);
          } else {
            updateStrictDnsHosts(new_hosts);
          }

          // reset failure backoff strategy because there was a success.
          parent_.failure_backoff_strategy_->reset();

          if (!response.empty() && parent_.respect_dns_ttl_ &&
              new_hosts.ttl_refresh_rate != std::chrono::seconds(0)) {
            final_refresh_rate = std::max(std::chrono::milliseconds(new_hosts.ttl_refresh_rate),
                                          parent_.dns_min_refresh_rate_ms_);
            ASSERT(new_hosts.ttl_refresh_rate != std::chrono::seconds::max() &&
                   final_refresh_rate.count() > 0);
          }
          if (parent_.dns_jitter_ms_.count() > 0) {
            // Note that `parent_.random_.random()` returns a uint64 while
            // `parent_.dns_jitter_ms_.count()` returns a signed long that gets cast into a uint64.
            // Thus, the modulo of the two will be a positive as long as
            // `parent_dns_jitter_ms_.count()` is positive.
            // It is important that this be positive, otherwise `final_refresh_rate` could be
            // negative causing Envoy to crash.
            final_refresh_rate += std::chrono::milliseconds(parent_.random_.random() %
                                                            parent_.dns_jitter_ms_.count());
          }

          ENVOY_LOG(debug, "DNS refresh rate reset for {}, refresh rate {} ms", dns_address_,
                    final_refresh_rate.count());
        } else {
          parent_.info_->configUpdateStats().update_failure_.inc();

          final_refresh_rate =
              std::chrono::milliseconds(parent_.failure_backoff_strategy_->nextBackOffMs());
          ENVOY_LOG(debug, "DNS refresh rate reset for {}, (failure) refresh rate {} ms",
                    dns_address_, final_refresh_rate.count());
        }

        // If there is an initialize callback, fire it now. Note that if the cluster refers to
        // multiple DNS names, this will return initialized after a single DNS resolution
        // completes. This is not perfect but is easier to code and unclear if the extra
        // complexity is needed so will start with this.
        parent_.onPreInitComplete();
        resolve_timer_->enableTimer(final_refresh_rate);
        parent_.onDemandResolveTargetComplete(std::string(details));
      });
}

} // namespace Upstream
} // namespace Envoy
