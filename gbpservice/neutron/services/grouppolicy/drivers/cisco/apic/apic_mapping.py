#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
import sqlalchemy as sa
from sqlalchemy.orm import exc as orm_exc

from apicapi import apic_manager
from keystoneclient.v2_0 import client as keyclient
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.db import model_base
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers.cisco.apic import config
from opflexagent import constants as ofcst
from opflexagent import rpc
from oslo.config import cfg
from oslo_concurrency import lockutils

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.extensions import servicechain as schain
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)
from gbpservice.neutron.services.grouppolicy import group_policy_context

LOG = logging.getLogger(__name__)


class PolicyRuleUpdateNotSupportedOnApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule update is not supported on APIC GBP"
                "driver.")


class ExactlyOneActionPerRuleIsSupportedOnApicDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Exactly one action per rule is supported on APIC GBP driver.")


class OnlyOneL3PolicyIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one L3 Policy per ES is supported on APIC GBP driver.")


class OnlyOneAddressIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one ip address on each ES is supported on "
                "APIC GBP driver.")


class NoAddressConfiguredOnExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("L3 Policy %(l3p_id)s has no address configured on "
                "External Segment %(es_id)s")


class PATNotSupportedByApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Port address translation is not supported by APIC driver.")


class SharedAttributeUpdateNotSupportedOnApic(gpexc.GroupPolicyBadRequest):
    message = _("Resource shared attribute update not supported on APIC "
                "GBP driver for resource of type %(type)s")


class ExplicitSubnetAssociationNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Explicit subnet association not supported by APIC driver.")


class HierarchicalContractsNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Hierarchical contracts not supported by APIC driver.")


class PTGAlreadyProvidingRedirectPRS(gpexc.GroupPolicyBadRequest):
    message = _("PTG %(ptg_id)s is already providing a redirect PRS.")


REVERSE_PREFIX = 'reverse-'
SHADOW_PREFIX = 'shadow-'
SERVICE_PREFIX = 'service-'
ANY_PREFIX = 'any-'
PROMISCUOUS_SUFFIX = 'promiscuous'
APIC_OWNED = 'apic_owned_'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
ALLOWING_ACTIONS = [g_const.GP_ACTION_ALLOW, g_const.GP_ACTION_REDIRECT]

GOTHROUGH_SERVICES = ['FIREWALL_TRANSPARENT', 'IDS']
GOTO_SERVICES = [pconst.LOADBALANCER]


class ApicPtgServiceChainInstanceMapping(model_base.BASEV2):
    """Policy Target Group to ServiceChainInstance mapping DB."""

    __tablename__ = 'gpm_apic_ptgs_servicechain_mapping'
    provider_ptg_id = sa.Column(sa.String(36),
                                sa.ForeignKey('gp_policy_target_groups.id',
                                              ondelete='CASCADE'),
                                nullable=False)
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id',
                                                 ondelete='CASCADE'),
                                   nullable=False)
    servicechain_instance_id = sa.Column(sa.String(36),
                                         sa.ForeignKey('sc_instances.id',
                                                       ondelete='CASCADE'),
                                         primary_key=True)


class ApicMappingDriver(api.ResourceMappingDriver):
    """Apic Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources, and leverages
    Cisco APIC's backend for enforcing the policies.
    """

    me = None
    manager = None

    @staticmethod
    def get_apic_manager(client=True):
        if not ApicMappingDriver.manager:
            apic_config = cfg.CONF.ml2_cisco_apic
            network_config = {
                'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
                'vni_ranges': cfg.CONF.ml2_type_vxlan.vni_ranges,
                'switch_dict': config.create_switch_dictionary(),
                'vpc_dict': config.create_vpc_dictionary(),
                'external_network_dict':
                    config.create_external_network_dictionary(),
            }
            apic_system_id = cfg.CONF.apic_system_id
            keyclient_param = keyclient if client else None
            keystone_authtoken = (cfg.CONF.keystone_authtoken if client else
                                  None)
            ApicMappingDriver.manager = apic_manager.APICManager(
                apic_model.ApicDbModel(), logging, network_config, apic_config,
                keyclient_param, keystone_authtoken, apic_system_id)
            ApicMappingDriver.manager.ensure_infra_created_on_apic()
            ApicMappingDriver.manager.ensure_bgp_pod_policy_created_on_apic()
        return ApicMappingDriver.manager

    def initialize(self):
        super(ApicMappingDriver, self).initialize()
        self._setup_rpc_listeners()
        self._setup_rpc()
        self.apic_manager = ApicMappingDriver.get_apic_manager()
        self.name_mapper = self.apic_manager.apic_mapper
        self._gbp_plugin = None
        self._sc_plugin = None
        ApicMappingDriver.me = self

    def _setup_rpc_listeners(self):
        self.endpoints = [rpc.GBPServerRpcCallback(self)]
        self.topic = rpc.TOPIC_OPFLEX
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        return self.conn.consume_in_threads()

    def _setup_rpc(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    @property
    def sc_plugin(self):
        if not self._sc_plugin:
            self._sc_plugin = (manager.NeutronManager.get_service_plugins()
                               .get("SERVICECHAIN"))
        return self._sc_plugin

    @staticmethod
    def get_initialized_instance():
        return ApicMappingDriver.me

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        port_id = self._core_plugin._device_to_port_id(
            kwargs['device'])
        port_context = self._core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return
        port = port_context.current

        if self._is_chain_port(context, port):
            if port['name'].startswith('vip-'):
                return self._get_chain_vip_details(context, port_context,
                                                   **kwargs)
            else:
                provider = self._port_id_to_ptg(context, port['id'])
                return self._get_chain_port_details(context, port_context,
                                                    provider, **kwargs)
        else:
            # retrieve PTG from a given Port
            ptg = self._port_id_to_ptg(context, port['id'])
            l2p = self._network_id_to_l2p(context, port['network_id'])
            if not ptg and not l2p:
                return
            context._plugin = self.gbp_plugin
            context._plugin_context = context

            l2_policy_id = l2p['id']
            ptg_tenant = self._tenant_by_sharing_policy(ptg or l2p)
            if ptg:
                endpoint_group_name = self.name_mapper.policy_target_group(
                    context, ptg['id'])
            else:
                endpoint_group_name = self.name_mapper.l2_policy(
                    context, l2p['id'], prefix=SHADOW_PREFIX)

            def is_port_promiscuous(port):
                return (port['device_owner'] in PROMISCUOUS_TYPES or
                        port['name'].endswith(PROMISCUOUS_SUFFIX))

            segment = port_context.bound_segment or {}
            return {'device': kwargs.get('device'),
                    'port_id': port_id,
                    'mac_address': port['mac_address'],
                    'app_profile_name': str(
                        self.apic_manager.app_profile_name),
                    'segment': segment,
                    'segmentation_id': segment.get('segmentation_id'),
                    'network_type': segment.get('network_type'),
                    'l2_policy_id': l2_policy_id,
                    'tenant_id': port['tenant_id'],
                    'host': port[portbindings.HOST_ID],
                    'ptg_tentant': str(ptg_tenant),
                    'endpoint_group_name': str(endpoint_group_name),
                    'promiscuous_mode': is_port_promiscuous(port)}

    def _is_chain_vip(self, context, port):
        if port['name'].startswith('vip-'):
            lb_plugin = manager.NeutronManager.get_service_plugins().get(
                "LOADBALANCER")
            try:
                vip = lb_plugin.get_vip(context, port['name'][len('vip-'):])
                chain = jsonutils.loads(
                    vip['description']).get('sc_instance')
                if chain:
                    return bool(self._get_ptg_servicechain_instance_mappings(
                        context.session, sc_id=chain))
            except Exception as e:
                LOG.warn(e.message)
            return False

    def _is_chain_port(self, context, port):
        if port['name'].startswith('pt_chain_'):
            provider = self._port_id_to_ptg(context, port['id'])
            return provider and bool(
                self._get_ptg_servicechain_instance_mappings(
                    context.session, provider_ptg_id=provider['id']))
        else:
            return self._is_chain_vip(context, port)

    def _get_chain_port_details(self, context, port_context, provider,
                                **kwargs):
        port = port_context.current
        parts = port['name'][len('pt_chain_'):].split('_')
        l2p = self.gbp_plugin.get_l2_policy(context, provider['l2_policy_id'])
        transparent = parts[-1] == 'transparent'
        order = int(parts[-2])
        is_provider = parts[-3] == 'provider'
        chain = self._get_ptg_servicechain_instance_mappings(
            context.session, provider_ptg_id=provider['id'])[0]
        instance = self.sc_plugin.get_servicechain_instance(
            context, chain.servicechain_instance_id)
        spec = self.sc_plugin.get_servicechain_spec(
            context, instance['servicechain_specs'][0])
        # maintain order
        nodes = [self.sc_plugin.get_servicechain_node(
            context, x) for x in spec['nodes']]
        is_transparent_chain = bool([x for x in nodes
                                     if x['service_type'] in
                                     GOTHROUGH_SERVICES])
        segment = port_context.bound_segment or {}
        common = {'device': kwargs.get('device'),
                  'port_id': port['id'],
                  'mac_address': port['mac_address'],
                  'app_profile_name': str(
                      self.apic_manager.app_profile_name),
                  'segment': segment,
                  'segmentation_id': segment.get('segmentation_id'),
                  'network_type': segment.get('network_type'),
                  'l2_policy_id': provider['l2_policy_id'],
                  'tenant_id': port['tenant_id'],
                  'host': port[portbindings.HOST_ID]}
        if not is_transparent_chain:
            ptg_tenant = self._tenant_by_sharing_policy(provider)
            endpoint_group_name = self.name_mapper.policy_target_group(
                context, provider['id'])
            common.update({
                'ptg_tentant': str(ptg_tenant),
                'endpoint_group_name': str(endpoint_group_name),
                'promiscuous_mode': False})
            return common
        else:
            # Count how many transparents exist before me
            prev_transparents = len([nodes[x] for x in xrange(order - 1)
                                     if nodes[x]['service_type'] in
                                    GOTHROUGH_SERVICES])
            ptg_tenant = self._tenant_by_sharing_policy(l2p)
            if transparent:
                # Place in the correct side
                promiscuous = True
                if is_provider:
                    ptg_name = (str(prev_transparents) + '-' +
                                chain.servicechain_instance_id)
                else:
                    ptg_name = (str(prev_transparents + 1) + '-' +
                                chain.servicechain_instance_id)
            else:
                promiscuous = False
                ptg_name = (str(prev_transparents) + '-' +
                            chain.servicechain_instance_id)
            common.update({'ptg_tentant': str(ptg_tenant),
                           'endpoint_group_name': str(ptg_name),
                           'promiscuous_mode': promiscuous})
            return common

    def _get_chain_vip_details(self, context, port_context, **kwargs):
        port = port_context.current
        lb_plugin = manager.NeutronManager.get_service_plugins().get(
                "LOADBALANCER")
        vip = lb_plugin.get_vip(context, port['name'][len('vip-'):])
        info = jsonutils.loads(vip['description'])
        order = info['order']
        provider = self.gbp_plugin.get_policy_target_group(
            context, info['provider_ptg'])
        port_context.current['name'] = ('pt_chain_provider_' + str(order) +
                                        '_notransparent')
        return self._get_chain_port_details(context, port_context, provider,
                                            **kwargs)

    def process_port_added(self, plugin_context, port):
        l2p = self._network_id_to_l2p(plugin_context, port['network_id'])
        if l2p and port['device_owner'] == n_constants.AGENT_TYPE_DHCP:
            # TODO(ivar): create DHCP relay on proper BD
            pass

    def create_policy_action_precommit(self, context):
        pass

    def create_policy_rule_precommit(self, context):
        if ('policy_actions' in context.current and
                len(context.current['policy_actions']) != 1):
            # TODO(ivar): to be fixed when redirect is supported
            raise ExactlyOneActionPerRuleIsSupportedOnApicDriver()

    def create_policy_rule_postcommit(self, context, transaction=None):
        action = context._plugin.get_policy_action(
            context._plugin_context, context.current['policy_actions'][0])
        classifier = context._plugin.get_policy_classifier(
            context._plugin_context,
            context.current['policy_classifier_id'])
        if action['action_type'] in ALLOWING_ACTIONS:
            port_min, port_max = (
                gpdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                    classifier['port_range']))
            attrs = {'etherT': 'unspecified'}
            if classifier['protocol']:
                attrs['etherT'] = 'ip'
                attrs['prot'] = classifier['protocol'].lower()
                if port_min and port_max:
                    attrs['dToPort'] = port_max
                    attrs['dFromPort'] = port_min
            tenant = self._tenant_by_sharing_policy(context.current)
            policy_rule = self.name_mapper.policy_rule(context,
                                                       context.current['id'])
            with self.apic_manager.apic.transaction(transaction) as trs:
                self.apic_manager.create_tenant_filter(
                    policy_rule, owner=tenant, transaction=trs, **attrs)
                # Also create reverse rule
                policy_rule = self.name_mapper.policy_rule(
                    context, context.current['id'], prefix=REVERSE_PREFIX)
                if attrs.get('dToPort') and attrs.get('dFromPort'):
                    attrs.pop('dToPort')
                    attrs.pop('dFromPort')
                    attrs['sToPort'] = port_max
                    attrs['sFromPort'] = port_min
                    self.apic_manager.create_tenant_filter(
                        policy_rule, owner=tenant, transaction=trs, **attrs)

    def create_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise HierarchicalContractsNotSupported()

    def create_policy_rule_set_postcommit(self, context):
        # Create APIC policy_rule_set
        tenant = self._tenant_by_sharing_policy(context.current)
        contract = self.name_mapper.policy_rule_set(context,
                                                    context.current['id'])
        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)
            rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': context.current['policy_rules']})
            self._apply_policy_rule_set_rules(
                context, context.current, rules, transaction=trs)

    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        port = self._core_plugin.get_port(context._plugin_context,
                                          context.current['port_id'])
        if self._is_port_bound(port):
            self._notify_port_update(context._plugin_context, port['id'])

    def create_policy_target_group_precommit(self, context):
        if context.current['subnets']:
            raise ExplicitSubnetAssociationNotSupported()
        self._validate_ptg_prss(context, context.current)

    def create_policy_target_group_postcommit(self, context):
        if not context.current['subnets']:
            self._use_implicit_subnet(context)
        self._handle_network_service_policy(context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l2_policy = self.name_mapper.l2_policy(context,
                                               context.current['l2_policy_id'])
        epg = self.name_mapper.policy_target_group(context,
                                                   context.current['id'])
        l2_policy_object = context._plugin.get_l2_policy(
            context._plugin_context, context.current['l2_policy_id'])
        bd_owner = self._tenant_by_sharing_policy(l2_policy_object)
        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.ensure_epg_created(tenant, epg,
                                                 bd_owner=bd_owner,
                                                 bd_name=l2_policy)

            l2p = context._plugin.get_l2_policy(
                context._plugin_context, context.current['l2_policy_id'])
            self._configure_epg_service_contract(context, context.current, l2p,
                                                 epg, transaction=trs)
        self._manage_ptg_policy_rule_sets(
                context, context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'], [], [])

    def create_l2_policy_precommit(self, context):
        self._reject_non_shared_net_on_shared_l2p(context)

    def update_l2_policy_precommit(self, context):
        self._reject_non_shared_net_on_shared_l2p(context)
        self._reject_shared_update(context, 'l2_policy')
        # TODO(ivar): check whether a transparent SC exists if allow_broadcast
        # is modified

    def create_l2_policy_postcommit(self, context):
        super(ApicMappingDriver, self).create_l2_policy_postcommit(context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context,
                                               context.current['l3_policy_id'])
        l2_policy = self.name_mapper.l2_policy(context, context.current['id'])
        l3_policy_object = context._plugin.get_l3_policy(
            context._plugin_context, context.current['l3_policy_id'])
        ctx_owner = self._tenant_by_sharing_policy(l3_policy_object)
        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.ensure_bd_created_on_apic(
                tenant, l2_policy, ctx_owner=ctx_owner, ctx_name=l3_policy,
                allow_broadcast=context.current['allow_broadcast'],
                transaction=trs)
            # Create neutron port EPG
            self._configure_shadow_epg(context, context.current, l2_policy,
                                       transaction=trs)
            # Add existing subnets
            net_id = context.current['network_id']
            subnets = self._core_plugin.get_subnets(context._plugin_context,
                                                    {'network_id': [net_id]})
            self._manage_l2p_subnets(
                context._plugin_context, context.current['id'], subnets, [],
                transaction=trs)

    def update_l2_policy_postcommit(self, context):
        tenant = self._tenant_by_sharing_policy(context.current)
        l2_policy = self.name_mapper.l2_policy(context, context.current['id'])
        if (context.current['allow_broadcast'] !=
                context.original['allow_broadcast']):
            self.apic_manager.ensure_bd_created_on_apic(
                tenant, l2_policy, ctx_name=None,
                allow_broadcast=context.current['allow_broadcast'])

    def create_l3_policy_precommit(self, context):
        self._check_l3p_es(context)

    def create_l3_policy_postcommit(self, context):
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])
        self.apic_manager.ensure_context_enforced(tenant, l3_policy)
        external_segments = context.current['external_segments']
        if external_segments:
            # Create a L3 ext for each External Segment
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': external_segments.keys()})
            for es in ess:
                self._plug_l3p_to_es(context, es)

    def delete_policy_rule_postcommit(self, context):
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])
        self._delete_policy_rule_from_apic(context)
        self._cleanup_redirect_rule(context, context.current)

    def _delete_policy_rule_from_apic(self, context, transaction=None):
        tenant = self._tenant_by_sharing_policy(context.current)
        policy_rule = self.name_mapper.policy_rule(context,
                                                   context.current['id'])
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant,
                                                   transaction=trs)
            # Delete policy reverse rule
            policy_rule = self.name_mapper.policy_rule(
                context, context.current['id'], prefix=REVERSE_PREFIX)
            self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant,
                                                   transaction=trs)

    def delete_policy_rule_set_precommit(self, context):
        # Intercept Parent Call
        pass

    def delete_policy_rule_set_postcommit(self, context):
        # TODO(ivar): disassociate PTGs to avoid reference leak
        tenant = self._tenant_by_sharing_policy(context.current)
        contract = self.name_mapper.policy_rule_set(context,
                                                    context.current['id'])
        self.apic_manager.delete_contract(contract, owner=tenant)

    def delete_policy_target_postcommit(self, context):
        try:
            port = self._core_plugin.get_port(context._plugin_context,
                                              context.current['port_id'])
        except n_exc.PortNotFound:
            LOG.warn(_("Port %s is missing") % context.current['port_id'])
            return
        # Delete Neutron's port
        port_id = context.current['port_id']
        self._cleanup_port(context._plugin_context, port_id)
        # Notify the agent. If the port has been deleted by the parent method
        # the notification will not be done
        self._notify_port_update(context._plugin_context, port['id'])

    def delete_policy_target_group_precommit(self, context):
        provider_ptg_chain_map = self._get_ptgs_servicechain(
            context._plugin_context.session, context.current['id'])

        context.ptg_chain_map = provider_ptg_chain_map
        for chain in context.ptg_chain_map:
            chain.l2p = self.gbp_plugin.get_l2_policy(
                context._plugin_context, context.current['l2_policy_id'])

    def delete_policy_target_group_postcommit(self, context):
        self._cleanup_network_service_policy(
            context, context.current['subnets'][0], context.current['id'])

        for chain in context.ptg_chain_map:
            self._unchain_ptg_pair(context, chain, context.current, chain.l2p)

        tenant = self._tenant_by_sharing_policy(context.current)
        ptg = self.name_mapper.policy_target_group(context,
                                                   context.current['id'])

        self.apic_manager.delete_epg_for_network(tenant, ptg)

    def delete_l2_policy_postcommit(self, context):
        super(ApicMappingDriver, self).delete_l2_policy_postcommit(context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l2_policy = self.name_mapper.l2_policy(context, context.current['id'])

        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.delete_bd_on_apic(
                tenant, l2_policy, transaction=trs)
            # Delete neutron port EPG
            self._delete_shadow_epg(context, context.current, transaction=trs)

    def delete_l3_policy_postcommit(self, context):
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])

        self.apic_manager.ensure_context_deleted(tenant, l3_policy)
        external_segments = context.current['external_segments']
        if external_segments:
            # Create a L3 ext for each External Segment
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': external_segments.keys()})
            for es in ess:
                self._unplug_l3p_from_es(context, es)

    def update_policy_rule_set_precommit(self, context):
        self._reject_shared_update(context, 'policy_rule_set')
        self._reject_multiple_redirects_in_prs(context)
        if context.current['child_policy_rule_sets']:
            raise HierarchicalContractsNotSupported()
        # If a redirect action is added (from 0 to one) we have to validate
        # the providing and consuming PTGs
        old_red_count = self._multiple_pr_redirect_action_number(
            context._plugin_context.session, context.original['policy_rules'])
        new_red_count = self._multiple_pr_redirect_action_number(
            context._plugin_context.session, context.current['policy_rules'])
        if new_red_count > old_red_count:
            self._validate_new_prs_redirect(context, context.current)

    def update_policy_rule_set_postcommit(self, context):
        # Update policy_rule_set rules
        old_rules = set(context.original['policy_rules'])
        new_rules = set(context.current['policy_rules'])
        to_add = context._plugin.get_policy_rules(
            context._plugin_context, {'id': new_rules - old_rules})
        to_remove = context._plugin.get_policy_rules(
            context._plugin_context, {'id': old_rules - new_rules})
        self._remove_policy_rule_set_rules(context, context.current, to_remove)
        self._apply_policy_rule_set_rules(context, context.current, to_add)

    def update_policy_target_postcommit(self, context):
        # TODO(ivar): redo binding procedure if the PTG is modified,
        # not doable unless driver extension framework is in place
        pass

    def update_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)
        old_redirect = self._get_redirect_action(context, context.original)
        new_redirect = self._get_redirect_action(context, context.current)
        if not old_redirect and new_redirect:
            # If redirect action is added, check that there's no contract that
            # already has a redirect action
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context,
                    {'id': context.current['policy_rule_sets']}):
                # Make sure the PRS can have a new redirect action
                self._validate_new_prs_redirect(context, prs)

    def update_policy_rule_postcommit(self, context):
        self._update_policy_rule_on_apic(context)
        old_redirect = self._get_redirect_action(context, context.original)
        new_redirect = self._get_redirect_action(context, context.current)
        if old_redirect != new_redirect:
            # Check if redirect action changed
            if old_redirect and old_redirect.get('action_value'):
                self._cleanup_redirect_rule(context, context.original)
            if new_redirect and new_redirect.get('action_value'):
                self._hadle_redirect_rule(context, context.current)

    def update_policy_action_postcommit(self, context):
        if context.current['action_type'] == g_const.GP_ACTION_REDIRECT:
            if (context.original['action_value'] !=
                    context.current['action_value']):
                rules = context._plugin.get_policy_rules(
                    context._plugin_context,
                    {'id': context.current['policy_rules']})
                # Clean old chains
                if context.original['action_value']:
                    for rule in rules:
                        self._cleanup_redirect_rule(context, rule)
                # Instantiate new chains
                if context.current['action_value']:
                    for rule in rules:
                        self._hadle_redirect_rule(context, rule)

    def _update_policy_rule_on_apic(self, context, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            self._delete_policy_rule_from_apic(context, transaction=trs)
            # The following only creates the APIC reference
            self.create_policy_rule_postcommit(context, transaction=trs)

    def update_policy_target_group_precommit(self, context):
        if set(context.original['subnets']) != set(context.current['subnets']):
            raise ExplicitSubnetAssociationNotSupported()
        self._reject_shared_update(context, 'policy_target_group')
        self._validate_ptg_prss(context, context.current)

    def update_policy_target_group_postcommit(self, context):
        # TODO(ivar): refactor parent to avoid code duplication
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        orig_consumed_policy_rule_sets = context.original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']

        new_provided_policy_rule_sets = list(
            set(curr_provided_policy_rule_sets) - set(
                orig_provided_policy_rule_sets))
        new_consumed_policy_rule_sets = list(
            set(curr_consumed_policy_rule_sets) - set(
                orig_consumed_policy_rule_sets))
        removed_provided_policy_rule_sets = list(
            set(orig_provided_policy_rule_sets) - set(
                curr_provided_policy_rule_sets))
        removed_consumed_policy_rule_sets = list(
            set(orig_consumed_policy_rule_sets) - set(
                curr_consumed_policy_rule_sets))

        old_nsp = context.original.get("network_service_policy_id")
        new_nsp = context.current.get("network_service_policy_id")
        if old_nsp != new_nsp:
            if old_nsp:
                self._cleanup_network_service_policy(
                                        context,
                                        context.current['subnets'][0],
                                        context.current['id'])
            if new_nsp:
                self._handle_network_service_policy(context)

        self._manage_ptg_policy_rule_sets(
            context, new_provided_policy_rule_sets,
            new_consumed_policy_rule_sets, removed_provided_policy_rule_sets,
            removed_consumed_policy_rule_sets)

    def update_l3_policy_precommit(self, context):
        self._reject_shared_update(context, 'l3_policy')
        self._check_l3p_es(context)

    def update_l3_policy_postcommit(self, context):
        old_segment_dict = context.original['external_segments']
        new_segment_dict = context.current['external_segments']
        if (context.current['external_segments'] !=
                context.original['external_segments']):
            new_segments = set(new_segment_dict.keys())
            old_segments = set(old_segment_dict.keys())
            added = new_segments - old_segments
            removed = old_segments - new_segments
            # Modified ES are treated like new ones
            modified = set(x for x in (new_segments - added) if
                        (set(old_segment_dict[x]) != set(new_segment_dict[x])))
            added |= modified
            # The following operations could be intra-tenant, can't be executed
            # in a single transaction
            if added:
                # Create a L3 ext for each External Segment
                added_ess = context._plugin.get_external_segments(
                    context._plugin_context, filters={'id': added})
                for es in added_ess:
                    self._plug_l3p_to_es(context, es)
            if removed:
                removed_ess = context._plugin.get_external_segments(
                    context._plugin_context, filters={'id': removed})
                for es in removed_ess:
                    self._unplug_l3p_from_es(context, es)

    def create_policy_classifier_precommit(self, context):
        pass

    def create_policy_classifier_postcommit(self, context):
        pass

    def update_policy_classifier_precommit(self, context):
        pass

    def update_policy_classifier_postcommit(self, context):
        for rule in context._plugin.get_policy_rules(
                context._plugin_context,
                filters={'id': context.current['policy_rules']}):

            rule_context = group_policy_context.PolicyRuleContext(
                context._plugin, context._plugin_context, rule)
            with self.apic_manager.apic.transaction(None) as trs:
                self._update_policy_rule_on_apic(rule_context,
                                                 transaction=trs)

    def create_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if ext_info and ext_info.get('cidr_exposed'):
            db_es = context._plugin._get_external_segment(
                context._plugin_context, context.current['id'])
            net = netaddr.IPNetwork(ext_info.get('cidr_exposed'))
            db_es.cidr = str(net)
            db_es.ip_version = net[0].version
            context.current['cidr'] = db_es.cidr
            context.current['ip_version'] = db_es.ip_version
        else:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])

    def create_external_segment_postcommit(self, context):
        external_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not external_info:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])

    def update_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()

    def update_external_segment_postcommit(self, context):
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not ext_info:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])
            return
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            new_routes_dict = self._build_routes_dict(
                context.current['external_routes'])
            new_routes = set((x['destination'], x['nexthop'])
                             for x in context.current['external_routes'])
            old_routes = set((x['destination'], x['nexthop'])
                             for x in context.original['external_routes'])
            added = new_routes - old_routes
            removed = old_routes - new_routes
            switch = ext_info['switch']
            default_gateway = ext_info['gateway_ip']
            es_name = self.name_mapper.external_segment(
                context, context.current['id'])
            es_tenant = self._tenant_by_sharing_policy(context.current)
            ep_names = [self.name_mapper.external_policy(context, x)
                        for x in context.current['external_policies']]

            nexthop = lambda h: h if h else default_gateway
            with self.apic_manager.apic.transaction() as trs:
                for route in removed:
                    if route[0] not in new_routes_dict:
                        # Remove Route completely
                        self.apic_manager.ensure_static_route_deleted(
                            es_name, switch, route[0], owner=es_tenant,
                            transaction=trs)
                        # Also from External EPG
                        del_epg = (self.apic_manager.
                                   ensure_external_epg_routes_deleted)
                        for ep in ep_names:
                            del_epg(
                                es_name, external_epg=ep, owner=es_tenant,
                                subnets=[route[0]], transaction=trs)
                    else:
                        # Only remove nexthop
                        self.apic_manager.ensure_next_hop_deleted(
                            es_name, switch, route[0], nexthop(route[1]),
                            owner=es_tenant, transaction=trs)
                for route in added:
                    # Create Static Route on External Routed Network
                    self.apic_manager.ensure_static_route_created(
                        es_name, switch, nexthop(route[1]),
                        owner=es_tenant, subnet=route[0], transaction=trs)
                    # And on the External EPGs
                    for ep in ep_names:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=route[0], external_epg=ep,
                            owner=es_tenant, transaction=trs)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        # If not in use, there's no representation of it in the APIC
        pass

    def create_external_policy_precommit(self, context):
        pass

    def create_external_policy_postcommit(self, context):
        segments = context.current['external_segments']
        provided_prs = context.current['provided_policy_rule_sets']
        consumed_prs = context.current['consumed_policy_rule_sets']
        self._plug_externa_policy_to_segment(
            context, context.current, segments, provided_prs, consumed_prs)

    def update_external_policy_precommit(self, context):
        pass

    def update_external_policy_postcommit(self, context):
        added_segments = (set(context.current['external_segments']) -
                          set(context.original['external_segments']))
        removed_segments = (set(context.original['external_segments']) -
                            set(context.current['external_segments']))
        # Remove segments
        self._unplug_external_policy_from_segment(
            context, context.current, removed_segments)
        # Add new segments
        provided_prs = context.current['provided_policy_rule_sets']
        consumed_prs = context.current['consumed_policy_rule_sets']
        self._plug_externa_policy_to_segment(
            context, context.current, added_segments, provided_prs,
            consumed_prs)
        # Manage updated PRSs
        added_p_prs = (set(context.current['provided_policy_rule_sets']) -
                       set(context.original['provided_policy_rule_sets']))
        removed_p_prs = (set(context.original['provided_policy_rule_sets']) -
                         set(context.current['provided_policy_rule_sets']))
        added_c_prs = (set(context.current['consumed_policy_rule_sets']) -
                       set(context.original['consumed_policy_rule_sets']))
        removed_c_prs = (set(context.original['consumed_policy_rule_sets']) -
                         set(context.current['consumed_policy_rule_sets']))
        # Avoid duplicating requests
        delta_segments = [x for x in context.current['external_segments']
                          if x not in added_segments]
        new_ess = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': delta_segments})
        for es in new_ess:
            self._manage_ep_policy_rule_sets(
                context._plugin_context, es, context.current, added_p_prs,
                added_c_prs, removed_p_prs, removed_c_prs)

    def delete_external_policy_precommit(self, context):
        pass

    def delete_external_policy_postcommit(self, context):
        external_segments = context.current['external_segments']
        self._unplug_external_policy_from_segment(
            context, context.current, external_segments)

    def process_subnet_changed(self, context, old, new):
        if old['gateway_ip'] != new['gateway_ip']:
            l2p = self._network_id_to_l2p(context, new['network_id'])
            if l2p:
                # Is GBP owned, reflect on APIC
                self._manage_l2p_subnets(context, l2p['id'], [new], [old])

    def process_subnet_added(self, context, subnet):
        l2p = self._network_id_to_l2p(context, subnet['network_id'])
        if l2p:
            self._sync_epg_subnets(context, l2p)
            self._manage_l2p_subnets(context, l2p['id'], [subnet], [])

    def process_subnet_deleted(self, context, subnet):
        l2p = self._network_id_to_l2p(context, subnet['network_id'])
        if l2p:
            self._manage_l2p_subnets(context, l2p['id'], [], [subnet])

    def process_port_changed(self, context, old, new):
        pass

    def process_port_bound(self, context, port):
        pass

    def _apply_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        # TODO(ivar): refactor parent to avoid code duplication
        if policy_rule_set['parent_id']:
            parent = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set['parent_id'])
            policy_rules = policy_rules & set(parent['policy_rules'])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, transaction=transaction)

    def _remove_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            transaction=transaction)

    def _manage_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, unset=False,
            transaction=None):
        # REVISIT(ivar): figure out what should be moved in apicapi instead
        if policy_rules:
            tenant = self._tenant_by_sharing_policy(policy_rule_set)
            contract = self.name_mapper.policy_rule_set(
                context, policy_rule_set['id'])
            in_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_IN]
            out_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_OUT]
            for rule in policy_rules:
                policy_rule = self.name_mapper.policy_rule(context, rule['id'])
                reverse_policy_rule = self.name_mapper.policy_rule(
                    context, rule['id'], prefix=REVERSE_PREFIX)
                rule_owner = self._tenant_by_sharing_policy(rule)
                classifier = context._plugin.get_policy_classifier(
                    context._plugin_context, rule['policy_classifier_id'])
                with self.apic_manager.apic.transaction(transaction) as trs:
                    if classifier['direction'] in in_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_in_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                        if classifier['port_range']:
                            (self.apic_manager.
                             manage_contract_subject_out_filter(
                                 contract, contract, reverse_policy_rule,
                                 owner=tenant, transaction=trs, unset=unset,
                                 rule_owner=rule_owner))
                    if classifier['direction'] in out_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_out_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                        if classifier['port_range']:
                            (self.apic_manager.
                             manage_contract_subject_in_filter(
                                 contract, contract, reverse_policy_rule,
                                 owner=tenant, transaction=trs, unset=unset,
                                 rule_owner=rule_owner))
                # If the rule is of redirect type, set/unset the chain
                # accordingly
                if self._get_redirect_action(context, rule):
                    if unset:
                        self._cleanup_redirect_rule(
                            context, rule,
                            policy_rule_sets=[policy_rule_set['id']])
                    else:
                        self._hadle_redirect_rule(
                            context, rule,
                            policy_rule_sets=[policy_rule_set['id']])

    def _manage_ptg_policy_rule_sets(
            self, ptg_context, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        context = ptg_context
        plugin_context = context._plugin_context
        ptg = context.current
        # Delete old servicechain instances in case of update
        if removed_provided:
            self._cleanup_service_chains(context, removed_provided)
        # Create new servicechain instances in case of update
        created = False
        if added_provided:
            created = self._handle_service_chains(context, added_provided)
        inst_id, tsc_len = self._get_ptg_transparent_chain_length(
            ptg_context, ptg_context.current['id'])
        ptg_params = []
        if not created and inst_id and tsc_len:
            # When a chain is instantiated, the corresponding shadow EPG
            # must provide and consume the same contracts as the original one
            l2p = context._plugin.get_l2_policy(
                context._plugin_context, ptg_context.current['l2_policy_id'])
            shadow_tenant = self._tenant_by_sharing_policy(l2p)
            shadow_ptg = str(tsc_len) + '-' + inst_id
            ptg_params.append((shadow_tenant, shadow_ptg))

        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        mapped_tenant = self._tenant_by_sharing_policy(ptg)
        mapped_ptg = self.name_mapper.policy_target_group(
            plugin_context, ptg['id'])
        ptg_params.append((mapped_tenant, mapped_ptg))
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_epg,
                   self.apic_manager.unset_contract_for_epg]

        for x in xrange(len(provided)):
            for c in self.gbp_plugin.get_policy_rule_sets(
                    plugin_context, filters={'id': provided[x]}):
                c_owner = self._tenant_by_sharing_policy(c)
                c = self.name_mapper.policy_rule_set(plugin_context,
                                                     c['id'])
                for params in ptg_params:
                    methods[x](params[0], params[1], c, provider=True,
                               contract_owner=c_owner, transaction=None)
        for x in xrange(len(consumed)):
            for c in self.gbp_plugin.get_policy_rule_sets(
                    plugin_context, filters={'id': consumed[x]}):
                c_owner = self._tenant_by_sharing_policy(c)
                c = self.name_mapper.policy_rule_set(plugin_context,
                                                     c['id'])
                for params in ptg_params:
                    methods[x](params[0], params[1], c, provider=False,
                               contract_owner=c_owner, transaction=None)

    def _manage_ep_policy_rule_sets(
            self, plugin_context, es, ep, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        mapped_tenant = self._tenant_by_sharing_policy(es)
        mapped_es = self.name_mapper.external_segment(plugin_context, es['id'])

        mapped_ep = self.name_mapper.external_policy(plugin_context,
                                                     ep['id'])
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_external_epg,
                   self.apic_manager.unset_contract_for_external_epg]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(provided)):
                for c in provided[x]:
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=True,
                               transaction=trs)
            for x in xrange(len(consumed)):
                for c in consumed[x]:
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=False,
                               transaction=trs)

    def _manage_l2p_subnets(self, plugin_context, l2p_id, added_subnets,
                            removed_subnets, transaction=None):
        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        l2_policy_object = self.gbp_plugin.get_l2_policy(
            plugin_context, l2p_id)
        mapped_tenant = self._tenant_by_sharing_policy(l2_policy_object)
        mapped_l2p = self.name_mapper.l2_policy(plugin_context, l2p_id)
        subnets = [added_subnets, removed_subnets]
        methods = [self.apic_manager.ensure_subnet_created_on_apic,
                   self.apic_manager.ensure_subnet_deleted_on_apic]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(subnets)):
                for s in subnets[x]:
                    methods[x](mapped_tenant, mapped_l2p, self._gateway_ip(s),
                               transaction=trs)

    def _update_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id, subnets=None):
        pass

    def _assoc_ptg_sg_to_pt(self, context, pt_id, ptg_id):
        pass

    def _handle_policy_rule_sets(self, context):
        pass

    def _gateway_ip(self, subnet):
        cidr = netaddr.IPNetwork(subnet['cidr'])
        return '%s/%s' % (subnet['gateway_ip'], str(cidr.prefixlen))

    def _subnet_ids_to_objects(self, plugin_context, ids):
        return self._core_plugin.get_subnets(plugin_context,
                                             filters={'id': ids})

    def _port_to_ptg_network(self, context, port_id):
        ptg = self._port_id_to_ptg(context, port_id)
        if not ptg:
            # Not GBP port
            return None, None
        network = self._l2p_id_to_network(context, ptg['l2_policy_id'])
        return ptg, network

    def _port_id_to_pt(self, context, port_id):
        pt = (context.session.query(gpdb.PolicyTargetMapping).
              filter_by(port_id=port_id).first())
        if pt:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_dict(pt)

    def _port_id_to_ptg(self, context, port_id):
        pt = self._port_id_to_pt(context, port_id)
        if pt:
            return self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id'])
        return

    def _l2p_id_to_network(self, context, l2p_id):
        l2_policy = self.gbp_plugin.get_l2_policy(context, l2p_id)
        return self._core_plugin.get_network(context, l2_policy['network_id'])

    def _network_id_to_l2p(self, context, network_id):
        l2ps = self.gbp_plugin.get_l2_policies(
            context, filters={'network_id': [network_id]})
        for l2p in l2ps:
            if l2p['network_id'] == network_id:
                return l2p

    def _subnet_to_ptg(self, context, subnet_id):
        ptg = (context.session.query(gpdb.PolicyTargetGroupMapping).
               join(gpdb.PolicyTargetGroupMapping.subnets).
               filter(gpdb.PTGToSubnetAssociation.subnet_id ==
                      subnet_id).
               first())
        if ptg:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_group_dict(ptg)

    def _plug_l3p_to_es(self, context, external_segment):
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])
        es = external_segment
        external_segments = context.current['external_segments']
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warn(
                _("External Segment %s is not managed by APIC mapping "
                  "driver.") % es['id'])
            return
        ip = external_segments[es['id']]
        ip = ip[0] if (ip and ip[0]) else ext_info.get('cidr_exposed',
                                                       '/').split('/')[0]
        if not ip:
            raise NoAddressConfiguredOnExternalSegment(
                l3p_id=context.current['id'], es_id=es['id'])
        context.set_external_fixed_ips(es['id'], [ip])
        encap = ext_info.get('encap')  # No encap if None
        switch = ext_info['switch']
        module, sport = ext_info['port'].split('/')
        router_id = ext_info['router_id']
        default_gateway = ext_info['gateway_ip']
        es_name = self.name_mapper.external_segment(
            context, es['id'])
        es_tenant = self._tenant_by_sharing_policy(es)
        with self.apic_manager.apic.transaction() as trs:
            # Create External Routed Network connected to the proper
            # L3 Context
            self.apic_manager.ensure_external_routed_network_created(
                es_name, owner=es_tenant, context=l3_policy,
                transaction=trs)
            self.apic_manager.ensure_logical_node_profile_created(
                es_name, switch, module, sport, encap,
                ip, owner=es_tenant, router_id=router_id,
                transaction=trs)
            for route in es['external_routes']:
                self.apic_manager.ensure_static_route_created(
                    es_name, switch, route['nexthop'] or default_gateway,
                    owner=es_tenant,
                    subnet=route['destination'], transaction=trs)

    def _unplug_l3p_from_es(self, context, es):
        es_name = self.name_mapper.external_segment(context, es['id'])
        es_tenant = self._tenant_by_sharing_policy(es)
        self.apic_manager.delete_external_routed_network(
            es_name, owner=es_tenant)

    def _build_routes_dict(self, routes):
        result = {}
        for route in routes:
            if route['destination'] not in result:
                result[route['destination']] = []
            result[route['destination']].append(route['nexthop'])
        return result

    def _plug_externa_policy_to_segment(self, context, ep, segments,
                                        provided_prs, consumed_prs):
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(
                context, ep['id'])
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(_("External Segment %s is not managed by APIC "
                             "mapping driver.") % es['id'])
                    continue
                es_name = self.name_mapper.external_segment(context, es['id'])
                es_tenant = self._tenant_by_sharing_policy(es)
                with self.apic_manager.apic.transaction() as trs:
                    # Create External EPG
                    subnets = set(x['destination'] for
                                  x in es['external_routes'])
                    for s in subnets:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=s, external_epg=ep_name,
                            owner=es_tenant, transaction=trs)
                    # Provide and consume contracts
                    self._manage_ep_policy_rule_sets(
                        context._plugin_context, es, ep,
                        provided_prs, consumed_prs, [], [], transaction=trs)

    def _unplug_external_policy_from_segment(self, context, ep, segments):
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(
                context, ep['id'])
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(_("External Segment %s is not managed by APIC "
                             "mapping driver.") % es['id'])
                    continue
                es_name = self.name_mapper.external_segment(context, es['id'])
                es_tenant = self._tenant_by_sharing_policy(es)
                self.apic_manager.ensure_external_epg_deleted(
                        es_name, external_epg=ep_name, owner=es_tenant)

    def _check_l3p_es(self, context):
        l3p = context.current
        if l3p['external_segments']:
            # Check not used
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': l3p['external_segments'].keys()})
            for es in ess:
                if [x for x in es['l3_policies'] if x != l3p['id']]:
                    raise OnlyOneL3PolicyIsAllowedPerExternalSegment()
            for allocations in l3p['external_segments'].values():
                if len(allocations) > 1:
                    raise OnlyOneAddressIsAllowedPerExternalSegment()

    def _get_ptg_by_subnet(self, plugin_context, subnet_id):
        ptgass = (plugin_context.session.query(gpdb.PTGToSubnetAssociation).
                  filter_by(subnet_id=subnet_id).first())
        if ptgass:
            return self.gbp_plugin.get_policy_target_group(
                plugin_context, ptgass['policy_target_group_id'])

    def _reject_shared_update(self, context, type):
        if context.original.get('shared') != context.current.get('shared'):
            raise SharedAttributeUpdateNotSupportedOnApic(type=type)

    def _tenant_by_sharing_policy(self, object):
        if not object.get('shared'):
            return self.name_mapper.tenant(None, object['tenant_id'])
        else:
            return apic_manager.TENANT_COMMON

    def _notify_port_update(self, plugin_context, port_id):
        try:
            port = self._core_plugin.get_port(plugin_context, port_id)
            if self._is_port_bound(port):
                self.notifier.port_update(plugin_context, port)
        except n_exc.PortNotFound:
            # Notification not needed
            pass

    def _get_port_network_type(self, context, port):
        try:
            network = self._core_plugin.get_network(context,
                                                    port['network_id'])
            return network['provider:network_type']
        except n_exc.NetworkNotFound:
            pass

    def _is_apic_network_type(self, context, port):
        return (self._get_port_network_type(context, port) ==
                ofcst.TYPE_OPFLEX)

    def _is_port_bound(self, port):
        return port[portbindings.VIF_TYPE] not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _use_implicit_subnet(self, context, force_add=False):
        """Implicit subnet for APIC driver.

        The first PTG of a given BD will allocate a new subnet from the L3P.
        Any subsequent PTG in the same BD will use the same subnet.
        More subnets will be allocated whenever the existing ones go out of
        addresses.
        """

        l2p_id = context.current['l2_policy_id']
        with lockutils.lock(l2p_id, external=True):
            subs = self._get_l2p_subnets(context._plugin_context, l2p_id)
            subs = set([x['id'] for x in subs])
            added = None
            if not subs or force_add:
                added = self._internal_use_implicit_subnet(context)
                subs.add(added['id'])
            context.add_subnets(subs - set(context.current['subnets']))
            if added:
                self.process_subnet_added(context._plugin_context, added)

    def _internal_use_implicit_subnet(self, context):
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        pool = netaddr.IPNetwork(l3p['ip_pool'])

        l2ps = context._plugin.get_l2_policies(
            context._plugin_context, filters={'l3_policy_id': [l3p['id']]})
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context,
            filters={'l2_policy_id': [x['id'] for x in l2ps]})
        subnets = []
        for ptg in ptgs:
            subnets.extend(ptg['subnets'])
        subnets = self._core_plugin.get_subnets(context._plugin_context,
                                                filters={'id': subnets})
        for cidr in pool.subnet(l3p['subnet_prefix_length']):
            if not self._validate_subnet_overlap_for_l3p(subnets,
                                                         cidr.__str__()):
                continue
            try:
                attrs = {'tenant_id': context.current['tenant_id'],
                         'name': APIC_OWNED + l2p['name'],
                         'network_id': l2p['network_id'],
                         'ip_version': l3p['ip_version'],
                         'cidr': cidr.__str__(),
                         'enable_dhcp': True,
                         'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                         'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                         'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                         'host_routes': attributes.ATTR_NOT_SPECIFIED}
                subnet = self._create_subnet(context._plugin_context, attrs)
                self._set_subnet_internal_route(context, subnet, l3p)
                return subnet
            except n_exc.BadRequest:
                # This is expected (CIDR overlap) until we have a
                # proper subnet allocation algorithm. We ignore the
                # exception and repeat with the next CIDR.
                pass
        raise gpexc.NoSubnetAvailable()

    def _sync_epg_subnets(self, plugin_context, l2p):
        l2p_subnets = [x['id'] for x in
                       self._get_l2p_subnets(plugin_context, l2p['id'])]
        epgs = self.gbp_plugin.get_policy_target_groups(
            nctx.get_admin_context(), {'l2_policy_id': [l2p['id']]})
        for sub in l2p_subnets:
            # Add to EPG
            for epg in epgs:
                if sub not in epg['subnets']:
                    try:
                        (self.gbp_plugin.
                         _add_subnet_to_policy_target_group(
                             nctx.get_admin_context(), epg['id'], sub))
                    except gpolicy.PolicyTargetGroupNotFound as e:
                        LOG.warn(e)

    def _get_l2p_subnets(self, plugin_context, l2p_id):
        l2p = self.gbp_plugin.get_l2_policy(plugin_context, l2p_id)
        return self._core_plugin.get_subnets(
            plugin_context, {'network_id': [l2p['network_id']]})

    def _configure_shadow_epg(self, context, l2p, bd_name, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            shadow_epg = self.name_mapper.l2_policy(
                context, l2p['id'], prefix=SHADOW_PREFIX)
            self.apic_manager.ensure_epg_created(
                tenant, shadow_epg, bd_owner=tenant, bd_name=bd_name,
                transaction=trs)

            # Create Service contract
            contract = self.name_mapper.l2_policy(
                context, l2p['id'], prefix=SERVICE_PREFIX)
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)

            # Shadow EPG provides this contract
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=True,
                contract_owner=tenant, transaction=trs)

            # Create DHCP filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 68,
                     'dFromPort': 68,
                     'sToPort': 67,
                     'sFromPort': 67}
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'dhcp', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 67,
                     'dFromPort': 67,
                     'sToPort': 68,
                     'sFromPort': 68}
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'r-dhcp', transaction=trs, **attrs)

            # Create DNS filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 'dns',
                     'dFromPort': 'dns'}
            self._associate_service_filter(tenant, contract, 'dns',
                                           'dns', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'sToPort': 'dns',
                     'sFromPort': 'dns'}
            self._associate_service_filter(tenant, contract, 'dns',
                                           'r-dns', transaction=trs, **attrs)

            # Create ARP filter/subject
            attrs = {'etherT': 'arp'}
            self._associate_service_filter(tenant, contract, 'arp',
                                           'arp', transaction=trs, **attrs)

            # Create HTTP filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'tcp',
                     'dToPort': 80,
                     'dFromPort': 80}
            self._associate_service_filter(tenant, contract, 'http',
                                           'http', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'tcp',
                     'sToPort': 80,
                     'sFromPort': 80}
            self._associate_service_filter(tenant, contract, 'http',
                                           'r-http', transaction=trs, **attrs)

            attrs = {'etherT': 'ip',
                     'prot': 'icmp'}
            self._associate_service_filter(tenant, contract, 'icmp',
                                           'icmp', transaction=trs, **attrs)

    def _create_any_contract(self, l2p, chain_id, transaction=None):
        tenant = self._tenant_by_sharing_policy(l2p)
        contract = ANY_PREFIX + chain_id
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.create_contract(
                    contract, owner=tenant, transaction=trs)
            attrs = {'etherT': 'unspecified'}
            self._associate_service_filter(
                tenant, contract, contract, contract, transaction=trs, **attrs)

    def _associate_service_filter(self, tenant, contract, filter_name,
                                  entry_name, transaction=None, **attrs):
        with self.apic_manager.apic.transaction(transaction) as trs:
            filter_name = '%s-%s' % (str(self.apic_manager.app_profile_name),
                                     filter_name)
            self.apic_manager.create_tenant_filter(
                filter_name, owner=tenant, entry=entry_name,
                transaction=trs, **attrs)
            self.apic_manager.manage_contract_subject_bi_filter(
                contract, contract, filter_name, owner=tenant,
                transaction=trs, rule_owner=tenant)

    def _delete_shadow_epg(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            shadow_epg = self.name_mapper.l2_policy(
                context, l2p['id'], prefix=SHADOW_PREFIX)
            self.apic_manager.delete_epg_for_network(
                tenant, shadow_epg, transaction=trs)

            # Delete Service Contract
            contract = self.name_mapper.l2_policy(
                context, l2p['id'], prefix=SERVICE_PREFIX)
            self.apic_manager.delete_contract(
                contract, owner=tenant, transaction=trs)

    def _configure_epg_service_contract(self, context, ptg, l2p, epg_name,
                                        transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            contract_owner = self._tenant_by_sharing_policy(l2p)
            tenant = self._tenant_by_sharing_policy(ptg)
            contract = self.name_mapper.l2_policy(
                context, l2p['id'], prefix=SERVICE_PREFIX)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=False,
                contract_owner=contract_owner, transaction=trs)

    def _get_ptgs_servicechain(self, session, provider_ptg_id, prs_id=None):
        with session.begin(subtransactions=True):
            query = session.query(
                ApicPtgServiceChainInstanceMapping)
            if provider_ptg_id:
                query = query.filter_by(provider_ptg_id=provider_ptg_id)
            if prs_id:
                query = query.filter_by(policy_rule_set_id=prs_id)
            return query.all()

    def _cleanup_service_chains(self, ptg_context, removed_provided):
        plugin_context = ptg_context._plugin_context
        for prs in removed_provided:
            for chain in self._get_ptgs_servicechain(
                    plugin_context.session, ptg_context.current['id'], prs):
                l2p = self.gbp_plugin.get_l2_policy(
                    ptg_context._plugin_context,
                    ptg_context.current['l2_policy_id'])
                self._unchain_ptg_pair(ptg_context, chain,
                                       ptg_context.current, l2p)

    def _cleanup_redirect_rule(self, context, policy_rule,
                               policy_rule_sets=None):
        for action in context._plugin.get_policy_actions(
                context._plugin_context,
                filters={'id': policy_rule['policy_actions']}):
            if action['action_type'] == g_const.GP_ACTION_REDIRECT:
                for chain in self._chains_by_rule(context, policy_rule,
                                                  policy_rule_sets):
                    provider = self.gbp_plugin.get_policy_target_group(
                        context._plugin_context, chain.provider_ptg_id)
                    l2p = self.gbp_plugin.get_l2_policy(
                        context._plugin_context, provider['l2_policy_id'])
                    self._unchain_ptg_pair(context, chain, provider, l2p)
                break

    def _hadle_redirect_rule(self, context, policy_rule,
                             policy_rule_sets=None):
        policy_rule_sets = (policy_rule_sets if policy_rule_sets is not None
                            else policy_rule['policy_rule_sets'])
        r_action = self._get_redirect_action(context, policy_rule)
        if r_action and r_action['action_value']:
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context, filters={'id': policy_rule_sets}):
                # Mash providers and consumenrs
                for prov in prs['providing_policy_target_groups']:
                    self._chain_ptg_pair(context, r_action, policy_rule,
                                         prov, prs)

    def _handle_service_chains(self, ptg_context, added_provided):

        screened_provided = self._screen_prss_with_redirect(ptg_context,
                                                            added_provided)
        for info in screened_provided:
            policy_action = info['pa']
            policy_rule = info['pr']
            if policy_action['action_value']:
                # Instance SC
                self._chain_ptg_pair(
                    ptg_context, policy_action, policy_rule,
                    ptg_context.current['id'], info['prs'])
                return True
        return False

    def _chain_ptg_pair(self, context, action, rule, provider_id, prs):
        instances = self._get_ptg_servicechain_instance_mappings(
            context._plugin_context.session, provider_id, prs['id'])
        if not instances:
            sc_instance_id = self._create_servicechain_instance(
                context, action.get("action_value"),
                None, provider_id, 'someone',
                rule['policy_classifier_id'])['id']

            # Create N shadow BDs, one for each transparent service
            spec = self.sc_plugin.get_servicechain_spec(
                context._plugin_context, action.get("action_value"))
            nodes = self.sc_plugin.get_servicechain_nodes(
                context._plugin_context, {'id': spec['nodes']})
            provider_ptg = self.gbp_plugin.get_policy_target_group(
                context._plugin_context, provider_id)
            l2p = self.gbp_plugin.get_l2_policy(context._plugin_context,
                                                provider_ptg['l2_policy_id'])
            tenant = self._tenant_by_sharing_policy(l2p)
            l3p = context._plugin.get_l3_policy(context._plugin_context,
                                                l2p['l3_policy_id'])
            l3_policy_name = self.name_mapper.l3_policy(context, l3p['id'])
            l2_policy_name = self.name_mapper.l2_policy(context, l2p['id'])
            ctx_owner = self._tenant_by_sharing_policy(l3p)
            any_contract = ANY_PREFIX + sc_instance_id
            n = 0
            with self.apic_manager.apic.transaction(None) as trs:
                self._create_any_contract(l2p, sc_instance_id,
                                          transaction=trs)
                for node in nodes:
                    if node['service_type'] in GOTHROUGH_SERVICES:
                        ordered_sc = str(n) + '-' + sc_instance_id
                        # Create Shadow BD for transparent service
                        self.apic_manager.ensure_bd_created_on_apic(
                            tenant, ordered_sc, ctx_owner=ctx_owner,
                            ctx_name=l3_policy_name, allow_broadcast=True,
                            unicast_route=False,
                            transaction=trs)
                        # Create one shadow EPG for each
                        self.apic_manager.ensure_epg_created(
                            tenant, ordered_sc, bd_owner=tenant,
                            bd_name=ordered_sc, transaction=trs)
                        n += 1
                if n > 0:
                    # Create shadow EPG in provider BD
                    self.apic_manager.ensure_epg_created(
                        tenant, str(n) + '-' + sc_instance_id, bd_owner=tenant,
                        bd_name=l2_policy_name, transaction=trs)

                    # consumer-side shadow EPG consumes service contract
                    c = self.name_mapper.l2_policy(
                        context, l2p['id'], prefix=SERVICE_PREFIX)
                    self.apic_manager.set_contract_for_epg(
                        tenant, str(n) + '-' + sc_instance_id, c,
                        provider=False, contract_owner=tenant,
                        transaction=trs)
                    # consumer-side shadow EPG consumes and
                    # provides everything that the real provider does.
                    for prs in context._plugin.get_policy_rule_sets(
                            context._plugin_context,
                            {'id': provider_ptg['provided_policy_rule_sets']}):
                        c = self.name_mapper.policy_rule_set(context,
                                                             prs['id'])
                        owner = self._tenant_by_sharing_policy(prs)
                        self.apic_manager.set_contract_for_epg(
                            tenant, str(n) + '-' + sc_instance_id, c,
                            provider=True, contract_owner=owner,
                            transaction=trs)
                    # Consumed
                    for prs in context._plugin.get_policy_rule_sets(
                            context._plugin_context,
                            {'id': provider_ptg['consumed_policy_rule_sets']}):
                        c = self.name_mapper.policy_rule_set(context,
                                                             prs['id'])
                        owner = self._tenant_by_sharing_policy(prs)
                        self.apic_manager.set_contract_for_epg(
                            tenant, str(n) + '-' + sc_instance_id, c,
                            provider=False, contract_owner=owner,
                            transaction=trs)

            # Attach Provider to the 0th shadow BD
            provider_name = self.name_mapper.policy_target_group(context,
                                                                 provider_id)
            prov_tenant = self._tenant_by_sharing_policy(provider_ptg)
            if n > 0:
                # Move provider EPG to shadow BD
                self.apic_manager.ensure_epg_created(
                    prov_tenant, provider_name, bd_owner=tenant,
                    bd_name='0-' + sc_instance_id)
                # Provider and 0th shadow EPG will be linked by an
                # ANY contract
                self.apic_manager.set_contract_for_epg(
                    tenant, '0-' + sc_instance_id, any_contract,
                    provider=False, contract_owner=tenant)
                self.apic_manager.set_contract_for_epg(
                    prov_tenant, provider_name, any_contract, provider=True,
                    contract_owner=tenant)
        else:
            sc_instance_id = instances[0].servicechain_instance_id
        self._set_apic_ptg_servicechain_instance_mapping(
            context._plugin_context.session, provider_id, sc_instance_id,
            prs['id'])

    def _unchain_ptg_pair(self, context, chain, provider, l2p):
        try:
            sc_instance_id = chain.servicechain_instance_id
            l2_policy_name = self.name_mapper.l2_policy(
                context, l2p['id'])
            tenant = self._tenant_by_sharing_policy(l2p)
            instance = self.sc_plugin.get_servicechain_instance(
                context._plugin_context, sc_instance_id)
            specs = self.sc_plugin.get_servicechain_specs(
                context._plugin_context,
                {'id': instance['servicechain_specs']})
            any_contract = ANY_PREFIX + sc_instance_id
            provider_name = self.name_mapper.policy_target_group(
                context, provider['id'])
            prov_tenant = self._tenant_by_sharing_policy(
                provider)
            for spec in specs:
                nodes = self.sc_plugin.get_servicechain_nodes(
                    context._plugin_context, {'id': spec['nodes']})
                with self.apic_manager.apic.transaction(None) as trs:
                    n = 0
                    for node in nodes:
                        if node['service_type'] not in GOTHROUGH_SERVICES:
                            continue
                        if n == 0:
                            # Move provider EPG back to original BD
                            self.apic_manager.ensure_epg_created(
                                prov_tenant, provider_name, bd_owner=tenant,
                                bd_name=l2_policy_name)
                        ordered_sc = str(n) + '-' + sc_instance_id
                        self.apic_manager.delete_bd_on_apic(
                            tenant, ordered_sc, transaction=trs)
                        self.apic_manager.delete_epg_for_network(
                            tenant, ordered_sc, transaction=trs)
                        n += 1
                    # Delete shadow consumer-side EPG
                    self.apic_manager.delete_epg_for_network(
                        tenant, str(n) + '-' + sc_instance_id, transaction=trs)
                # Unset ANY contract from provider
                self.apic_manager.unset_contract_for_epg(
                    prov_tenant, provider_name, any_contract,
                    provider=True, contract_owner=tenant)
                self.apic_manager.delete_contract(any_contract, owner=tenant)
            self._delete_servicechain_instance(
                context, chain.servicechain_instance_id)
        except (schain.ServiceChainInstanceNotFound,
                orm_exc.ObjectDeletedError):
            LOG.warn(_("Service chain instance not found."))
        with context._plugin_context.session.begin(subtransactions=True):
            try:
                context._plugin_context.session.delete(chain)
            except Exception as e:
                LOG.warn(e.message)

    def _screen_prss_with_redirect(self, context, to_screen=None):
        if to_screen is not None and len(to_screen) == 0:
            # No result will be found in this case
            return []
        session = context._plugin_context.session
        with session.begin(subtransactions=True):
            query = session.query(
                gpdb.gpdb.PolicyRuleSet, gpdb.gpdb.PolicyRule,
                gpdb.gpdb.PolicyAction)
            query = query.join(gpdb.gpdb.PRSToPRAssociation)
            query = query.join(gpdb.gpdb.PolicyRule)
            query = query.join(gpdb.gpdb.PolicyRuleActionAssociation)
            query = query.join(gpdb.gpdb.PolicyAction)
            query = query.filter(gpdb.gpdb.PolicyAction.action_type ==
                                 'redirect')
            if to_screen is not None:
                query = query.filter(gpdb.gpdb.PolicyRuleSet.id.in_(to_screen))
            result = query.all()
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return [{'prs': db_utils._make_policy_rule_set_dict(x[0]),
                     'pr': db_utils._make_policy_rule_dict(x[1]),
                     'pa': db_utils._make_policy_action_dict(x[2])}
                    for x in result]

    def _chains_by_rule(self, context, policy_rule, policy_rule_sets=None):
        policy_rule_sets = (policy_rule_sets if policy_rule_sets is not None
                            else policy_rule['policy_rule_sets'])
        if len(policy_rule_sets) == 0:
            # No result will be found in this case
            return []
        session = context._plugin_context.session
        with session.begin(subtransactions=True):
            result = (session.query(
                      ApicPtgServiceChainInstanceMapping).
                      filter(ApicPtgServiceChainInstanceMapping.
                             policy_rule_set_id.in_(policy_rule_sets))).all()
            return result

    def _get_redirect_action(self, context, policy_rule):
        for action in context._plugin.get_policy_actions(
                context._plugin_context,
                filters={'id': policy_rule['policy_actions']}):
            if action['action_type'] == g_const.GP_ACTION_REDIRECT:
                return action

    def _set_apic_ptg_servicechain_instance_mapping(
            self, session, provider_ptg_id, servicechain_instance_id, prs_id):
        with session.begin(subtransactions=True):
            mapping = ApicPtgServiceChainInstanceMapping(
                provider_ptg_id=provider_ptg_id,
                servicechain_instance_id=servicechain_instance_id,
                policy_rule_set_id=prs_id)
            session.add(mapping)

    def _get_ptg_servicechain_instance_mappings(self, session,
                                                provider_ptg_id=None,
                                                prs_id=None, sc_id=None):
        with session.begin(subtransactions=True):
            query = session.query(ApicPtgServiceChainInstanceMapping)
            if provider_ptg_id:
                query = query.filter(
                    ApicPtgServiceChainInstanceMapping.provider_ptg_id ==
                    provider_ptg_id)
            if prs_id:
                query = query.filter(
                    ApicPtgServiceChainInstanceMapping.policy_rule_set_id ==
                    prs_id)
            if sc_id:
                query = query.filter(
                    ApicPtgServiceChainInstanceMapping.
                    servicechain_instance_id == sc_id)
            return query.all()

    def _validate_ptg_prss(self, context, ptg):
        # If the PTG is providing a redirect PRS, it can't provide and consume
        # anything else
        if self._prss_redirect_rules(context._plugin_context.session,
                                     ptg['provided_policy_rule_sets']) > 1:
                raise PTGAlreadyProvidingRedirectPRS(ptg_id=ptg['id'])

    def _validate_new_prs_redirect(self, context, prs):
        if self._prss_redirect_rules(context._plugin_context.session,
                                     [prs['id']]) > 1:
            raise gpexc.MultipleRedirectActionsNotSupportedForPRS()
        for ptg in context._plugin.get_policy_target_groups(
                context._plugin_context,
                {'id': prs['providing_policy_target_groups']}):
            if self._prss_redirect_rules(
                    context._plugin_context.session,
                    ptg['provided_policy_rule_sets']) > 1:
                raise PTGAlreadyProvidingRedirectPRS(ptg_id=ptg['id'])

    def _prss_redirect_rules(self, session, prs_ids):
        if len(prs_ids) == 0:
            # No result will be found in this case
            return 0
        query = (session.query(gpdb.gpdb.PolicyAction).
                 join(gpdb.gpdb.PolicyRuleActionAssociation).
                 join(gpdb.gpdb.PolicyRule).
                 join(gpdb.gpdb.PRSToPRAssociation).
                 filter(
                 gpdb.gpdb.PRSToPRAssociation.policy_rule_set_id.in_(prs_ids)).
                 filter(gpdb.gpdb.PolicyAction.action_type ==
                        g_const.GP_ACTION_REDIRECT))
        return query.count()

    def _multiple_pr_redirect_action_number(self, session, pr_ids):
        # Given a set of rules, gives the total number of redirect actions
        # found
        if len(pr_ids) == 0:
            # No result will be found in this case
            return 0
        return (session.query(gpdb.gpdb.PolicyAction).
                join(gpdb.gpdb.PolicyRuleActionAssociation).
                filter(
                gpdb.gpdb.PolicyRuleActionAssociation.policy_rule_id.in_(
                    pr_ids)).
                filter(gpdb.gpdb.PolicyAction.action_type ==
                       g_const.GP_ACTION_REDIRECT)).count()

    def _get_ptg_transparent_chain_length(self, context, ptg_id):
        sc_instance_id = self._get_ptg_servicechain_instance_mappings(
            context._plugin_context.session, provider_ptg_id=ptg_id)
        if not sc_instance_id:
            return None, 0
        else:
            sc_instance_id = sc_instance_id[0].servicechain_instance_id
        instance = self.sc_plugin.get_servicechain_instance(
            context._plugin_context, sc_instance_id)
        specs = self.sc_plugin.get_servicechain_specs(
            context._plugin_context,
            {'id': instance['servicechain_specs']})
        n = 0
        for node in self.sc_plugin.get_servicechain_nodes(
                context._plugin_context, {'id': specs[0]['nodes']}):
            if node['service_type'] in GOTHROUGH_SERVICES:
                n += 1
        return sc_instance_id, n
