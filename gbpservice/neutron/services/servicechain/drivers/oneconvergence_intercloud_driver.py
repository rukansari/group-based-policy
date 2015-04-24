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

import ast

from neutron.common import log
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from neutron.services.loadbalancer.drivers.OneConvergence.device_manager  \
    import DeviceManager as ServiceManager
from oslo.config import cfg

from gbpservice.neutron.services.servicechain.common import exceptions as exc
from gbpservice.neutron.services.servicechain.drivers import simplechain_driver


appliance_driver_opts = [
    cfg.StrOpt('svc_management_ptg_name',
               default='Service_Management_Tier',
               help=_("Name of the PTG that is associated with the "
                      "service management network")),
]

cfg.CONF.register_opts(appliance_driver_opts, "appliance_driver")

sc_supported_type = [pconst.LOADBALANCER, 'FIREWALL_TRANSPARENT', 'IDS']
TRANSPARENT_PT = "transparent"
SERVICE_PT = "service"
PROVIDER_PT_NAME = "chain_provider_%s_%s"
CONSUMER_PT_NAME = "chain_consumer_%s_%s"
SC_METADATA = '{"sc_instance":"%s", "order":"%s", "provider_ptg":"%s", "svc_mgmt_ptg":"%s"}'
SVC_MGMT_PTG_NAME = cfg.CONF.appliance_driver.svc_management_ptg_name

POOL_MEMBER_PARAMETER = {"Description": "Pool Member IP Address",
                         "Type": "String"}

LOG = logging.getLogger(__name__)


class ChainWithTwoArmAppliance(simplechain_driver.SimpleChainDriver):

    def __init__(self):
        super(ChainWithTwoArmAppliance, self).__init__()
        self.svc_mgr = ServiceManager()

    @log.log
    def create_servicechain_node_precommit(self, context):
        if context.current['service_type'] not in sc_supported_type:
            raise exc.InvalidServiceTypeForReferenceDriver()

    def _fetch_template_and_params(self, context, sc_instance,
                                   sc_spec, sc_node, order):
        stack_template = sc_node.get('config')
        # TODO(Magesh):Raise an exception ??
        if not stack_template:
            LOG.error(_("Service Config is not defined for the service"
                        " chain Node"))
            return
        instance_type = sc_node['service_type']
        stack_template = jsonutils.loads(stack_template)
        config_param_values = sc_instance.get('config_param_values', {})
        stack_params = {}
        # config_param_values has the parameters for all Nodes. Only apply
        # the ones relevant for this Node
        if config_param_values:
            config_param_values = jsonutils.loads(config_param_values)
        config_param_names = sc_spec.get('config_param_names', [])
        if config_param_names:
            config_param_names = ast.literal_eval(config_param_names)

        provider_ptg_id = sc_instance.get('provider_ptg_id')
        consumer_ptg_id = sc_instance.get('consumer_ptg_id')
        sc_instance_id = sc_instance['id']
        filters = {'name': [SVC_MGMT_PTG_NAME]}
        svc_mgmt_ptgs = self._grouppolicy_plugin.get_policy_target_groups(
            context._plugin_context, filters)
        pt_type = TRANSPARENT_PT

        # Create port on provider pt and service mgmt pt
        provider_pt = self.create_pt(self, context, provider_ptg_id)
        svc_mgmt_pt = self.create_pt(self, context, svc_mgmt_ptgs[0]['id'])

        # Create service instance
        _user_token = self.svc_mgr._get_user_token(context.tenant_id)
        service_instance_id = self.svc_mgr._create_instance(
            _user_token, context.tenant_id, instance_type, provider_pt[
                "port_id"], svc_mgmt_pt["port_id"])

        if sc_node['service_type'] == pconst.LOADBALANCER:
            pt_type = SERVICE_PT
            self._generate_pool_members(context, stack_template,
                                        config_param_values, provider_ptg_id)
            if 'Subnet' in config_param_names:
                value = self._get_ptg_subnet(context, provider_ptg_id)
                config_param_values['Subnet'] = value

        if 'provider_ptg' in config_param_names:
            config_param_values['provider_ptg'] = provider_ptg_id
        if 'consumer_ptg' in config_param_names:
            config_param_values['consumer_ptg'] = consumer_ptg_id
        if 'provider_pt_name' in config_param_names:
            config_param_values['provider_pt_name'] = PROVIDER_PT_NAME % (
                order, pt_type)
        if 'consumer_pt_name' in config_param_names:
            config_param_values['consumer_pt_name'] = CONSUMER_PT_NAME % (
                order, pt_type)
        if 'service_chain_metadata' in config_param_names:
            config_param_values['service_chain_metadata'] = (
                SC_METADATA % (sc_instance_id, order, provider_ptg_id,
                               svc_mgmt_ptgs[0]['id']))
        if 'svc_mgmt_ptg' in config_param_names:
            config_param_values['svc_mgmt_ptg'] = svc_mgmt_ptgs[0]['id']
	# TODO(Magesh): Retrieve the ext-net from external-segment
	if 'external_network_id' in config_param_names:
	    filters = {}
	    filters['router:external'] = "True"
	    ext_networks = self._core_plugin.get_networks(context._plugin_context, filters)
	    if ext_networks:
		external_net_id = ext_networks[0]['id']
	    config_param_values['external_network_id'] = external_net_id
        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters'))
        if node_params:
            for parameter in config_param_values.keys():
                if parameter in node_params.keys():
                    stack_params[parameter] = config_param_values[parameter]
        LOG.debug(stack_template)
        return stack_template, stack_params

    def _generate_pool_members(self, context, stack_template,
                               config_param_values, provider_ptg_id):
        member_ips = self._get_member_ips(context, provider_ptg_id)
        member_count = 0
        for member in member_ips:
            template_name = 'mem-' + member
            param_name = 'par-' + member
            stack_template['Resources'][template_name] = (
                self._generate_pool_member_template(param_name))
            stack_template['Parameters'][param_name] = POOL_MEMBER_PARAMETER
            config_param_values[param_name] = member
            member_count += 1

    def _generate_pool_member_template(self, param_name):
        return {"Type": "OS::Neutron::PoolMember",
                "Properties": {
                    "address": {"Ref": param_name},
                    "admin_state_up": True,
                    "pool_id": {"Ref": "HaproxyPool"},
                    "protocol_port": 80,
                    "weight": 1}}

    def create_pt(self, context, ptg_id):
        pt = dict(name="port1", description={}, tenant_id=context.tenant_id,
                  policy_target_group_id=ptg_id)
        return self._grouppolicy_plugin.create_policy_target(
            context._plugin_context, pt)

    def delete_servicechain_instance_postcommit(self, context):
        filters = {'id': context.current.servicechain_specs}
        specs = context._plugin.get_servicechain_specs(context._plugin_context,
                                               filters)

        for spec in specs:
            node_list = spec.get('nodes')
            filters = {'id': node_list}
            sc_nodes = context._plugin.get_servicechain_nodes(
                context._plugin_context, filters)
            for node in sc_nodes:
                self.svc_mgr.delete_service_instance(context,
                                                     node['service_type'])

        self._delete_servicechain_instance_stacks(context._plugin_context,
                                                  context.current['id'])


