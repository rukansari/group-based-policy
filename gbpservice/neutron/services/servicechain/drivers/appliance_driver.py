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
from neutron.services.socli.so_client import ServiceOrchestratorClient \
    as ServiceManager
from oslo.config import cfg

from gbpservice.neutron.services.servicechain.common import exceptions as exc
from gbpservice.neutron.services.servicechain.drivers import simplechain_driver
from gbpservice.neutron.services.grouppolicy.common import constants


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
SC_METADATA = '{"sc_instance":"%s", "order":"%s", "provider_ptg":"%s", ' \
              '"svc_mgmt_port":"%s"}'
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
        # TODO(Sumit):Raise an exception ??
        if not stack_template:
            LOG.error(_("Service Config is not defined for the service"
                        " chain Node"))
            return
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
        else:
            config_param_names = list()
        # Retrieve classifier details
        # classifier_id = sc_instance.get('classifier_id')
        # classifier = self._grouppolicy_plugin.get_policy_classifier(
        #    context._plugin_context, classifier_id)

        # Retrieve consumer details - With Intercloud SC instance is created
        # on just provider create. Consumer is not coming
        consumer_ptg_id = sc_instance.get('consumer_ptg_id')
        # consumer_ptg = self._grouppolicy_plugin.get_policy_target_group(
        #    context._plugin_context, consumer_ptg_id)
        # consumer_ptg_subnet_id = consumer_ptg[0]['subnets'][0]
        # subnet = self._core_plugin.get_subnet(
        #    context._plugin_context, consumer_ptg['subnets'][0])
        # consumer_cidr = subnet['cidr']

        # Retrieve provider details
        provider_ptg_id = sc_instance.get('provider_ptg_id')
        provider_ptg = self._grouppolicy_plugin.get_policy_target_group(
            context._plugin_context, provider_ptg_id)
        provider_policy_rule_sets_list = provider_ptg[
            "provided_policy_rule_sets"]
        provider_policy_rule_sets = \
            self._grouppolicy_plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': provider_policy_rule_sets_list})
                #filters=provider_policy_rule_sets_list)

        # Get service instance type
        instance_type = sc_node['service_type']

        # This is stupid
        if instance_type == 'FIREWALL_TRANSPARENT':
            policy_rule_ids = list()
            for rule_set in provider_policy_rule_sets:
                policy_rule_ids.extend(rule_set.get("policy_rules"))

            policy_rules = self._grouppolicy_plugin.get_policy_rules(
                context._plugin_context, filters={'id': policy_rule_ids})

            i = 0
            policy_action_classifier_list = list()
            for policy_rule in policy_rules:
                policy_action_ids = policy_rule.get("policy_actions")
                policy_actions_detail = \
                    self._grouppolicy_plugin.get_policy_actions(
                        context._plugin_context, filters={'id': policy_action_ids})
                for policy_action in policy_actions_detail:
                    if (policy_action["action_type"] ==
                            constants.GP_ACTION_ALLOW):
                        policy_action_classifier = \
                            self._grouppolicy_plugin.get_policy_classifier(
                                context._plugin_context, policy_rule.get(
                                    "policy_classifier_id"))

                        firewall_rule_dict = (
                            dict(rule_no=(i+1),
                            protocol=policy_action_classifier.get("protocol"),
                            consumer_cidr="0.0.0.0/0",
                            destination_port=policy_action_classifier.get(
                                "port_range"))
                        )

                        rule_name = "Rule_%s" % i
                        stack_template['resources'][rule_name] = \
                            self._generate_firewall_rule_template(
                            firewall_rule_dict)
                        policy_action_classifier_list.append({'get_resource':
                                                              rule_name})

            stack_template['resources']['Firewall_Policy']['properties'][
                'firewall_rules'] = policy_action_classifier_list


        sc_instance_id = sc_instance['id']
        filters = {'name': [SVC_MGMT_PTG_NAME]}
        svc_mgmt_ptgs = self._grouppolicy_plugin.get_policy_target_groups(
            context._plugin_context, filters)
        pt_type = TRANSPARENT_PT

        if sc_node['service_type'] == pconst.LOADBALANCER:
            pt_type = SERVICE_PT
            provider = (
                stack_template['Resources']['HaproxyPool']['Properties'].get(
                                                                    'provider')
            )

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

        if 'external_network_id' in config_param_names:
            filters = {}
            filters['router:external'] = "True"
            ext_networks = self._core_plugin.get_networks(
                context._plugin_context, filters)
            external_net_id = ''
            if ext_networks:
                external_net_id = ext_networks[0]['id']
            config_param_values['external_network_id'] = external_net_id
        
        firewall_desc = dict()
        instance_type = sc_node['service_type']
        if (instance_type == pconst.LOADBALANCER and
            provider == 'haproxy_on_vm'):
            # Create service mgmt pt we won't have floating ip for CISCO
            svc_mgmt_port = self.svc_mgr.create_port(
                context._plugin_context.tenant_id, svc_mgmt_ptgs[0]
                ['subnets'][0], service_type=sc_node['service_type'])
            # svc_mgmt_pt = self.create_pt(context, svc_mgmt_ptgs[0]['id'])
            svc_mgmt_pt = self.create_pt(context, svc_mgmt_ptgs[0]['id'],
                                         port_id=svc_mgmt_port['id'])
            if 'service_chain_metadata' in config_param_names:
                config_param_values['service_chain_metadata'] = (
                                SC_METADATA % (sc_instance_id, order,
                                               provider_ptg_id,
                                               svc_mgmt_port['id']))
            # LB driver now uses vip port itself to launch VM
            # Create provider port. Pass PT name as SERVICE_PT
            # pt_type = SERVICE_PT
            # provider_pt = self.create_pt(context, provider_ptg_id,
            #                             name=PROVIDER_PT_NAME % (order,
            #                                                      pt_type))
            '''
            service_instance_id = self.svc_mgr.create_service_instance(
                context._plugin_context, instance_type, provider_pt[
                    "port_id"], svc_mgmt_pt["port_id"])
            '''

        if instance_type == 'FIREWALL_TRANSPARENT':

            # Create service mgmt pt we won't have floating ip for CISCO
            svc_mgmt_port = self.svc_mgr.create_port(
                context._plugin_context.tenant_id, svc_mgmt_ptgs[0]
                ['subnets'][0], service_type=sc_node['service_type'])

            svc_mgmt_pt = self.create_pt(context, svc_mgmt_ptgs[0]['id'],
                                         port_id=svc_mgmt_port['id'])

            # Create two provider port (*_left and *_right represents as
            # consumer and provider port) for Firewall
            # provider_port_left = self.svc_mgr.create_port(
            #     context._plugin_context.tenant_id,provider_ptg['subnets'][0],
            #     service_type=sc_node['service_type'])
            provider_pt_left = self.create_pt(context, provider_ptg_id,
                                         name=CONSUMER_PT_NAME % (order,
                                                                  pt_type))
            provider_port_left = self._core_plugin.get_port(
                context._plugin_context, provider_pt_left["port_id"])

            # provider_port_right = self.svc_mgr.create_port(
            #     context._plugin_context.tenant_id,provider_ptg['subnets'][0],
            #     service_type=sc_node['service_type'])
            provider_pt_right = self.create_pt(context, provider_ptg_id,
                                         name=PROVIDER_PT_NAME % (order,
                                                                  pt_type))

            provider_port_right = self._core_plugin.get_port(
                context._plugin_context, provider_pt_right["port_id"])


            # Create provider & consumer port for Firewall
            # consumer_pt = self.create_pt(context, consumer_ptg_id,
            #                              name=CONSUMER_PT_NAME % (order,
            #                                                       pt_type))

            service_instance_id = self.svc_mgr.create_service_instance(
                context._plugin_context, instance_type, provider_pt_left[
                    "port_id"], svc_mgmt_pt["port_id"],
                right_port=provider_pt_right["port_id"])

            floating_ip = self.svc_mgr.get_service_floating_ip(
                context._plugin_context, sc_node['service_type'])
            firewall_desc.update({'vm_management_ip': floating_ip})
            firewall_desc.update({'provider_ptg_info': [provider_port_right[
                'mac_address']]})
            stack_template['resources']['Firewall']['properties'][
                'description'] = str(firewall_desc)

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

    def _generate_firewall_rule_template(self, firewall):
        return {"type": "OS::Neutron::FirewallRule",
                "properties": {
                    "protocol": firewall.get("protocol"),
                    "enabled": True,
                    "destination_port": firewall.get("destination_port"),
                    "action": "allow",
                    "source_ip_address": firewall.get("consumer_cidr")
                    }
                }


    def _generate_pool_member_template(self, param_name):
        return {"Type": "OS::Neutron::PoolMember",
                "Properties": {
                    "address": {"Ref": param_name},
                    "admin_state_up": True,
                    "pool_id": {"Ref": "HaproxyPool"},
                    "protocol_port": 80,
                    "weight": 1}}

    # Need to pass port name for Cisco.
    def create_pt(self, context, ptg_id, name=None, port_id=None):
        if not name:
            name = "port1"
        pt = dict(name=name, description="",
                  tenant_id=context._plugin_context.tenant_id,
                  policy_target_group_id=ptg_id, port_id=port_id)

        return self._grouppolicy_plugin.create_policy_target(
            context._plugin_context, {"policy_target": pt})

    def delete_servicechain_instance_postcommit(self, context):
        filters = {'id': context.current['servicechain_specs']}
        specs = context._plugin.get_servicechain_specs(
            context._plugin_context, filters)

        for spec in specs:
            node_list = spec.get('nodes')
            filters = {'id': node_list}
            sc_nodes = context._plugin.get_servicechain_nodes(
                context._plugin_context, filters)
            for node in sc_nodes:
                stack_template = node.get('config')
                stack_template = jsonutils.loads(stack_template)
                if node['service_type'] ==  pconst.LOADBALANCER:
                    provider = (
                        stack_template['Resources']['HaproxyPool'][
                                    'Properties'].get('provider'))
                if (node['service_type'] ==  pconst.LOADBALANCER and
                    provider == 'haproxy_on_vm' or
                    node['service_type'] == 'FIREWALL_TRANSPARENT'):

                    instance_ports = self.svc_mgr.get_service_ports(
                        context._plugin_context, node['service_type'])
                    # instance_ports = self.svc_mgr.get_service_ports(
                    #     context._plugin_context, node['service_type'])
                    if instance_ports:
                        if instance_ports.get("data_port_id"):
                            filters = {'port_id': [instance_ports[
                                                    'data_port_id']]}
                            policy_targets = (
                                self._grouppolicy_plugin.get_policy_targets(
                                    context._plugin_context, filters))
                            if policy_targets:
                                self._grouppolicy_plugin.delete_policy_target(
                                    context._plugin_context, policy_targets[0][
                                        'id'])
    
                        if instance_ports.get("mgmt_port_id"):
                            filters = {'port_id': [instance_ports[
                                                        'mgmt_port_id']]}
                            policy_targets = (
                                self._grouppolicy_plugin.get_policy_targets(
                                    context._plugin_context, filters))
                            if policy_targets:
                                self._grouppolicy_plugin.delete_policy_target(
                                    context._plugin_context, policy_targets[0][
                                        'id'])
                    if node['service_type'] == 'FIREWALL_TRANSPARENT':
                        self.svc_mgr.delete_service_instance(
                            context._plugin_context, node['service_type'])

        self._delete_servicechain_instance_stacks(context._plugin_context,
                                                  context.current['id'])
