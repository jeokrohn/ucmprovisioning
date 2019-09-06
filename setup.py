'''
Created on 01.07.2017

@author: jkrohn
!!! To Do
    * Set default user credential policy for users (PIN for LDAP synced users etc.)
    * set default CM group
    * Im&P configuration..

'''

import zeep.transports
import zeep.exceptions
import logging.config
import re
import ucmaxl
import zeep.wsdl.utils
import yaml
import ucmcontrolcenter
import datetime
import urllib3


class UCMConfigurator:
    def __init__(self, config):
        self.config = config
        # UCM control center API helper
        self.control_center = ucmcontrolcenter.ControlCenterHelper(auth=(self.target['auth']['user'],
                                                                         self.target['auth']['password']),
                                                                   version='12.0',
                                                                   verify=False)

        # UCM AXL helper
        self.axl = ucmaxl.AXLHelper(self.target['ucm'],
                                    auth=(self.target['auth']['user'], self.target['auth']['password']),
                                    version='12.0',
                                    verify=False)

    @property
    def target(self):
        return self.config.get('target', None)

    @property
    def dialplan(self):
        return self.config.get('dialplan', None)

    @property
    def base_dialplan(self):
        return self.config.get('base_dialplan', None)

    @property
    def cluster_id(self):
        return self.config.get('cluster_id', None)

    @property
    def enterprise_parameter(self):
        return self.config.get('enterprise_parameter', None)

    @property
    def gdpr(self):
        return self.config.get('gdpr', None)

    @property
    def services(self):
        return self.config.get('services', None)

    @property
    def ldap(self):
        return self.config.get('ldap', None)

    @property
    def routing(self):
        return self.config.get('routing', None)

    def __getattr__(self, item):
        return self.axl.__getattribute__(item)

    def get_site_plus_e164(self, site):
        """
        Get full +E.164 of a site!!!
        :param site: three character site code (SJC, ..)
        :return: full +E.164 of that site's DN range incl. trailing Xes
        """
        site_info = self.dialplan['sites'][site]
        e164 = '+{CC}{NDC}{SN}'.format(CC=self.dialplan['habits'][site_info['habit']]['CC'], NDC=site_info['NDC'],
                                       SN=site_info['SN'])
        return e164

    def create_normalization(self, partition, habit_id, habit_info, add_desc=''):
        """
        Create dialing habit (country) specific dialing normalization translation patterns
        :param partition: partition to create the TPs in
        :param habit_id: dialing habit identifier (US, DE, ..)
        :param habit_info: dialing habit configuration data
        :param add_desc: string to be added as suffix ro descriptions of TPs
        :return: None
        """
        country_code = habit_info['CC']
        for pattern, prefix_cc in habit_info['normalisation'].items():
            prefix = '+'
            if prefix_cc:
                prefix = '{}{}'.format(prefix, country_code)

            self.axl.add_update_translation(pattern=pattern, partition=partition,
                                            description='Normalise {} {}'.format(habit_id, add_desc),
                                            digit_discard='PreDot', prefix_digits=prefix,
                                            dont_wait_for_idt=False)

            # for variable length patterns ending in ! create a second pattern with a trailing #
            if pattern[-1] == '!':
                self.axl.add_update_translation(pattern='{}#'.format(pattern), partition=partition,
                                                description='Normalise {} {}'.format(habit_id, add_desc),
                                                digit_discard='PreDot Trailing-#', prefix_digits=prefix,
                                                dont_wait_for_idt=True)
            # if
        # for
        return

    def set_cluster_id(self):
        """
        Set the UCM cluster's cluster ID (Enterprise parameter)
        :return: None
        """
        cluster_id = self.cluster_id
        if cluster_id is None:
            return

        r = self.axl.get_enterprise_parameter('ClusterID')
        if r['value'] != cluster_id:
            # need to update
            self.axl.update_enterprise_parameter('ClusterID', cluster_id)
        return

    def set_process_node_names(self):
        """
        Make sure that all process node names are FQDNs. If they aren't then a common domain suffix is appended
        :return: None
        """
        domain_suffix = self.config.get('node_domain_suffix')
        if domain_suffix is None:
            return

        process_nodes = self.axl.list_process_node()
        # ignore dummy node for Enterprise parameters
        process_nodes = [p for p in process_nodes if p['name'] != 'EnterpriseWideData']

        # which nodes are not yet FQDN?
        fqdn_tail = '.{}'.format(self.config['node_domain_suffix'])
        process_nodes = [p for p in process_nodes if not p['name'].endswith(fqdn_tail)]
        for pn in process_nodes:
            name = pn['name']
            m = re.match(r'(\d{1,3}\.){3}\d{1,3}', name)
            assert m is None, 'No idea how to handle IP addresses!'
            name = name.strip().split('.')[0]
            new_name = name.strip() + fqdn_tail
            uuid = pn['uuid']
            self.axl.update_process_node(uuid=uuid, new_name=new_name)
        return

    def set_enterprise_parameters(self):
        """
        Set a number of enterprise parameters to the desired defaults
        :return: None
        """
        # want to make sure that all URLs use FQDN of publisher
        urls = [
            'URLAuthentication',
            'URLDirectories',
            'URLInformation',
            'URLServices',
            'SecureAuthenticationURL',
            'SecureDirectoryURL',
            'SecureInformationURL',
            'SecureServicesURL',
            'SecureUDSUsersAccessURL'
        ]

        # tknodeusage: 0=publisher, 1=subscriber
        # tkprocessnoderole: 1=ucm, 2=imp
        ucm_pub = self.axl.sql_query(
            'select name from processnode where tknodeusage=0 and tkprocessnoderole=1')
        ucm_pub = ucm_pub[0]['name'].lower()
        for url_para in urls:
            value = self.axl.get_enterprise_parameter(url_para)
            value = value['value']
            # extract host from URL
            m = re.search(r'//([^:/]+)', value)
            assert m
            if m.group(0)[2:].lower().startswith(ucm_pub):
                continue
            new_value = re.sub(r'//([^:/]+)', '//{}'.format(ucm_pub), value)
            self.axl.update_enterprise_parameter(url_para, new_value)

        parameters = self.config.get('enterprise_parameter', dict())
        for param, value in parameters.items():
            try:
                self.axl.update_enterprise_parameter(param, value)
            except Exception as e:
                print(e)
        return

    def deploy_services(self):
        """
        Activate the required services on all nodes in the cluster
        :return: None
        """
        services_info = self.services
        if services_info is None:
            return
        ucm_services = services_info['ucm']
        imp_services = services_info['imp']

        # create a dict which for each service allows to lookup whether the service should only be enabled only on the pub
        ucm_services = {service: False if v is None else v.get('pub_only', False) for service, v in
                        ucm_services.items()}
        imp_services = {service: False if v is None else v.get('pub_only', False) for service, v in
                        imp_services.items()}
        # get all processnodes
        # tknodeusage: 0=publisher, 1=subscriber
        # tkprocessnoderole: 1=ucm, 2=imp
        process_nodes = self.axl.sql_query(
            'select pkid, name, tknodeusage, tkprocessnoderole from processnode where systemnode=\'f\'')
        for process_node in process_nodes:
            process_node['tkprocessnoderole'] = int(process_node['tkprocessnoderole'])
            process_node['tknodeusage'] = int(process_node['tknodeusage'])
            host = process_node['name']

            # deploy services on a single node
            services = ucm_services if process_node['tkprocessnoderole'] == 1 else imp_services
            deploy_services = [service for service, pub_only in services.items() if
                               process_node['tknodeusage'] == 0 or not pub_only]

            # get service status from node; we use the name to connect to the node
            # hence the processnode name has to be FQDN and DNS has to be there
            service_status = self.control_center.soap_get_service_status(host=host)
            service_status = {service_info['ServiceName']: {'status': service_info['ServiceStatus'],
                                                            'code': int(service_info['ReasonCode'])} for service_info in
                              service_status['ServiceInfoList']['item']}

            # only need to deploy services which are not yet activated
            deploy_services = [service for service in deploy_services if service_status[service]['code'] == -1068]
            for service in deploy_services:
                r = self.control_center.soap_do_service_deployment(host=host, node_name=host, deploy_type='Deploy',
                                                                   service_name=service)
                return_code = int(r['ReturnCode']['_value_1'])
                return_service_info = r['ServiceInfoList']['item'][0]
                if return_code != 0 or return_service_info['ServiceStatus'] not in ['Started', 'Starting']:
                    logging.error('Failed to activate \'{service}\' on {node}'.format(service=service, node=host))
                else:
                    logging.info('Started \'{service}\' on {node}'.format(service=service, node=host))
        # for
        return

    def set_service_parameter(self):
        """
        Set a number of service parameters to the desired values
        :return: None
        """
        parameters = self.config.get('service_parameter', [])
        for service in parameters:
            assert service in ['ucm']
            service_name = 'Cisco CallManager'
            service_parameters = parameters[service]
            service_parameters = {
                parameter_name: {'per_node': False, 'value': value} if not isinstance(value, dict) else
                value for parameter_name, value in service_parameters.items()}
            # if there's at lest one parameter which needs to be deployed on each node then we need to find all
            # nodes the service runs on
            if next((p for p in service_parameters.values() if p['per_node']), None):
                # tknodeusage: 0=publisher, 1=subscriber
                # tkprocessnoderole: 1=ucm, 2=imp
                ucm_nodes = self.axl.sql_query(
                    'select name from processnode where tkprocessnoderole=1 and systemnode=\'f\'')
                ucm_nodes = [r['name'] for r in ucm_nodes]
            for par, value in service_parameters.items():
                if value['per_node']:
                    for node in ucm_nodes:
                        self.axl.update_service_parameter(process_node_name=node, name=par, service=service_name,
                                                          value=value['value'])
                else:
                    self.axl.update_service_parameter(process_node_name='EnterpriseWideData', name=par,
                                                      service=service_name,
                                                      value=value['value'])
        return

    def create_base_dialplan(self):
        """
        Create a number of base dial plan elements not specific to sites or dialing domains
        :return: None
        """
        bdp = self.base_dialplan

        # provision partitions explicitly listed in config file
        partitions = bdp.get('partitions', None)
        if partitions is not None:
            for (name, description) in partitions.items():
                self.axl.add_update_route_partition(name=name, description=description)

        # provision CSSes explicitly listed in config file
        csses = bdp.get('CSSes')
        if csses is not None:
            for name in csses:
                description = csses[name].get('description', '')
                clause = csses[name]['clause']
                self.axl.add_update_css(name=name, description=description, clause=clause)

        # SIP Profiles
        sip_profiles = bdp.get('SIPProfiles', None)
        if sip_profiles is not None:
            for name, params in sip_profiles.items():
                sip_profile = {k: v for k, v in params.items()}
                sip_profile['name'] = name
                self.axl.add_update_sip_profile(sip_profile=sip_profile)

        # AAR Groups
        aar_groups = bdp.get('AAR Groups', None)
        if aar_groups is not None:
            for name in aar_groups:
                try:
                    self.axl.addAarGroup(aarGroup={'name': name})
                except zeep.exceptions.Fault as e:
                    if not e.message.startswith('Could not insert new row'):
                        raise

        # LRGs
        lrgs = bdp.get('LRGs', None)
        if lrgs is not None:
            for name, description in lrgs.items():
                self.axl.add_update_lrg(name=name, description=description)
            # for
        # if

        # route lists
        route_lists = bdp.get('routelists', None)
        if route_lists is not None:
            for name, params in route_lists.items():
                description = params.get('description')
                members = params.get('members') or []
                members = {
                    'member': [
                        {
                            'routeGroupName': rg_name,
                            'selectionOrder': i
                        }
                        for i, rg_name in enumerate(members, start=1)
                    ]
                }
                self.axl.add_update_route_list(name=name,
                                               description=description,
                                               callManagerGroupName='Default',
                                               routeListEnabled='true',
                                               runOnEveryNode='true',
                                               members=members)
            # for
        # if

        # route pattern
        route_patterns = bdp.get('routepatterns', dict())
        for pattern, params in route_patterns.items():
            params['pattern'] = pattern
            self.axl.add_update_route_pattern(**params)
        return

    def create_dial_plan(self):
        """
        Create the actual site and dialing domain specific dial plan
        :return: None
        """

        dp_info = self.dialplan

        for habit_id, habit_info in dp_info['habits'].items():
            # PSTN Partition for RPs to national destinations
            # USPSTNNational
            self.axl.add_update_route_partition(name='{}PSTNNational'.format(habit_id),
                                                description='{} National PSTN RP'.format(habit_id))

            # partition/CSS: USemergency
            self.axl.add_update_route_partition(name='{}Emergency'.format(habit_id),
                                                description='{} emergency RP'.format(habit_id))
            self.axl.add_update_css(name='{}emergency'.format(habit_id),
                                    description='{} emergency CSS'.format(habit_id),
                                    clause='{}emergency'.format(habit_id))

            # if an emergency pattern is defined for the habit then also create the RP
            emergency = habit_info.get('emergency')
            if emergency:
                self.axl.add_update_route_pattern(pattern=emergency,
                                                  partition='{}emergency'.format(habit_id),
                                                  description='{} Emergency'.format(habit_id),
                                                  route_list_name='RL_emergency')

            # dial plan based on CSS inheritance on TPs and urgent DNs
            # UStoE164 - single partition for dialing normalization
            self.axl.add_update_route_partition(name='{}toE164'.format(habit_id),
                                                description='{} normalize'.format(habit_id))
            self.create_normalization(partition='{}toE164'.format(habit_id), habit_id=habit_id, habit_info=habit_info)

            # ISDN GW egress calling party normalisation per dialing domain
            # \+<cc>.! -> strip pre dot, ISDN/national
            # \+.! -> strip pre dot, ISDN/international
            self.axl.add_update_route_partition(name='{}ISDNEgressCn'.format(habit_id),
                                                description='{} ISDN GW Egress CnPTx'.format(habit_id))
            self.axl.add_update_css(name='{}ISDNEgressCn'.format(habit_id),
                                    description='{} ISDN GW Egress CnPTx'.format(habit_id),
                                    clause='{}ISDNEgressCn'.format(habit_id))

            self.axl.add_update_cnptx(pattern='\+{}.!'.format(habit_info['CC']),
                                      partition='{}ISDNEgressCn'.format(habit_id),
                                      description='{} ISDN national'.format(habit_id),
                                      discard='PreDot',
                                      prefix='',
                                      plan='ISDN',
                                      type='National')

            self.axl.add_update_cnptx(pattern='\+.!',
                                      partition='{}ISDNEgressCn'.format(habit_id),
                                      description='{} ISDN international'.format(habit_id),
                                      discard='PreDot',
                                      prefix='',
                                      plan='ISDN',
                                      type='International')

            # phone egress calling party normalisation per dialing domain
            # \+<cc>.! -> strip pre-dot, prefix <natPrefix>
            # \+.! -> strip pre-dot, prefix <internatPrefix>
            self.axl.add_update_route_partition(name='{}PhLocalize'.format(habit_id),
                                                description='{} Phone Localization'.format(habit_id))

            self.axl.add_update_cnptx(pattern='\+{}.!'.format(habit_info['CC']),
                                      partition='{}PhLocalize'.format(habit_id),
                                      description='{} phone national'.format(habit_id),
                                      discard='PreDot',
                                      prefix=habit_info['nationalPrefix'],
                                      plan='Cisco CallManager',
                                      type='Cisco CallManager')

            self.axl.add_update_cnptx(pattern='\+.!',
                                      partition='{}PhLocalize'.format(habit_id),
                                      description='{} phone international'.format(habit_id),
                                      discard='PreDot',
                                      prefix=habit_info['internationalPrefix'],
                                      plan='Cisco CallManager',
                                      type='Cisco CallManager')
        # end of dialing habit specific DP provisioning

        # now create the site specific dial plan elements
        for site_name, site_info in dp_info['sites'].items():
            self.axl.add_update_route_partition(name='{}toE164'.format(site_name),
                                                description='Local normalisation for {}'.format(site_name))

            # SJCPSTNLocal - PSTN route patterns for local destinations
            self.axl.add_update_route_partition(name='{}PSTNLocal'.format(site_name),
                                                description='Local PSTN RP for {}'.format(site_name))

            # simplified dial plan with CSS inheritance
            # SJCInternational = DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:SJCtoE164:UStoE164:PSTNInternational:USPSTNNational
            self.axl.add_update_css(name='{}International'.format(site_name),
                                    description='{} CoS International'.format(site_name),
                                    clause='DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:{site_name}toE164:{habit}toE164:PSTNInternational:{habit}PSTNNational:B2B_URI'.format(
                                        site_name=site_name, habit=habit_id))

            # SJCNational = DN:Directory URI:URI:ESN:OnNetRemote:SJCtoE164:UStoE164:USPSTNNational
            self.axl.add_update_css(name='{}National'.format(site_name),
                                    description='{} CoS National'.format(site_name),
                                    clause='DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:{site_name}toE164:{habit}toE164:{habit}PSTNNational:B2B_URI'.format(
                                        site_name=site_name, habit=habit_id))

            # SJCLocal = DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:SJCtoE164:UStoE164:PSTNLocal
            self.axl.add_update_css(name='{}Local'.format(site_name),
                                    description='{} CoS Local'.format(site_name),
                                    clause='DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:{site_name}toE164:{habit}toE164:{site_name}PSTNLocal:B2B_URI'.format(
                                        site_name=site_name, habit=habit_id))

            # SJCInternal = DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:SJCtoE164:UStoE164
            self.axl.add_update_css(name='{}Internal'.format(site_name),
                                    description='{} CoS Internal'.format(site_name),
                                    clause='DN:Directory URI:URI:ESN:OnNetRemote:BroadCloud:{site_name}toE164:{habit}toE164'.format(
                                        site_name=site_name, habit=habit_id))

            # Translation Pattern for abbreviated intra-site dialing
            # create in SJCtoE164
            site_e164_pattern = self.get_site_plus_e164(site=site_name)
            site_to_e164_partition = '{}toE164'.format(site_name)
            subscriber_number = site_info['SN']
            # abbreviated intra site dialing: starting with the last digit before the wildcards at the end
            intra_site_4d = re.search(r'\dX+', subscriber_number).group(0)
            self.axl.add_update_translation(pattern=intra_site_4d,
                                            partition=site_to_e164_partition,
                                            description='{} Intra-Site'.format(site_name),
                                            called_party_transformation_mask=site_e164_pattern)

            esn_non_did = site_info.get('ESNnonDID')
            if esn_non_did:
                # Translation Pattern for abbreviated intra-site dialing for non-DIDs (last four digit of non-DID ESN range
                # create in SJCtoE164. Transform to ESN
                pattern = re.search(r'\dX+', esn_non_did).group(0)
                self.axl.add_update_translation(pattern=pattern,
                                                partition='{}toE164'.format(site_name),
                                                description='{} Intra-Site non-DID'.format(site_name),
                                                called_party_transformation_mask=esn_non_did)

            # Translation pattern for ESN dialing
            # for example: 8496-9XXX. The 1st four digits are the ESN from the site info in the dial plan configuration data
            pattern = '{}{}'.format(site_info['ESN'], intra_site_4d)
            self.axl.add_update_translation(pattern=pattern,
                                            partition='ESN',
                                            description='{} ESN'.format(site_name),
                                            called_party_transformation_mask=site_e164_pattern)

            # Advertise a +E.164 pattern per site
            self.axl.add_update_advertised_pattern(pattern=site_e164_pattern,
                                                   description='+E.164 {}'.format(site_name),
                                                   pattern_type='+E.164 Number',
                                                   hosted_pstn_rule='Use pattern',
                                                   pstn_strip=0,
                                                   pstn_prepend='')

            # Advertise an enterprise pattern per site
            esn = '{}{}'.format(site_info['ESN'], intra_site_4d)
            strip_digits = len(str(site_info['ESN']))
            prepend = site_e164_pattern[:-len(intra_site_4d)]
            self.axl.add_update_advertised_pattern(pattern=esn,
                                                   description='ESN {}'.format(site_name),
                                                   pattern_type='Enterprise Number',
                                                   hosted_pstn_rule='Specify',
                                                   pstn_strip=strip_digits,
                                                   pstn_prepend=prepend)

            # ... and also advertize the ESN pattern for non-DIDs (w/o PSTN failover though)
            if esn_non_did:
                self.axl.add_update_advertised_pattern(pattern=esn_non_did,
                                                       description='ESN {} non-DID'.format(site_name),
                                                       pattern_type='Enterprise Number')

            # Site specific phone egress calling party transformation
            # phone egress calling party normalisation per dialing domain
            # \+<cc><ndc><sn> -> mask
            self.axl.add_update_route_partition(name='{}PhLocalize'.format(site_name),
                                                description='{} Phone Localization'.format(site_name))

            # CSS ESCPhLocalize := {DEPhLocalize, ESCPhLocalize}
            self.axl.add_update_css(name='{}PhLocalize'.format(site_name),
                                    description='{} Phone Localization'.format(site_name),
                                    clause='{habit}PhLocalize:{site}PhLocalize'.format(habit=habit_id, site=site_name))

            mask = re.search(r'\dX+', subscriber_number).group(0)
            self.axl.add_update_cnptx(pattern='\\' + site_e164_pattern,
                                      partition='{}PhLocalize'.format(site_name),
                                      description='{} phone intra-site'.format(site_name),
                                      discard='',
                                      prefix='',
                                      mask=mask,
                                      plan='Cisco CallManager',
                                      type='Cisco CallManager'
                                      )

            # create a date/time group for the site (if defined)
            dt_group = site_info.get('dateTime', None)
            if dt_group is not None:
                self.axl.add_update_date_time_group(dt_group)

            # create device pool for phones in site with egress calling party transform set accordingly
            dp = {
                'name': '{}Phone'.format(site_name),
                'autoSearchSpaceName': '',
                # set site specific date/time group or default
                'dateTimeSettingName': dt_group['name'] if dt_group else 'CMLocal',
                'callManagerGroupName': 'Default',
                'mediaResourceListName': '',
                'regionName': 'Default',
                'networkLocale': '',
                'srstName': 'Disable',
                'connectionMonitorDuration': '-1',
                'automatedAlternateRoutingCssName': 'AAR',
                'aarNeighborhoodName': 'Default',
                'locationName': 'Hub_None',
                'mobilityCssName': '',
                'physicalLocationName': '',
                'deviceMobilityGroupName': '',
                'revertPriority': 'Default',
                'singleButtonBarge': 'Default',
                'joinAcrossLines': 'Default',
                'cgpnTransformationCssName': '{}PhLocalize'.format(site_name),
                'geoLocationName': '',
                'geoLocationFilterName': '',
                'callingPartyNationalPrefix': 'Default',
                'callingPartyInternationalPrefix': 'Default',
                'callingPartyUnknownPrefix': 'Default',
                'callingPartySubscriberPrefix': 'Default',
                'adjunctCallingSearchSpace': '',
                'callingPartyNationalStripDigits': '',
                'callingPartyInternationalStripDigits': '',
                'callingPartyUnknownStripDigits': '',
                'callingPartySubscriberStripDigits': '',
                'callingPartyNationalTransformationCssName': '',
                'callingPartyInternationalTransformationCssName': '',
                'callingPartyUnknownTransformationCssName': '',
                'callingPartySubscriberTransformationCssName': '',
                'calledPartyNationalPrefix': 'Default',
                'calledPartyInternationalPrefix': 'Default',
                'calledPartyUnknownPrefix': 'Default',
                'calledPartySubscriberPrefix': 'Default',
                'calledPartyNationalStripDigits': '',
                'calledPartyInternationalStripDigits': '',
                'calledPartyUnknownStripDigits': '',
                'calledPartySubscriberStripDigits': '',
                'calledPartyNationalTransformationCssName': '',
                'calledPartyInternationalTransformationCssName': '',
                'calledPartyUnknownTransformationCssName': '',
                'calledPartySubscriberTransformationCssName': '',
                'imeEnrolledPatternGroupName': '',
                'cntdPnTransformationCssName': '',
                'redirectingPartyTransformationCSS': '',
                'callingPartyTransformationCSS': ''
            }
            self.axl.add_update_device_pool(dp)
        return

    def create_ldap(self):
        """
        set up the LDAP configuration (LDAP sync, auth, etc.)
        :return: None
        """
        ldap_config = self.ldap
        if ldap_config is None:
            return

        # First create the feature group templates defined
        fgt_config = ldap_config.get('fgt', {})

        base_fgt = {
            'serviceProfile': '',
            'enableEMCC': 'false',
            'enableMobility': 'false',
            'enableMobileVoiceAccess': 'false',
            'maxDeskPickupWait': '10000',
            'remoteDestinationLimit': '4',
            'BLFPresenceGp': 'Standard Presence group',
            'subscribeCallingSearch': '',
            'userLocale': '',
            'userProfile': '',
            'meetingInformation': 'false'
        }
        for name, fgt_data in fgt_config.items():
            fgt = dict(base_fgt)
            fgt['name'] = name
            fgt.update(fgt_data)
            self.axl.add_update_fgt(fgt)

        # then we need to enable LDAP
        self.axl.updateLdapSystem(syncEnabled=True, ldapServer='Microsoft Active Directory',
                                  userIdAttribute='sAMAccountName')

        # create LDAP filters
        for filter_name, filter_expression in ldap_config['filter'].items():
            # insert filter expression into base expression
            filter_expression = '(&(objectclass=user)(!(objectclass=Computer))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)){expr})'.format(
                expr=filter_expression)
            filter = {
                'name': filter_name,
                'filter': filter_expression
            }
            self.axl.add_update_ldap_filter(filter=filter)
        # for

        auth_dn = ldap_config['dn']
        auth_password = ldap_config['ldap_password']
        servers = {'server': [{
            'hostName': s,
            'ldapPortNumber': 389,
            'sslEnabled': False}
            for s in ldap_config['ldap_server']]}
        for dir_name, dir_config in ldap_config['ldap_directory'].items():
            search_base = dir_config['search_base']
            filter = dir_config['filter']
            fgt = dir_config['fgt']
            access_control_groups = {'accessControlGroupName': [{'accessControlGroup': a} for a in
                                                                dir_config['accessControlGroup']]}

            # access_control_groups = [{'accessControlGroupName': {'accessControlGroup': a}} for a in dir_config['accessControlGroup']]
            next_exec = datetime.datetime.now() + datetime.timedelta(days=1)
            next_exec = next_exec.isoformat()[:10]
            next_exec = '{} 00:00'.format(next_exec)
            ldap_directory = {
                'name': dir_name,
                'ldapDn': auth_dn,
                'ldapPassword': auth_password,
                'userSearchBase': search_base,
                'repeatable': 'true',
                'intervalValue': '6',
                'scheduleUnit': 'HOUR',
                'nextExecTime': next_exec,
                'middleName': 'middleName',
                'phoneNumber': 'telephoneNumber',
                'mailId': 'mail',
                'ldapFilter': filter,
                'directoryUri': 'mail',
                'featureGroupTemplate': fgt,
                'applyPoolList': 'false',
                'servers': servers,
                'accessControlGroupInfo': access_control_groups
            }
            self.axl.add_update_ldap_directory(directory=ldap_directory)
            r = self.axl.getLdapDirectory(name=dir_name)

            # trigger sync
            self.axl.doLdapSync(name=dir_name, sync=True)
            r = self.axl.getLdapDirectory(name=dir_name)

        # for

        # enable LDAP Authentication
        r = self.axl.updateLdapAuthentication(authenticateEndUsers=True,
                                              distinguishedName=auth_dn,
                                              ldapPassword=auth_password,
                                              userSearchBase=ldap_config['authentication']['search_base'],
                                              servers=servers)
        return

    def create_gdpr(self):
        """
        GDPR configuration
        :return: None
        """
        gdpr_config = self.gdpr
        if gdpr_config is None:
            return

        route_string = gdpr_config['route_string']
        registration_server = gdpr_config['registration_server']
        if registration_server is None:
            registration_server = ''
        ils_password = gdpr_config['password']
        learned_partition = gdpr_config['learned_partition']
        update_interval_minutes = gdpr_config['update_interval_minutes']

        # set learned partitions for GDPR
        # run sql update remoteobjectpartitionrule set fkroutepartition=(select pkid from routepartition where name='onNetRemote')
        sql = 'update remoteobjectpartitionrule set fkroutepartition=(select pkid from routepartition where name=\'{partition}\')'.format(
            partition=learned_partition)
        r = self.axl.sql_update(sql=sql)

        # set E.164 urgency
        # run sql update remoteobjectpartitionrule set isurgentfixedlen='t' where tkglobalnumber=200
        sql = 'update remoteobjectpartitionrule set isurgentfixedlen=\'t\' where tkglobalnumber=200'
        r = self.axl.sql_update(sql=sql)

        # Activate GDPR
        r = self.axl.updateInterClusterDirectoryUri(exchangeDirectoryUri=True,
                                                    routeString=route_string)

        # activate ILS
        r = self.axl.updateIlsConfig(role='Hub Cluster',
                                     registrationServer=registration_server,
                                     activateIls=True,
                                     synchronizeClustersEvery=update_interval_minutes,
                                     activatedServers='',
                                     deactivatedServers='',
                                     useTls=False,
                                     usePassword=ils_password,
                                     enableUsePassword=True)

        # restart ILS service
        # tknodeusage: 0=publisher, 1=subscriber
        # tkprocessnoderole: 1=ucm, 2=imp
        ucm_pub = self.axl.sql_query(
            'select name from processnode where tknodeusage=0 and tkprocessnoderole=1')
        ucm_pub = ucm_pub[0]['name']
        r = self.control_center.soap_do_control_services(host=ucm_pub, node_name='', control_type='Restart',
                                                         service_name='Cisco Intercluster Lookup Service')

        return

    def create_imp(self):
        """
        Create the standard IM&P configuration
        :return:
        """
        if self.config.get('imp_publish_trunk') is None:
            return

        # SIP profile
        profile = {
            'name': 'IM and Presence',
            'description': 'For IM and Presence subcription trunk',
        }
        self.axl.add_update_sip_profile(sip_profile=profile)

        # SIP trunk security profile for subscription trunk
        sec_profile = {
            'name': 'IM and Presence',
            'description': 'Profile for IM and P subscription trunk',
            'acceptPresenceSubscription': 'true',
            'acceptOutOfDialogRefer': 'true',
            'acceptUnsolicitedNotification': 'true',
            'allowReplaceHeader': 'true'
        }
        self.axl.add_update_sip_trunk_security_profile(sec_profile)

        # create subscription trunk
        destinations = self.config['imp_publish_trunk']['destinations']

        destinations = {
            'destination': [{'addressIpv4': d, 'port': 5060, 'sortOrder': i} for i, d in
                            enumerate(destinations, start=1)]}
        sip_trunk = {
            'name': 'IMPSubscription',
            'description': 'IM and P subscription',
            'callingSearchSpaceName': 'ICTInbound',
            'devicePoolName': 'Default',
            'automatedAlternateRoutingCssName': 'AAR',
            'aarNeighborhoodName': 'Default',
            'securityProfileName': 'IM and Presence',
            'sipProfileName': 'IM and Presence',
            'destinations': destinations
        }
        r = self.axl.add_update_sip_trunk(trunk=sip_trunk)
        uuid = r[1:-1].lower()

        r = self.axl.do_device_reset(name='IMPSubscription', is_mgcp=False, is_hard_reset=False, reset_type='Reset')

        # set the IM and Presence Publish Trunk; service parameter needs to be set to lower case UUID w/o the brackets
        self.axl.update_service_parameter('EnterpriseWideData', 'SIPPublishTrunk', 'Cisco CallManager', uuid)
        return

    def create_sip_routing(self):
        """
        Create SIP routing as defined in the 'routing' section of the config file
        """
        routing_conf = self.routing
        if routing_conf is None:
            return
        for sip_trunk_name, sip_trunk_params in routing_conf['siptrunks'].items():
            # define a SIP profile for that trunk
            # define trunk

            # SIP trunk security profile
            sec_profile = {
                'name': sip_trunk_name,
                'description': 'Profile for trunk {}'.format(sip_trunk_name),
                'acceptPresenceSubscription': 'false',
                'transmitSecurityStatus': 'true',
                'incomingPort': sip_trunk_params['incomingPort']
            }
            self.axl.add_update_sip_trunk_security_profile(sec_profile)

            # create subscription trunk
            destinations = sip_trunk_params['destinations']

            destinations = {
                'destination': [{'addressIpv4': d, 'port': sip_trunk_params['incomingPort'], 'sortOrder': i} for i, d in
                                enumerate(destinations, start=1)]}
            sip_trunk = {
                'name': sip_trunk_name,
                'description': sip_trunk_params['description'],
                'callingSearchSpaceName': sip_trunk_params['incomingCss'],
                'devicePoolName': 'Default',
                'automatedAlternateRoutingCssName': 'AAR',
                'aarNeighborhoodName': 'Default',
                'securityProfileName': sip_trunk_name,
                'sipProfileName': sip_trunk_params['profile'],
                'destinations': destinations
            }
            r = self.axl.add_update_sip_trunk(trunk=sip_trunk)
            r = self.axl.do_device_reset(name=sip_trunk_name, is_mgcp=False, is_hard_reset=False, reset_type='Reset')

        # for

        # route groups
        for route_group_name, route_group_params in routing_conf['routegroups'].items():
            route_group = {
                'name': route_group_name,
                'distributionAlgorithm': 'Circular',
                'members': {
                    'member': [{'deviceSelectionOrder': i, 'deviceName': m, 'port': 0} for
                               i, m
                               in enumerate(route_group_params['members'], start=1)]
                }
            }
            r = self.axl.add_update_route_group(route_group=route_group)

        # route lists
        for route_list_name, route_list_params in routing_conf['routelists'].items():
            description = route_list_params.get('description')
            members = route_list_params.get('members') or []
            members = {
                'member': [
                    {
                        'routeGroupName': rg_name,
                        'selectionOrder': i
                    }
                    for i, rg_name in enumerate(members, start=1)
                ]
            }
            self.axl.add_update_route_list(name=route_list_name,
                                           description=description,
                                           callManagerGroupName='Default',
                                           #routeListEnabled='true',
                                           runOnEveryNode='true',
                                           members=members)
        # SIP routes
        for route, route_params in routing_conf.get('siproutes', dict()).items():
            destination = route_params['destination']
            description = route_params['description']
            partition = route_params['partition']
            pattern = {
                'pattern': route,
                'description': description,
                'routePartitionName': partition,
                'usage': 'Domain Routing',
                'blockEnable': False,
                'callingPartyTransformationMask': '',
                'useCallingPartyPhoneMask': 'Off',
                'callingPartyPrefixDigits': '',
                'callingLinePresentationBit': 'Default',
                'callingNamePresentationBit': 'Default',
                'connectedLinePresentationBit': 'Default',
                'connectedNamePresentationBit': 'Default',
                'sipTrunkName': destination
            }
            self.axl.add_update_sip_route_pattern(route_pattern=pattern)
        return

    def create_site_specific_self_provisioning_config(self, site):
        """
        For the given site:
        * create Universal Device Template {site}International
        * create Universal Line Template {site}International
        * create User Provisioning Profile {site}International
        * update all endusers with DNs in that site to use above User Provisioning Profile
        :param site: site code (SJC, RTP, ...)
        :return: None
        """
        site_info = self.config['dialplan']['sites'][site]
        dp_info = self.config['dialplan']['habits'][site_info['habit']]

        site_international = '{}International'.format(site)
        css_emergency = '{}emergency'.format(site_info['habit'])
        udt_name = '{} Template'.format(site)
        site_udt = {
            'name': udt_name,
            'deviceDescription': '#UserID# (#Product# #Protocol#)',
            'devicePool': '{}Phone'.format(site),
            'sipProfile': 'FQDN',
            'callingSearchSpace': css_emergency,
            'authenticationString': 12345,
            'aarCallingSearchSpace': 'AAR',
            'location': 'Hub_none'
        }
        self.axl.add_update_universal_device_template(site_udt)

        # determine AAR destination mask
        self.get_site_plus_e164(site)
        aar_mask = '+{}{}{}'.format(dp_info['CC'], site_info['NDC'], site_info['SN'])
        site_ult = {
            'name': site_international,
            'urgentPriority': True,
            'lineDescription': '#FirstName# #LastName#',
            'routePartition': 'DN',
            'callingSearchSpace': site_international,
            'alertingName': '#FirstName# #LastName#',
            'aarDestinationMask': aar_mask,
            'aarGroup': 'Default',
            'busyIntCallsCss': site_international,
            'busyExtCallsCss': site_international,
            'noAnsIntCallsCss': site_international,
            'noAnsExtCallsCss': site_international,
            'noCoverageIntCallsCss': site_international,
            'noCoverageExtCallsCss': site_international,
            'unregisteredIntCallsCss': 'AAR',
            'unregisteredExtCallsCss': 'AAR',
            'ctiFailureCss': site_international,
            'e164AltNum': {
                'member': {
                    'numberMask': aar_mask,
                    'addToLocalRoutePartition': False,
                    'advertiseGloballyIls': False
                }
            },

        }
        self.axl.add_update_universal_line_template(site_ult)

        # find numplan entry created for the ULT
        np_sql = 'select pkid from Numplan where dnorpattern=\'{}\''.format(site_international)
        np = self.axl.sql_query(np_sql)
        np_pkid = np[0]['pkid']

        # find +E.164 (200) alternaten number entry for that numplan entry; created by above thick AXL request
        an = self.axl.sql_query(
            'SELECT * FROM alternatenumber WHERE tkglobalnumber=200 and fknumplan=\'{np_pkid}\''.format(
                np_pkid=np_pkid))
        an_pkid = an[0]['pkid']

        # set AAR='t' in that entry
        update_sql = 'update alternatenumber set isaar=\'t\' where pkid=\'{}\''.format(an_pkid)
        r = self.axl.sql_update(update_sql)

        # Add site specific user provisioning profile
        upp = {
            'name': site_international,
            'description': 'User Profile for {}'.format(site),
            'deskPhones': udt_name,
            'mobileDevices': udt_name,
            'profile': '',
            'universalLineTemplate': site_international,
            'allowProvision': True,
            'limitProvision': 10,
            'defaultUserProfile': '',
            'enableMra': True,
            'mraPolicy_Desktop': 'IM & Presence, Voice and Video calls',
            'mraPolicy_Mobile': 'IM & Presence, Voice and Video calls'
        }
        r = self.axl.add_update_user_profile_provision(upp)
        pkid = r[1:-1].lower()

        # update all users
        # update enduser set fkucuserprofile='...' where telephonenumber like '+1919%'
        sql_phone_prefix = re.sub(r'X+', '%', aar_mask)
        sql = 'update enduser set fkucuserprofile=\'{}\' where telephonenumber like \'{}\''.format(pkid,
                                                                                                   sql_phone_prefix)
        r = self.axl.sql_update(sql)
        return

    def create_self_provisioning(self):
        """
        * Create site specific self provisioning config
        * set up auto registration etc.
        :return:
        """

        if False:
            for site in self.config['dialplan']['sites']:
                self.create_site_specific_self_provisioning_config(site)
        # for

        self_provisioning_info = self.config['selfprovisioning']
        # create auto-registration partition and CSS
        self.axl.add_update_route_partition(name=self_provisioning_info['partition'], description='Self provisioning')
        self.axl.add_update_css(name=self_provisioning_info['css'], description='Self provisioning',
                                clause=self_provisioning_info['partition'])

        # create device pool for auto-registered phones and CTI-RP
        dp = {
            'name': self_provisioning_info['device_pool'],
            'autoSearchSpaceName': self_provisioning_info['css'],
            # set site specific date/time group or default
            'dateTimeSettingName': 'CMLocal',
            'callManagerGroupName': 'Default',
            'mediaResourceListName': '',
            'regionName': 'Default',
            'networkLocale': '',
            'srstName': 'Disable',
            'connectionMonitorDuration': '-1',
            'automatedAlternateRoutingCssName': '',
            'aarNeighborhoodName': 'Default',
            'locationName': 'Hub_None',
            'mobilityCssName': '',
            'physicalLocationName': '',
            'deviceMobilityGroupName': '',
            'revertPriority': 'Default',
            'singleButtonBarge': 'Default',
            'joinAcrossLines': 'Default',
            'cgpnTransformationCssName': '',
            'geoLocationName': '',
            'geoLocationFilterName': '',
            'callingPartyNationalPrefix': 'Default',
            'callingPartyInternationalPrefix': 'Default',
            'callingPartyUnknownPrefix': 'Default',
            'callingPartySubscriberPrefix': 'Default',
            'adjunctCallingSearchSpace': '',
            'callingPartyNationalStripDigits': '',
            'callingPartyInternationalStripDigits': '',
            'callingPartyUnknownStripDigits': '',
            'callingPartySubscriberStripDigits': '',
            'callingPartyNationalTransformationCssName': '',
            'callingPartyInternationalTransformationCssName': '',
            'callingPartyUnknownTransformationCssName': '',
            'callingPartySubscriberTransformationCssName': '',
            'calledPartyNationalPrefix': 'Default',
            'calledPartyInternationalPrefix': 'Default',
            'calledPartyUnknownPrefix': 'Default',
            'calledPartySubscriberPrefix': 'Default',
            'calledPartyNationalStripDigits': '',
            'calledPartyInternationalStripDigits': '',
            'calledPartyUnknownStripDigits': '',
            'calledPartySubscriberStripDigits': '',
            'calledPartyNationalTransformationCssName': '',
            'calledPartyInternationalTransformationCssName': '',
            'calledPartyUnknownTransformationCssName': '',
            'calledPartySubscriberTransformationCssName': '',
            'imeEnrolledPatternGroupName': '',
            'cntdPnTransformationCssName': '',
            'redirectingPartyTransformationCSS': '',
            'callingPartyTransformationCSS': ''
        }
        self.axl.add_update_device_pool(dp)

        # create DN
        dn = {
            'pattern': self_provisioning_info['cti_rp_dn'],
            'routePartitionName': self_provisioning_info['partition'],
            'description': 'Self provisioning IVR',
            'usage': 'Device',
            'aarNeighborhoodName': 'Default',
            'aarDestinationMask': '',
            'aarKeepCallHistory': 'true',
            'aarVoiceMailEnabled': 'false',
            'autoAnswer': 'Auto Answer Off',
            'networkHoldMohAudioSourceId': '',
            'userHoldMohAudioSourceId': '',
            'alertingName': 'Self provisioning IVR',
            'asciiAlertingName': 'Self provisioning IVR',
            'presenceGroupName': 'Standard Presence group',
            'shareLineAppearanceCssName': self_provisioning_info['css'],
            'voiceMailProfileName': '',
            'patternPrecedence': 'Default',
            'releaseClause': 'No Error',
            'hrDuration': '',
            'hrInterval': '',
            'cfaCssPolicy': 'Use System Default',
            'defaultActivatedDeviceName': '',
            'parkMonForwardNoRetrieveDn': '',
            'parkMonForwardNoRetrieveIntDn': '',
            'parkMonForwardNoRetrieveVmEnabled': 'false',
            'parkMonForwardNoRetrieveIntVmEnabled': 'false',
            'parkMonForwardNoRetrieveCssName': '',
            'parkMonForwardNoRetrieveIntCssName': '',
            'parkMonReversionTimer': '',
            'partyEntranceTone': 'Default',
            'allowCtiControlFlag': 'true',
            'rejectAnonymousCall': 'false',
            'patternUrgency': 'true'
        }
        self.axl.add_update_line(dn)

        # create CTI RP
        cti_rp = {
            'name': self_provisioning_info['cti_rp_name'],
            'description': 'CTI RP for Self provisioning',
            'product': 'CTI Route Point',
            'class': 'CTI Route Point',
            'protocol': 'SCCP',
            'protocolSide': 'User',
            'callingSearchSpaceName': self_provisioning_info['css'],
            'devicePoolName': self_provisioning_info['device_pool'],
            'commonDeviceConfigName': '',
            'locationName': 'Hub_none',
            'mediaResourceListName': '',
            'networkHoldMohAudioSourceId': '',
            'userHoldMohAudioSourceId': '',
            'useTrustedRelayPoint': 'Default',
            'cgpnTransformationCssName': '',
            'useDevicePoolCgpnTransformCss': True,
            'geoLocationName': '',
            'userLocale': '',
            'lines': {
                'line': {
                    'index': 1,
                    'label': 'IVR',
                    'display': 'Self provisioning IVR',
                    'dirn': {
                        'pattern': self_provisioning_info['cti_rp_dn'],
                        'routePartitionName': self_provisioning_info['partition']},
                    'ringSetting': 'Ring',
                    'consecutiveRingSetting': 'Use System Default',
                    'ringSettingIdlePickupAlert': 'Use System Default',
                    'ringSettingActivePickupAlert': 'Use System Default',
                    'displayAscii': 'Self provisioning IVR',
                    'e164Mask': '',
                    'mwlPolicy': 'Use System Policy',
                    'maxNumCalls': 2,
                    'busyTrigger': 1,
                    'callInfoDisplay': {
                        'callerName': True,
                        'callerNumber': False,
                        'redirectedNumber': False,
                        'dialedNumber': True},
                    'recordingProfileName': '',
                    'monitoringCssName': '',
                    'recordingFlag': 'Call Recording Disabled',
                    'audibleMwi': 'Default',
                    'speedDial': '',
                    'partitionUsage': 'General',
                    'missedCallLogging': True,
                    'recordingMediaSource': 'Gateway Preferred'
                }
            }
        }
        self.axl.add_update_cti_rp(cti_rp)
        r = self.axl.do_device_reset(name=cti_rp['name'],
                                     is_mgcp=False,
                                     is_hard_reset=False,
                                     reset_type='Reset')

        # create application user, associate CTI-RP
        app_user = {
            'userid': self_provisioning_info['app_user'],
            'password': self_provisioning_info['app_user_password'],
            'acceptPresenceSubscription': False,
            'acceptOutOfDialogRefer': False,
            'acceptUnsolicitedNotification': False,
            'allowReplaceHeader': False,
            'associatedDevices': {
                'device': self_provisioning_info['cti_rp_name']},
            'associatedGroups': {
                'userGroup': {
                    'name': 'Standard CTI Enabled',
                }
            }
        }
        self.axl.add_update_app_user(app_user)

        # phone button template for auto-registration: 1 line, 1 SD
        pbt = {
            'name': self_provisioning_info['phone_button_template_name'],
            'basePhoneTemplateName': 'Universal Device Template Button Layout',
            'buttons': {
                'button':
                    {
                        'feature': 'Speed Dial',
                        'label': 'IVR',
                        'buttonNumber': '2'
                    }

            }
        }
        self.axl.add_update_phone_button_template(pbt)

        # create ULT/UDT for auto-registered phones
        site_udt = {
            'name': self_provisioning_info['udt_name'],
            'deviceDescription': 'Self provisioning (#Product# #Protocol#)',
            'devicePool': self_provisioning_info['device_pool'],
            'sipProfile': 'FQDN',
            'callingSearchSpace': self_provisioning_info['css'],
            'authenticationString': 12345,
            'aarCallingSearchSpace': '',
            'location': 'Hub_none',
            'phoneButtonTemplate': self_provisioning_info['phone_button_template_name'],
            'speeddials': {
                'speeddial': {
                    'dirn': self_provisioning_info['cti_rp_dn'],
                    'label': 'IVR',
                    'index': 1
                }
            }
        }
        self.axl.add_update_universal_device_template(site_udt)

        ult = {
            'name': self_provisioning_info['ult_name'],
            'urgentPriority': True,
            'lineDescription': 'auto-registered',
            'routePartition': self_provisioning_info['partition'],
            'callingSearchSpace': self_provisioning_info['css'],
            'alertingName': '',
            'aarDestinationMask': '',
            'aarGroup': 'Default',
            'busyIntCallsCss': '',
            'busyExtCallsCss': '',
            'noAnsIntCallsCss': '',
            'noAnsExtCallsCss': '',
            'noCoverageIntCallsCss': '',
            'noCoverageExtCallsCss': '',
            'unregisteredIntCallsCss': '',
            'unregisteredExtCallsCss': '',
            'ctiFailureCss': '',
            'e164AltNum': ''
        }
        self.axl.add_update_universal_line_template(ult)

        # set parameter on CM nodes
        r = self.axl.listCallManager(searchCriteria={'name': '%'}, returnedTags={'name': ''})
        r = r['return']['callManager']
        for cm in r:
            self.axl.updateCallManager(uuid=cm['uuid'],
                                       autoRegistration={
                                           'startDn': 1000,
                                           'endDn': 2000,
                                           'routePartitionName': self_provisioning_info['partition'],
                                           'autoRegistrationEnabled': True,
                                           'universalDeviceTemplate': self_provisioning_info['udt_name'],
                                           'lineTemplate': self_provisioning_info['ult_name']})

        # set self provisioning parameters
        self.axl.updateSelfProvisioning(requireAuthentication='0',
                                        ctiRoutePoint=self_provisioning_info['cti_rp_name'],
                                        applicationUser=self_provisioning_info['app_user'])

        # restart IVR service
        # tknodeusage: 0=publisher, 1=subscriber
        # tkprocessnoderole: 1=ucm, 2=imp
        ucm_pub = self.axl.sql_query(
            'select name from processnode where tknodeusage=0 and tkprocessnoderole=1')
        ucm_pub = ucm_pub[0]['name']
        r = self.control_center.soap_do_control_services(host=ucm_pub, node_name='', control_type='Restart',
                                                         service_name='Self Provisioning IVR')
        return

    def provision_dn_for_user(self, user, user_site):
        alerting = '{} {}'.format(user['firstname'], user['lastname'])
        fwd_css_international = {
            'forwardToVoiceMail': 'false',
            'callingSearchSpaceName': '{}International'.format(user_site),
            'destination': ''}
        dn = {
            'pattern': '\\' + user['telephonenumber'],
            'routePartitionName': 'DN',
            'description': user['userid'],
            'usage': 'Device',
            'aarNeighborhoodName': 'Default',
            'aarDestinationMask': user['telephonenumber'],
            'aarKeepCallHistory': 'true',
            'aarVoiceMailEnabled': 'false',
            'callForwardAll': fwd_css_international,
            'callForwardBusy': fwd_css_international,
            'callForwardBusyInt': fwd_css_international,
            'callForwardNoAnswer': fwd_css_international,
            'callForwardNoAnswerInt': fwd_css_international,
            'callForwardNoCoverage': fwd_css_international,
            'callForwardNoCoverageInt': fwd_css_international,
            'callForwardOnFailure': fwd_css_international,
            'callForwardAlternateParty': {
                'callingSearchSpaceName': '{}International'.format(user_site),
                'destination': ''},
            'callForwardNotRegistered': {
                'forwardToVoiceMail': 'false',
                'callingSearchSpaceName': 'AAR',
                'destination': user['telephonenumber']},
            'callForwardNotRegisteredInt': {
                'forwardToVoiceMail': 'false',
                'callingSearchSpaceName': 'AAR',
                'destination': user['telephonenumber']},
            'autoAnswer': 'Auto Answer Off',
            'networkHoldMohAudioSourceId': '',
            'userHoldMohAudioSourceId': '',
            'alertingName': alerting,
            'asciiAlertingName': alerting,
            'presenceGroupName': 'Standard Presence group',
            'shareLineAppearanceCssName': '{}International'.format(user_site),
            'voiceMailProfileName': '',
            'patternPrecedence': 'Default',
            'releaseClause': 'No Error',
            'hrDuration': '',
            'hrInterval': '',
            'cfaCssPolicy': 'Use System Default',
            'defaultActivatedDeviceName': '',
            'parkMonForwardNoRetrieveDn': '',
            'parkMonForwardNoRetrieveIntDn': '',
            'parkMonForwardNoRetrieveVmEnabled': 'false',
            'parkMonForwardNoRetrieveIntVmEnabled': 'false',
            'parkMonForwardNoRetrieveCssName': '',
            'parkMonForwardNoRetrieveIntCssName': '',
            'parkMonReversionTimer': '',
            'partyEntranceTone': 'Default',
            'allowCtiControlFlag': 'true',
            'rejectAnonymousCall': 'false',
            'patternUrgency': 'true'
        }
        self.axl.add_update_line(dn)

        # add +E.164 alternate number as PSTN failover
        dn = {
            'pattern': '\\' + user['telephonenumber'],
            'routePartitionName': 'DN',
            'description': user['userid'],
            'e164AltNum': {
                'numMask': '',
                'addLocalRoutePartition': 'false',
                'advertiseGloballyIls': 'false'
            },
            'pstnFailover': 200,
            'useE164AltNum': 'true'
        }
        self.axl.updateLine(**dn)
        return

    def deploy_csf(self, user, user_site):
        """

        :param user: dictionary with user information
        :param user_site: 3 character site code of the site the device should be added for
        :return: None
        """
        user_id = user['userid']
        name = 'CSF{}'.format(user_id.upper())
        description = 'CSF for {}'.format(user_id.upper())
        dp = '{}Phone'.format(user_site)
        pattern = '\\{}'.format(user['telephonenumber'])
        alerting = '{} {}'.format(user['firstname'], user['lastname'])
        emergency_css = '{}Emergency'.format(self.config['dialplan']['sites'][user_site]['habit'])

        csf = {
            'name': name,
            'description': description,
            'product': 'Cisco Unified Client Services Framework',
            'class': 'Phone',
            'protocol': 'SIP',
            'protocolSide': 'User',
            'callingSearchSpaceName': emergency_css,
            'devicePoolName': dp,
            'commonPhoneConfigName': 'Standard Common Phone Profile',
            'locationName': 'Hub_None',
            'automatedAlternateRoutingCssName': 'AAR',
            'aarNeighborhoodName': 'Default',
            'securityProfileName': 'Cisco Unified Client Services Framework - Standard SIP Non-Secure Profile',
            'sipProfileName': 'FQDN',
            'useDevicePoolCgpnTransformCss': 'true',
            'lines': {
                'line': {
                    'index': 1,
                    'label': pattern[-4:],
                    'display': alerting,
                    'dirn': {'pattern': pattern,
                             'routePartitionName': 'DN'
                             },
                    'displayAscii': alerting,
                    'e164Mask': pattern[1:],
                    'associatedEndusers': {
                        'enduser': {
                            'userId': user_id
                        }
                    },

                    'missedCallLogging': 'true',
                    'recordingMediaSource': 'Gateway Preferred'
                }
            },
            'phoneTemplateName': 'Standard Client Services Framework',
            'primaryPhoneName': '',
            'builtInBridgeStatus': 'Default',
            'ownerUserName': user_id,
            'packetCaptureMode': 'None',
            'subscribeCallingSearchSpaceName': '',
            'allowCtiControlFlag': 'true',
            'presenceGroupName': 'Standard Presence group',
            # Enable device mobiliyt to make sure that we can have CAC for devices registered through expressway
            'deviceMobilityMode': 'On',
            'useDevicePoolCgpnIngressDN': 'true'
        }
        r = self.axl.add_update_phone(csf)

        # Apply config
        r = self.axl.do_device_reset(name=name, is_mgcp=False, is_hard_reset=False, reset_type='Reset')

        # find all devices associated with that DN
        r = self.axl.getLine(pattern=pattern, routePartitionName='DN')

        # uuid in thick AXL is uppercase and as curly brackets at the start/end
        dn_uuid = r['return']['line']['uuid']
        dn_uuid = dn_uuid[1:-1].lower()
        devices = self.axl.sql_query(
            ('select device.pkid, device.name as dname,device.description,typeproduct.name as tname from '
             'device, devicenumplanmap,typeproduct where devicenumplanmap.fknumplan=\'{dn_uuid}\' and '
             'devicenumplanmap.fkdevice=device.pkid and typeproduct.enum=device.tkproduct').format(dn_uuid=dn_uuid))

        # associated devices
        ass_devices = [{'device': d['dname'] for d in devices}]
        if len(ass_devices) == 1:
            ass_devices = ass_devices[0]

        # line appearances for presence
        laap = [
            {
                'laapAssociate': 't',
                'laapDeviceName': d['dname'],
                'laapProductType': d['tname'],
                'laapDirectory': pattern,
                'laapPartition': 'DN'
            }
            for d in devices
        ]
        if len(laap) == 1:
            laap = laap[0]
        laap = {'lineAppearanceAssociationForPresence': laap}

        # associate these devices with the user and set primary extension
        user_update = {
            'userid': user_id,
            'primaryExtension': {
                'pattern': pattern,
                'routePartitionName': 'DN'
            },
            'associatedDevices': ass_devices,
            'lineAppearanceAssociationForPresences': laap
        }
        try:
            self.axl.updateUser(**user_update)
        except Exception as e:
            logging.error(f'Setting line appearance for presence for {user["userid"]} failed ({e}). Possibly issue with double DN?')
        return

    def create_dns_and_csfs(self):
        """
        For each user in any site create a DN and a CSF device
        :return: None
        """

        # get all active local users
        users = self.axl.sql_query(
            ('select pkid, userid, mailid, firstname, lastname, telephonenumber, status, islocaluser from enduser '
             'where status=1 and islocaluser'))

        # ignore users where we don't have a telephone number
        users = [u for u in users if u['telephonenumber'] is not None]

        # prepare a list of compiled regular expressions matching on the DN ranges of all sites
        site_e164 = []
        dp = self.dialplan
        for site, site_info in dp['sites'].items():
            e164 = self.get_site_plus_e164(site)
            e164 = '\{}'.format(e164.replace('X', '\d'))
            e164 = re.compile(e164)
            site_e164.append((site, e164))

        for user in users:
            # determine the user's site based on match of phone number
            user_site = next((site for site, e164 in site_e164 if e164.match(user['telephonenumber'])), None)
            if user_site is None:
                print('No site found for user {}'.format(user['userid']))
                continue

            self.provision_dn_for_user(user, user_site)
            self.deploy_csf(user, user_site)
        # for
        return

    def update_all_users(self):
        """
        Fix group member ships for all users
        :return: None
        """
        r = self.axl.sql_query('select pkid,userid from enduser')
        new_groups = ['Standard CTI Enabled', 'Standard CCM End Users',
                      'Standard CTI Allow Control of Phones supporting Connected Xfer and conf',
                      'Standard CTI Allow Control of Phones supporting Rollover Mode']
        user_ids = (user['pkid'] for user in r if not user['userid'].startswith('Token'))
        # we need uppercase PKIDs in curly brackets
        user_ids = ('{{{pkid}}}'.format(pkid=id.upper()) for id in user_ids)
        updated_users = 0
        for user_id in user_ids:
            # user = self.axl.getUser(uuid=user_id, returnedTags={'associatedGroups': {'userGroup': {'name': ''}}})

            user = self.axl.getUser(uuid=user_id,
                                    returnedTags={'userid': '', 'associatedGroups': {'userGroup': {'name': ''}}})
            ass_groups = [g['name'] for g in user['return']['user']['associatedGroups']['userGroup']]
            groups_to_add = [g for g in new_groups if g not in ass_groups]
            if not groups_to_add:
                continue
            ass_groups.extend((g for g in groups_to_add))
            new_ass_groups = {'userGroup': [{'name': g} for g in ass_groups]}
            self.axl.updateUser(uuid=user_id, associatedGroups=new_ass_groups)
            updated_users += 1
        print('{} users updated'.format(updated_users))
        return

    def set_pin_for_all_users(self):
        r = self.axl.sql_query('select pkid,userid from enduser where islocaluser=\'t\'')
        user_ids = (user['pkid'] for user in r if not user['userid'].startswith('Token'))
        user_ids = ('{{{pkid}}}'.format(pkid=id.upper()) for id in user_ids)
        updated_users = 0
        for user_id in user_ids:
            self.axl.updateUser(uuid=user_id, pin='12345')
            updated_users += 1
        print('{} users updated'.format(updated_users))
        return


def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'INFO',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })

    for config_selector in ['example']:
        config_file_name = 'config_{}.yml'.format(config_selector)
        with open(config_file_name, 'r') as f:
            config = yaml.load(f)

        configurator = UCMConfigurator(config)

        # configurator.set_cluster_id()
        # configurator.set_process_node_names()
        # configurator.set_enterprise_parameters()
        # configurator.deploy_services()
        # configurator.set_service_parameter()
        # configurator.create_ldap()
        # configurator.create_base_dialplan()
        # configurator.create_dial_plan()
        # configurator.create_gdpr()
        # configurator.create_imp()
        # configurator.create_sip_routing()
        configurator.create_dns_and_csfs()
        # configurator.create_self_provisioning()
        configurator.set_pin_for_all_users()

if __name__ == '__main__':
    main()
