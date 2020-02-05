"""
AXL helper to wrap SOAP methods created based on the UCM AXL WSDL
"""
import zeep
import zeep.cache
import zeep.helpers
import zeep.exceptions
from zeep.plugins import HistoryPlugin
import requests
import tempfile
import os
from collections import OrderedDict
import re
import tempfile
import zipfile
import logging

log = logging.getLogger(__name__)

class AXLHelper:
    def __init__(self, ucm_host, auth, version=None, verify=None, timeout=60):
        """

        :param ucm_host: IP/FQDN of host to direct AXL requests to, optional with port spec
        :param auth: passed to requests.Session object. For basic authentication simply pass a (user/password) tuple
        :param version: String of WSDL version to use. For example: '12.0'
        :param verify: set to False to disable SSL key validation
        :param timeout: zeep timeout
        """
        self.ucm_host = ucm_host
        if not ':' in ucm_host:
            ucm_host += ':8443'
        self.axl_url = 'https://{ucm_host}/axl/'.format(ucm_host=ucm_host)

        self.session = requests.Session()
        self.session.auth = auth
        if verify is not None:
            self.session.verify = verify

        version = version or self._get_version()

        wsdl_version = version

        self.wsdl = os.path.join(os.path.dirname(__file__), 'WSDL', wsdl_version, 'AXLAPI.wsdl')
        temp_dir = None
        if not os.path.isfile(self.wsdl):
            log.debug(f'__init__: WSDL not found: {self.wsdl}')
            # we need to download the wsdl from UCM
            temp_dir = tempfile.TemporaryDirectory()
            temp_zip_file_name = os.path.join(temp_dir.name, 'axlsqltoolkit.zip')
            r = self.session.get(f'https://{self.ucm_host}/plugins/axlsqltoolkit.zip')
            with open(temp_zip_file_name, 'wb') as f:
                f.write(r.content)
            log.debug(f'__init__: downloaded {temp_zip_file_name}')
            with zipfile.ZipFile(temp_zip_file_name, 'r') as zip:
                zip.extractall(path=temp_dir.name)
            log.debug(f'__init__: extracted {temp_zip_file_name}')
            self.wsdl = os.path.join(temp_dir.name, 'schema', 'current', 'AXLAPI.wsdl')
            log.debug(f'__init__: using {self.wsdl}')
        self.cache = zeep.cache.SqliteCache(
            path=os.path.join(tempfile.gettempdir(), 'sqlite_{}.db'.format(self.ucm_host)),
            timeout=60)
        self.history = HistoryPlugin()
        self.client = zeep.Client(wsdl=self.wsdl,
                                  transport=zeep.Transport(timeout=timeout,
                                                           operation_timeout=timeout,
                                                           cache=self.cache,
                                                           session=self.session),
                                  plugins=[self.history])

        self.service = self.client.create_service('{http://www.cisco.com/AXLAPIService/}AXLAPIBinding',
                                                  self.axl_url)
        if temp_dir:
            # remove temporary WSDL directory and temp files
            log.debug(f'__init__: cleaning up temp dir {temp_dir.name}')
            temp_dir.cleanup()
        return

    def _get_version(self):
        """
        Get UCM version w/o using zeep.
        Used to determine UCM version if no version is given on initialization
        :return: UCM version
        """
        # try for a number of UCM versions
        for major_version in [12, 11, 10, 14, 9, 8]:
            soap_envelope = (f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                             f'xmlns:ns="http://www.cisco.com/AXL/API/{major_version}.0"><soapenv:Header/>'
                             f'<soapenv:Body><ns:getCCMVersion></ns:getCCMVersion></soapenv:Body></soapenv:Envelope>')
            headers = {'Content-Type': 'text/xml',
                       'SOAPAction': f'CUCM:DB ver={major_version}.0 getCCMVersion'}
            r = self.session.post(self.axl_url, data=soap_envelope, headers=headers)
            if r.status_code == 599:
                continue
            r.raise_for_status()
            log.debug(f'_get_version: reply from UCM: {r.text}')
            m = re.search(r'<version>(\d+)\.(\d+)\..+</version>', r.text)
            version = f'{m.group(1)}.{m.group(2)}'
            log.debug(f'_get_version: assuming version {version}')
            return version
        return ''

    def __getattr__(self, item):
        """
        unknown attributes are mapped to attributes of the zeep session.
        :param item:
        :return:
        """
        return self.service[item]

    def sql_query(self, query):
        """
        execute an SQL query
        :param query: SQL query
        :return: list of dict; each dict representing one record
        """
        r = self.service.executeSQLQuery(sql=query)

        if r['return'] is None:
            return []

        return [OrderedDict(((t.tag, t.text) for t in row)) for row in r['return']['row']]

    def sql_update(self, sql):
        """
        Execute an SQL update
        :param sql:  SQL statement
        :return: number of updated rows
        """
        r = self.service.executeSQLUpdate(sql=sql)
        return r['return']['rowsUpdated']

    def do_device_reset(self, name, is_mgcp=False, is_hard_reset=False, reset_type='Reset'):
        """
        Reset a device
        :param name: device name
        :param is_mgcp:
        :param is_hard_reset:
        :param reset_type: 'Reset', 'Restart', 'Apply Configuration'
        :return:
        """
        return self.service.doDeviceReset(isMGCP=is_mgcp, deviceName=name, isHardReset=is_hard_reset,
                                          deviceResetType=reset_type)

    @staticmethod
    def filter_search_criteria(search_criteria, supported_search_criteria, default_search_criteria=None):
        search_criteria = {k: v for k, v in search_criteria.items() if k in supported_search_criteria}
        if not search_criteria:
            if default_search_criteria is None:
                return None
            search_criteria[default_search_criteria] = '%'
        return search_criteria

    @staticmethod
    def handle_list_response(r):
        if r['return'] is None:
            return []
        r = r['return'][next((r for r in r['return']))]
        return [zeep.helpers.serialize_object(s) for s in r]

    ################ service parameter
    def get_service_parameter(self, process_node_name, name, service):
        tags = ['name', 'service', 'value', 'valueType', 'processNodeName']
        r = self.service.getServiceParameter(processNodeName=process_node_name,
                                             name=name,
                                             service=service,
                                             returnedTags={t: '' for t in tags})
        return r['return']['serviceParameter']

    def get_enterprise_parameter(self, name):
        return self.get_service_parameter(process_node_name='EnterpriseWideData',
                                          service='Enterprise Wide',
                                          name=name)

    def update_service_parameter(self, process_node_name, name, service, value):
        r = self.service.updateServiceParameter(processNodeName=process_node_name,
                                                name=name,
                                                service=service,
                                                value=value)
        return r['return']

    def update_enterprise_parameter(self, name, value):
        return self.update_service_parameter(process_node_name='EnterpriseWideData',
                                             service='Enterprise Wide',
                                             name=name,
                                             value=value)

    def list_service_parameter(self, **search_criteria):
        """

        :param search_criteria: supported search criteria: processNodeName, service
        :return: list of service parameters
        """
        search_criteria = self.filter_search_criteria(search_criteria, ['processNodeName', 'service'],
                                                      'processNodeName')

        tags = ['processNodeName', 'name', 'service', 'value', 'valueType']
        r = self.service.listServiceParameter(searchCriteria=search_criteria, returnedTags={t: '' for t in tags})
        return self.handle_list_response(r)

    def list_css(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['description', 'partitionUsage', 'name'],
                                                      'name')
        tags = ['description', 'clause', 'dialPlanWizardGenId', 'partitionUsage', 'name']
        r = self.service.listCss(searchCriteria=search_criteria, returnedTags={t: '' for t in tags})
        return self.handle_list_response(r)

    ############### process nodes
    def list_process_node(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['name', 'description', 'processNodeRole'],
                                                      'name')
        # tags = ['name', 'description', 'ipv6Name', 'nodeUsage', 'lbmHubGroup', 'processNodeRole']
        # requesting processNodeRole fails as zeep fails to parse this part of thre response:
        #    <processNodeRole>CUCM Voice/Video</processNodeRole>
        tags = ['name', 'description', 'mac', 'ipv6Name', 'nodeUsage', 'lbmHubGroup']
        r = self.service.listProcessNode(search_criteria, returnedTags={t: '' for t in tags})
        return self.handle_list_response(r)

    def update_process_node(self, name=None, uuid=None, new_name=None):
        assert new_name is not None
        if name is not None:
            assert uuid is None
            key, value = 'name', name
        else:
            assert uuid is not None
            # UUIDs obtained via thick AXL are uppercase and embedded in curly brackets
            key, value = 'pkid', uuid[1:-1].lower()

        # we do a direct update via SQL. For some reason the thick AXL method did not work?
        # update ProcessNode set Name='emea-imp-pub.tmevalidate.com' where pkid='5f9a6a63-9fd0-49c0-8fd4-99de7894e975'
        sql = 'update processnode set name=\'{new_name}\' where {key}=\'{value}\''.format(new_name=new_name, key=key,
                                                                                          value=value)
        r = self.sql_update(sql=sql)
        return r

    ############### user
    def list_user(self, returnedTags=None, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria,
                                                      ['firstName', 'lastName', 'userid', 'department'],
                                                      'userid')

        returnedTags = returnedTags or {'uuid': '', 'userid': '', 'firstName': '', 'lastName': ''}
        r = self.service.listUser(searchCriteria=search_criteria, returnedTags=returnedTags)
        return self.handle_list_response(r)

    ############### CSS
    def add_update_css(self, name, description, clause):
        member_list = [
            {'routePartitionName': p,
             'index': i
             }
            for i, p in enumerate(clause.split(':'), start=1)]
        css = {
            'name': name,
            'description': description,
            'members': {'member': member_list}
        }
        try:
            p = self.service.getCss(name=name,
                                    returnedTags={'description': '', 'clause': ''})
        except zeep.exceptions.Fault as e:
            p = self.service.addCss(css=css)
        else:
            p = self.service.updateCss(name=name,
                                       description=description,
                                       members={'member': member_list})

        return p['return']

    ############### route partition
    def list_route_partition(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['name', 'description'], 'name')
        tags = ['name', 'description', 'dialPlanWizardGenId', 'timeScheduleIdName', 'useOriginatingDeviceTimeZone',
                'timeZone', 'partitionUsage']
        r = self.service.listRoutePartition(searchCriteria=search_criteria, returnedTags={t: '' for t in tags})
        return self.handle_list_response(r)

    def get_route_partition(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['name', 'uuid'], 'name')
        assert search_criteria is not None, 'Search criteria mantatory'
        assert len(search_criteria) == 1, 'Only name or uuid can be used'

        tags = ['name', 'description', 'dialPlanWizardGenId', 'timeScheduleIdName', 'useOriginatingDeviceTimeZone',
                'timeZone', 'partitionUsage']
        try:
            r = self.service.getRoutePartition(returnedTags={t: '' for t in tags}, **search_criteria)
        except zeep.exceptions.Fault as e:
            if e.message.startswith('Item not valid'):
                return None
            raise
        r = zeep.helpers.serialize_object(r['return']['routePartition'])
        return r

    def add_route_partition(self, **values):
        r = self.service.addRoutePartition(routePartition=values)
        return r['return']

    def update_route_partition(self, **values):
        r = self.service.updateRoutePartition(**values)
        return r['return']

    def add_update_route_partition(self, name, description):
        p = self.get_route_partition(name=name)
        if p is None:
            # create
            p = self.add_route_partition(name=name, description=description)
        else:
            # update
            p = self.update_route_partition(name=name, description=description)
        return p

    ################ route list
    def get_route_list(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['name', 'uuid'], 'name')
        assert search_criteria is not None, 'Search criteria mantatory'
        assert len(search_criteria) == 1, 'Only name or uuid can be used'

        tags = ['name', 'description', 'callManagerGroupName', 'routeListEnabled']
        try:
            r = self.service.getRouteList(returnedTags={t: '' for t in tags}, **search_criteria)
        except zeep.exceptions.Fault as e:
            if e.message.startswith('Item not valid'):
                return None
            raise
        r = zeep.helpers.serialize_object(r['return']['routeList'])
        return r

    def add_update_route_list(self, **values):
        try:
            r = self.service.getRouteList(name=values['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addRouteList(routeList=values)
        else:
            r = self.service.updateRouteList(**values)
        return r['return']

    ################ route pattern
    ROUTE_PATTERN_TAGS = ['pattern', 'description', 'usage', 'routePartitionName', 'blockEnable',
                          'calledPartyTransformationMask',
                          'callingPartyTransformationMask', 'useCallingPartyPhoneMask', 'callingPartyPrefixDigits',
                          'dialPlanName', 'dialPlanWizardGenId', 'digitDiscardInstructionName', 'networkLocation',
                          'patternUrgency', 'prefixDigitsOut', 'routeFilterName', 'callingLinePresentationBit',
                          'callingNamePresentationBit', 'connectedLinePresentationBit', 'connectedNamePresentationBit',
                          'supportOverlapSending', 'patternPrecedence', 'releaseClause', 'allowDeviceOverride',
                          'provideOutsideDialtone', 'callingPartyNumberingPlan', 'callingPartyNumberType',
                          'calledPartyNumberingPlan', 'calledPartyNumberType', 'authorizationCodeRequired',
                          'authorizationLevelRequired', 'clientCodeRequired', 'withTag', 'withValueClause',
                          'resourcePriorityNamespaceName', 'routeClass', 'externalCallControl']

    def list_route_pattern(self, returned_tags=None, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['pattern', 'description', 'routePartitionName'],
                                                      'pattern')
        returned_tags = returned_tags or self.ROUTE_PATTERN_TAGS

        r = self.service.listRoutePattern(searchCriteria=search_criteria,
                                          returnedTags={t: '' for t in returned_tags})
        return self.handle_list_response(r)

    def get_route_pattern(self, returned_tags=None, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria, ['uuid', 'pattern', 'routePartitionName'])
        assert search_criteria is not None, 'Search criteria mantatory'

        returned_tags = returned_tags or self.ROUTE_PATTERN_TAGS

        try:
            r = self.service.getRoutePattern(returnedTags={t: '' for t in returned_tags}, **search_criteria)
        except zeep.exceptions.Fault as e:
            if e.message.startswith('Item not valid'):
                return None
            raise
        r = zeep.helpers.serialize_object(r['return']['routePattern'])
        return r

    def add_route_pattern(self, **values):
        # values = self.filter_search_criteria(values, self.ROUTE_PATTERN_TAGS)
        r = self.service.addRoutePattern(routePattern=values)
        return r['return']

    def update_route_pattern(self, **values):
        r = self.service.updateRoutePattern(**values)
        return r['return']

    def add_update_route_pattern(self, pattern, partition, description, route_list_name):
        route_pattern = {
            'pattern': pattern,
            'routePartitionName': partition,
            'description': description,
            'blockEnable': False,
            'calledPartyTransformationMask': '',
            'callingPartyTransformationMask': '',
            'useCallingPartyPhoneMask': 'Off',
            'callingPartyPrefixDigits': '',
            'digitDiscardInstructionName': '',
            'patternUrgency': False,
            'prefixDigitsOut': '',
            'routeFilterName': '',
            'supportOverlapSending': False,
            'patternPrecedence': 'Default',
            'provideOutsideDialtone': True,
            'authorizationCodeRequired': False,
            'authorizationLevelRequired': '0',
            'externalCallControl': '',
            'destination': {'routeListName': route_list_name}
        }
        p = self.get_route_pattern(pattern=pattern, routePartitionName=partition)
        if p is None:
            # create
            p = self.add_route_pattern(**route_pattern)
        else:
            p = self.update_route_pattern(**route_pattern)
        return p

    def remove_route_pattern(self, uuid):
        r = self.service.removeRoutePattern(uuid=uuid)
        return r

    ######### called party transforms
    CDPTX_TAGS = ['pattern', 'description', 'usage', 'routePartitionName', 'calledPartyTransformationMask',
                  'dialPlanName', 'digitDiscardInstructionName', 'patternUrgency', 'routeFilterName',
                  'calledPartyPrefixDigits', 'calledPartyNumberingPlan', 'calledPartyNumberType',
                  'mlppPreemptionDisabled']

    def list_called_party_transformation_pattern(self, **search_criteria):
        search_criteria = self.filter_search_criteria(search_criteria,
                                                      ['pattern', 'description', 'routePartitionName', 'dialPlanName',
                                                       'routeFilterName'],
                                                      'pattern')
        r = self.service.listCalledPartyTransformationPattern(searchCriteria=search_criteria,
                                                              returnedTags={t: '' for t in self.CDPTX_TAGS})
        return self.handle_list_response(r)

    def add_called_party_transformation_pattern(self, **values):
        r = self.service.addCalledPartyTransformationPattern(calledPartyTransformationPattern=values)
        return r['return']

    def remove_called_party_transformation_pattern(self, uuid):
        r = self.service.removeCalledPartyTransformationPattern(uuid=uuid)
        return r

    ######### SIP profile
    SIP_PROFILE_TAGS = ['name', 'description']

    def get_sip_profile(self, name):
        try:
            r = self.service.getSipProfile(returnedTags={t: '' for t in self.SIP_PROFILE_TAGS},
                                           name=name)
        except zeep.exceptions.Fault as e:
            if e.message.startswith('Item not valid'):
                return None
            raise
        r = zeep.helpers.serialize_object(r['return']['sipProfile'])
        return r

    def add_sip_profile(self, sip_profile):
        # values = self.filter_search_criteria(values, self.ROUTE_PATTERN_TAGS)
        r = self.service.addSipProfile(sipProfile=sip_profile)
        return r['return']

    def update_sip_profile(self, **values):
        r = self.service.updateSipProfile(**values)
        return r['return']

    def add_update_sip_profile(self, sip_profile):
        standard_sip_profile = {
            'defaultTelephonyEventPayloadType': '101',
            'redirectByApplication': False,
            'ringing180': False,
            'timerInvite': '180',
            'timerRegisterDelta': '5',
            'timerRegister': '3600',
            'timerT1': '500',
            'timerT2': '4000',
            'retryInvite': '6',
            'retryNotInvite': '10',
            'startMediaPort': '16384',
            'stopMediaPort': '32766',
            'startVideoPort': '0',
            'stopVideoPort': '0',
            'dscpForAudioCalls': '',
            'dscpForVideoCalls': '',
            'dscpForAudioPortionOfVideoCalls': '',
            'dscpForTelePresenceCalls': '',
            'dscpForAudioPortionOfTelePresenceCalls': '',
            'callpickupListUri': 'x-cisco-serviceuri-opickup',
            'callpickupGroupUri': 'x-cisco-serviceuri-gpickup',
            'meetmeServiceUrl': 'x-cisco-serviceuri-meetme',
            'userInfo': 'None',
            'dtmfDbLevel': 'Nominal',
            'callHoldRingback': 'Off',
            'anonymousCallBlock': 'Off',
            'callerIdBlock': 'Off',
            'dndControl': 'User',
            'telnetLevel': 'Disabled',
            'timerKeepAlive': '120',
            'timerSubscribe': '120',
            'timerSubscribeDelta': '5',
            'maxRedirects': '70',
            'timerOffHookToFirstDigit': '15000',
            'callForwardUri': 'x-cisco-serviceuri-cfwdall',
            'abbreviatedDialUri': 'x-cisco-serviceuri-abbrdial',
            'confJointEnable': True,
            'rfc2543Hold': False,
            'semiAttendedTransfer': True,
            'enableVad': False,
            'stutterMsgWaiting': False,
            'callStats': False,
            't38Invite': False,
            'faxInvite': False,
            'rerouteIncomingRequest': 'Never',
            'resourcePriorityNamespaceListName': '',
            'enableAnatForEarlyOfferCalls': False,
            'rsvpOverSip': 'Local RSVP',
            'fallbackToLocalRsvp': True,
            'sipRe11XxEnabled': 'Disabled',
            'gClear': 'Disabled',
            'sendRecvSDPInMidCallInvite': False,
            'enableOutboundOptionsPing': False,
            'optionsPingIntervalWhenStatusOK': '60',
            'optionsPingIntervalWhenStatusNotOK': '120',
            'deliverConferenceBridgeIdentifier': False,
            'sipOptionsRetryCount': '6',
            'sipOptionsRetryTimer': '500',
            'sipBandwidthModifier': 'TIAS and AS',
            'enableUriOutdialSupport': 'f',
            'userAgentServerHeaderInfo': 'Send Unified CM Version Information as User-Agent Header',
            'allowPresentationSharingUsingBfcp': False,
            'scriptParameters': '',
            'isScriptTraceEnabled': False,
            'sipNormalizationScript': '',
            'allowiXApplicationMedia': False,
            'dialStringInterpretation': 'Phone number consists of characters 0-9, *, #, and + (others treated as URI '
                                        'addresses)',
            'acceptAudioCodecPreferences': 'Default',
            'mlppUserAuthorization': False,
            'isAssuredSipServiceEnabled': False,
            'enableExternalQoS': False,
            'resourcePriorityNamespace': '',
            'useCallerIdCallerNameinUriOutgoingRequest': False,
            'callerIdDn': '',
            'callerName': '',
            'callingLineIdentification': 'Default',
            'rejectAnonymousIncomingCall': False,
            'callpickupUri': 'x-cisco-serviceuri-pickup',
            'rejectAnonymousOutgoingCall': False,
            'videoCallTrafficClass': 'Mixed',
            'sdpTransparency': '',
            'allowMultipleCodecs': False,
            'sipSessionRefreshMethod': 'Invite',
            'earlyOfferSuppVoiceCall': 'Disabled (Default value)',
            'cucmVersionInSipHeader': 'Major And Minor',
            'confidentialAccessLevelHeaders': 'Disabled',
            'destRouteString': False,
            'inactiveSDPRequired': False,
            'allowRRAndRSBandwidthModifier': False,
            'connectCallBeforePlayingAnnouncement': False
        }
        profile = dict(standard_sip_profile)
        profile.update(**sip_profile)
        sip_profile = profile
        p = self.get_sip_profile(name=sip_profile['name'])
        if p is None:
            p = self.add_sip_profile(sip_profile)
        else:
            # update
            p = self.update_sip_profile(**sip_profile)
        return p

    ################ translation pattern
    TRANS_PATTERN_TAGS = ['pattern', 'description', 'routePartitionName']

    def list_translation(self, returned_tags=None, **search_criteria):

        returned_tags = returned_tags or self.TRANS_PATTERN_TAGS

        search_criteria = self.filter_search_criteria(search_criteria, ['pattern', 'description', 'routePartitionName'],
                                                      'pattern')
        r = self.service.listTransPattern(searchCriteria=search_criteria,
                                          returnedTags={t: '' for t in returned_tags})
        return self.handle_list_response(r)

    def add_translation(self, pattern, partition, description,
                        digit_discard='', prefix_digits='',
                        called_party_transformation_mask='',
                        block_enable=False, urgency=True,
                        outside_dial_tone=False, css_inheritance=True,
                        dont_wait_for_idt=True):
        translation = {
            'pattern': pattern,
            'routePartitionName': partition,
            'description': description,
            'usage': 'Translation',
            'blockEnable': block_enable,
            'patternUrgency': urgency,
            'provideOutsideDialtone': outside_dial_tone,
            'digitDiscardInstructionName': digit_discard,
            'prefixDigitsOut': prefix_digits,
            'useOriginatorCss': css_inheritance,
            'dontWaitForIDTOnSubsequentHops': dont_wait_for_idt,
            'calledPartyTransformationMask': called_party_transformation_mask
        }
        r = self.service.addTransPattern(transPattern=translation)
        return r

    def add_update_translation(self, pattern, partition, description,
                               digit_discard='', prefix_digits='',
                               called_party_transformation_mask='',
                               block_enable=False, urgency=True,
                               outside_dial_tone=False, css_inheritance=True,
                               dont_wait_for_idt=True):
        translation = {
            'pattern': pattern,
            'routePartitionName': partition,
            'description': description,
            'usage': 'Translation',
            'blockEnable': block_enable,
            'patternUrgency': urgency,
            'provideOutsideDialtone': outside_dial_tone,
            'digitDiscardInstructionName': digit_discard,
            'prefixDigitsOut': prefix_digits,
            'useOriginatorCss': css_inheritance,
            'dontWaitForIDTOnSubsequentHops': dont_wait_for_idt,
            'calledPartyTransformationMask': called_party_transformation_mask
        }
        try:
            p = self.service.getTransPattern(pattern=pattern,
                                             routePartitionName=partition,
                                             returnedTags={'pattern': '', 'routePartitionName': ''})
        except zeep.exceptions.Fault as e:
            p = self.service.addTransPattern(transPattern=translation)
        else:
            translation.pop('usage', None)
            p = self.service.updateTransPattern(**translation)
        return p['return']

    def remove_translation(self, uuid):
        r = self.service.removeTransPattern(uuid=uuid)
        return r

    ########## CnPTx
    def add_update_cnptx(self, pattern, partition, description, discard, prefix, plan, type, mask=''):
        trans = {
            'pattern': pattern,
            'routePartitionName': partition,
            'description': description,
            'callingPartyTransformationMask': mask,
            'useCallingPartyPhoneMask': 'Off',
            'dialPlanName': '',
            'digitDiscardInstructionName': discard,
            'callingPartyPrefixDigits': prefix,
            'routeFilterName': '',
            'callingLinePresentationBit': 'Default',
            'callingPartyNumberingPlan': plan,
            'callingPartyNumberType': type,
            'mlppPreemptionDisabled': False
        }
        try:
            p = self.service.getCallingPartyTransformationPattern(pattern=pattern,
                                                                  routePartitionName=partition,
                                                                  returnedTags={'pattern': '',
                                                                                'routePartitionName': ''})
        except zeep.exceptions.Fault:
            p = self.service.addCallingPartyTransformationPattern(callingPartyTransformationPattern=trans)
        else:
            p = self.service.updateCallingPartyTransformationPattern(**trans)
        return p['return']

    ####### etc

    def add_update_lrg(self, name, description):
        try:
            r = self.service.getLocalRouteGroup(name=name)
        except zeep.exceptions.Fault as e:
            if e.message.startswith('Item not valid'):
                lrg = {'name': name, 'description': description}
                r = self.service.addLocalRouteGroup(localRouteGroup=lrg)
            else:
                raise
        else:
            lrg = {'uuid': r['return']['localRouteGroup']['uuid'], 'name': name, 'description': description,
                   'newName': name, 'newDescription': description}
            r = self.service.updateLocalRouteGroup(localRouteGroup=lrg)
        return r['return']

    def add_update_advertised_pattern(self, pattern, description, pattern_type,
                                      hosted_pstn_rule='No PSTN', pstn_strip=0, pstn_prepend=''):
        ad_pattern = {
            'pattern': pattern,
            'description': description,
            'patternType': pattern_type,
            'hostedRoutePSTNRule': hosted_pstn_rule,
            'pstnFailStrip': pstn_strip,
            'pstnFailPrepend': pstn_prepend
        }
        try:
            r = self.service.getAdvertisedPatterns(pattern=pattern)
        except zeep.exceptions.Fault as e:
            r = self.service.addAdvertisedPatterns(advertisedPatterns=ad_pattern)
        else:
            r = self.service.updateAdvertisedPatterns(**ad_pattern)
        return r['return']

    def add_update_date_time_group(self, dt_group):
        try:
            r = self.service.getDateTimeGroup(name=dt_group['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addDateTimeGroup(dateTimeGroup=dt_group)
        else:
            r = self.service.updateDateTimeGroup(**dt_group)
        return r['return']

    def add_update_device_pool(self, dp):
        try:
            r = self.service.getDevicePool(name=dp['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addDevicePool(devicePool=dp)
        else:
            r = self.service.updateDevicePool(**dp)
        return r['return']

    def add_update_line(self, dn):
        returned_tags = {k:'' for k in dn.keys()}
        try:
            r = self.service.getLine(pattern=dn['pattern'], routePartitionName=dn['routePartitionName'], returnedTags = returned_tags)
        except zeep.exceptions.Fault as e:
            r = self.service.addLine(line=dn)
        else:
            dn.pop('usage', None)
            r = self.service.updateLine(**dn)
        return r['return']

    def add_update_phone(self, phone):
        try:
            r = self.service.getPhone(name=phone['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addPhone(phone=phone)
        else:
            to_pop = ['product', 'protocolSide', 'class', 'protocol']
            for p in to_pop:
                phone.pop(p, None)
            r = self.service.updatePhone(**phone)
        return r['return']

    def add_update_fgt(self, fgt):
        try:
            r = self.service.getFeatureGroupTemplate(name=fgt['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addFeatureGroupTemplate(featureGroupTemplate=fgt)
        else:
            r = self.service.updateFeatureGroupTemplate(**fgt)
        return r['return']

    def add_update_ldap_filter(self, filter):
        try:
            r = self.service.getLdapFilter(name=filter['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addLdapFilter(ldapFilter=filter)
        else:
            r = self.service.updateLdapFilter(**filter)
        return r['return']

    def add_update_ldap_directory(self, directory):
        try:
            r = self.service.getLdapDirectory(name=directory['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addLdapDirectory(ldapDirectory=directory)
        else:
            attrs_not_in_update = ['mailId', 'directoryUri', 'middleName', 'phoneNumber']
            for a in attrs_not_in_update:
                directory.pop(a, None)
            r = self.service.updateLdapDirectory(**directory)
        return r['return']

    def add_update_sip_trunk_security_profile(self, profile):
        default_security_profile = {
            'securityMode': 'Non Secure',
            'incomingTransport': 'TCP+UDP',
            'outgoingTransport': 'TCP',
            'digestAuthentication': False,
            'noncePolicyTime': '600',
            'x509SubjectName': '',
            'incomingPort': '5060',
            'applLevelAuthentication': False,
            'acceptPresenceSubscription': False,
            'acceptOutOfDialogRefer': False,
            'acceptUnsolicitedNotification': False,
            'allowReplaceHeader': False,
            'transmitSecurityStatus': False,
            'sipV150OutboundSdpOfferFiltering': 'Use Default Filter',
            'allowChargingHeader': False
        }
        security_profile = dict(default_security_profile)
        security_profile.update(**profile)
        profile = security_profile
        try:
            r = self.service.getSipTrunkSecurityProfile(name=profile['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addSipTrunkSecurityProfile(sipTrunkSecurityProfile=profile)
        else:
            r = self.service.updateSipTrunkSecurityProfile(**profile)
        return r['return']

    def add_update_sip_trunk(self, trunk):
        default_sip_trunk = {
            'product': 'SIP Trunk',
            'class': 'Trunk',
            'protocol': 'SIP',
            'protocolSide': 'Network',
            'callingSearchSpaceName': '',
            'devicePoolName': 'Default',
            'commonDeviceConfigName': '',
            'networkLocation': 'Use System Default',
            'locationName': 'Hub_None',
            'mediaResourceListName': '',
            'networkHoldMohAudioSourceId': '',
            'userHoldMohAudioSourceId': '',
            'automatedAlternateRoutingCssName': '',
            'aarNeighborhoodName': '',
            'packetCaptureMode': 'None',
            'packetCaptureDuration': '0',
            'loadInformation': '',
            'traceFlag': False,
            'mlppIndicationStatus': 'Off',
            'preemption': 'Disabled',
            'useTrustedRelayPoint': 'Default',
            'retryVideoCallAsAudio': True,
            'securityProfileName': 'Non Secure SIP Trunk Profile',
            'sipProfileName': 'Standard SIP Profile',
            'cgpnTransformationCssName': '',
            'useDevicePoolCgpnTransformCss': True,
            'geoLocationName': '',
            'geoLocationFilterName': '',
            'sendGeoLocation': False,
            'cdpnTransformationCssName': '',
            'useDevicePoolCdpnTransformCss': True,
            'unattendedPort': False,
            'transmitUtf8': False,
            'subscribeCallingSearchSpaceName': '',
            'rerouteCallingSearchSpaceName': '',
            'referCallingSearchSpaceName': '',
            'mtpRequired': False,
            'presenceGroupName': 'Standard Presence group',
            'unknownPrefix': 'Default',
            'tkSipCodec': '711ulaw',
            'connectedNamePresentation': 'Default',
            'connectedPartyIdPresentation': 'Default',
            'callingPartySelection': 'Originator',
            'callingname': 'Default',
            'callingLineIdPresentation': 'Default',
            'prefixDn': '',
            'callerName': '',
            'callerIdDn': '',
            'acceptInboundRdnis': True,
            'acceptOutboundRdnis': True,
            'srtpAllowed': False,
            'srtpFallbackAllowed': True,
            'isPaiEnabled': True,
            'sipPrivacy': 'Default',
            'isRpidEnabled': True,
            'sipAssertedType': 'Default',
            'dtmfSignalingMethod': 'No Preference',
            'routeClassSignalling': 'Default',
            'sipTrunkType': 'None(Default)',
            'pstnAccess': False,
            'imeE164TransformationName': '',
            'useImePublicIpPort': False,
            'useDevicePoolCntdPnTransformationCss': True,
            'useDevicePoolCgpnTransformCssUnkn': True,
            'sipNormalizationScriptName': '',
            'runOnEveryNode': True,
        }
        sip_trunk = dict(default_sip_trunk)
        sip_trunk.update(**trunk)
        trunk = sip_trunk
        try:
            r = self.service.getSipTrunk(name=trunk['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addSipTrunk(sipTrunk=trunk)
        else:
            attrs_not_in_update = ['product', 'protocolSide', 'loadInformation', 'protocol', 'traceFlag', 'class']
            for a in attrs_not_in_update:
                trunk.pop(a, None)
            r = self.service.updateSipTrunk(**trunk)

        return r['return']

    def add_update_route_group(self, route_group):
        try:
            r = self.service.getRouteGroup(name=route_group['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addRouteGroup(routeGroup=route_group)
        else:
            r = self.service.updateRouteGroup(**route_group)
        return r['return']

    def add_update_sip_route_pattern(self, route_pattern):
        try:
            r = self.service.getSipRoutePattern(pattern=route_pattern['pattern'],
                                                routePartitionName=route_pattern['routePartitionName'])
        except zeep.exceptions.Fault as e:
            r = self.service.addSipRoutePattern(sipRoutePattern=route_pattern)
        else:
            attrs_not_in_update = ['usage']
            for a in attrs_not_in_update:
                route_pattern.pop(a, None)
            r = self.service.updateSipRoutePattern(**route_pattern)
        return r['return']

    def add_update_universal_device_template(self, site_udt):
        base_udt = {
            'deviceSecurityProfile': 'Universal Device Template - Model-independent Security Profile',
            'phoneButtonTemplate': 'Universal Device Template Button Layout',
            'sipDialRules': None,
            'callingPartyTransformationCSSForInboundCalls': None,
            'callingPartyTransformationCSSForOutboundCalls': None,
            'reroutingCallingSearchSpace': None,
            'subscribeCallingSearchSpaceName': None,
            'useDevicePoolCallingPartyTransformationCSSforInboundCalls': True,
            'useDevicePoolCallingPartyTransformationCSSforOutboundCalls': True,
            'commonPhoneProfile': 'Standard Common Phone Profile',
            'commonDeviceConfiguration': None,
            'softkeyTemplate': 'Cisco User with Feature Hardkeys',
            'featureControlPolicy': None,
            'phonePersonalization': 'Default',
            'mtpPreferredOriginatingCodec': '711ulaw',
            'outboundCallRollover': 'No Rollover',
            'mediaTerminationPointRequired': False,
            'unattendedPort': False,
            'requiredDtmfReception': False,
            'rfc2833Disabled': False,
            'useTrustedRelayPoint': 'Default',
            'protectedDevice': False,
            'servicesProvisioning': 'Default',
            'packetCaptureMode': 'None',
            'packetCaptureDuration': 0,
            'secureShellUser': None,
            'secureShellPassword': None,
            'userLocale': None,
            'networkLocale': None,
            'mlppDomain': None,
            'mlppIndication': 'Default',
            'mlppPreemption': 'Default',
            'dndOption': 'Use Common Phone Profile Setting',
            'dndIncomingCallAlert': None,
            'aarGroup': 'Default',
            'blfPresenceGroup': 'Standard Presence group',
            'blfAudibleAlertSettingPhoneBusy': 'Default',
            'blfAudibleAlertSettingPhoneIdle': 'Default',
            'userHoldMohAudioSource': None,
            'networkHoldMohAudioSource': None,
            'geoLocation': None,
            'deviceMobilityMode': 'Default',
            'mediaResourceGroupList': None,
            'remoteDevice': False,
            'hotlineDevice': False,
            'retryVideoCallAsAudio': True,
            'requireOffPremiseLocation': False,
            'ownerUserId': None,
            'mobilityUserId': None,
            'joinAcrossLines': 'Default',
            'alwaysUsePrimeLine': 'Default',
            'alwaysUsePrimeLineForVoiceMessage': 'Default',
            'singleButtonBarge': 'Default',
            'builtInBridge': 'Default',
            'allowControlOfDeviceFromCti': True,
            'ignorePresentationIndicators': False,
            'enableExtensionMobility': True,
            'servicesUrl': None
        }
        udt = dict(base_udt)
        udt.update(**site_udt)
        try:
            r = self.service.getUniversalDeviceTemplate(name=udt['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addUniversalDeviceTemplate(universalDeviceTemplate=udt)
        else:
            r = self.service.updateUniversalDeviceTemplate(**udt)
        return r['return']

    def add_update_universal_line_template(self, site_ult):
        base_ult = {
            'voiceMailProfile': None,
            'extCallControlProfile': None,
            'blfPresenceGroup': 'Standard Presence group',
            'partyEntranceTone': 'Default',
            'autoAnswer': 'Auto Answer Off',
            'rejectAnonymousCall': True,
            'userHoldMohAudioSource': None,
            'networkHoldMohAudioSource': None,
            'retainDestInCallFwdHistory': False,
            'CssActivationPolicy': 'Use System Default',
            'fwdDestExtCallsWhenNotRetrieved': None,
            'cssFwdExtCallsWhenNotRetrieved': None,
            'fwdDestInternalCallsWhenNotRetrieved': None,
            'cssFwdInternalCallsWhenNotRetrieved': None,
            'parkMonitorReversionTime': 60,
            'target': None,
            'mlppCss': None,
            'mlppNoAnsRingDuration': None,
            'holdReversionRingDuration': None,
            'holdReversionNotificationInterval': None,
            'busyIntCallsDestination': None,
            'busyExtCallsDestination': None,
            'noAnsIntCallsDestination': None,
            'noAnsExtCallsDestination': None,
            'noCoverageIntCallsDestination': None,
            'noCoverageExtCallsDestination': None,
            'unregisteredIntCallsDestination': None,
            'unregisteredExtCallsDestination': None,
            'ctiFailureDestination': None
        }
        ult = dict(base_ult)
        ult.update(**site_ult)
        try:
            r = self.service.getUniversalLineTemplate(name=ult['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addUniversalLineTemplate(universalLineTemplate=ult)
        else:
            r = self.service.updateUniversalLineTemplate(**ult)
        return r['return']

    def add_update_user_profile_provision(self, upp):
        try:
            r = self.service.getUserProfileProvision(name=upp['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addUserProfileProvision(userProfileProvision=upp)
        else:
            r = self.service.updateUserProfileProvision(**upp)
        return r['return']
        pass

    def add_update_cti_rp(self, cti_rp):
        try:
            r = self.service.getCtiRoutePoint(name=cti_rp['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addCtiRoutePoint(ctiRoutePoint=cti_rp)
        else:
            to_pop = ['product', 'protocolSide', 'class', 'protocol']
            for p in to_pop:
                cti_rp.pop(p, None)
            r = self.service.updateCtiRoutePoint(**cti_rp)
        return r['return']

    def add_update_app_user(self, app_user):
        try:
            r = self.service.getAppUser(userid=app_user['userid'])
        except zeep.exceptions.Fault as e:
            r = self.service.addAppUser(appUser=app_user)
        else:
            r = self.service.updateAppUser(**app_user)
        return r['return']

    def add_update_phone_button_template(self, pbt):
        try:
            r = self.service.getPhoneButtonTemplate(name=pbt['name'])
        except zeep.exceptions.Fault as e:
            r = self.service.addPhoneButtonTemplate(phoneButtonTemplate=pbt)
        else:
            pbt.pop('basePhoneTemplateName', None)
            r = self.service.updatePhoneButtonTemplate(**pbt)
        return r['return']
