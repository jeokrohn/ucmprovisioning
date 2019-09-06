import requests
import os
import zeep
import zeep.cache
import tempfile


class ControlCenterHelper:
    def __init__(self, auth, version=None, verify=None, timeout=60):

        self.session = requests.Session()
        self.session.auth = auth
        if verify is not None:
            self.session.verify = verify

        if version is None:
            # Somehow determine the UCM version
            raise Exception('Not implemented')

        wsdl_version = version

        self.wsdl = os.path.join(os.path.dirname(__file__), 'WSDL', wsdl_version, 'ControlCenterServices.wsdl')

        self.cache = zeep.cache.SqliteCache(
            path=os.path.join(tempfile.gettempdir(), 'sqlite_control_CC.db'),
            timeout=60)

        self.client = zeep.Client(wsdl=self.wsdl,
                                  transport=zeep.Transport(timeout=timeout,
                                                           operation_timeout=timeout,
                                                           cache=self.cache,
                                                           session=self.session))

        self.services = {}
        return

    @staticmethod
    def service_url(host):
        if not ':' in host:
            host += ':8443'
        return 'https://{host}/controlcenterservice2/services/ControlCenterServices'.format(host=host)

    def assert_service(self, host):
        service = self.services.get(host, None)
        if service is None:
            service = self.client.create_service('{http://schemas.cisco.com/ast/soap}ControlCenterServicesBinding',
                                                 self.service_url(host))
            self.services[host] = service
        return service

    def get_product_information_list(self, host):
        service = self.assert_service(host)
        r = service.getProductInformationList(ServiceInfo='')
        return r

    def soap_get_service_status(self, host, service_status=''):
        service = self.assert_service(host)
        return service.soapGetServiceStatus(ServiceStatus=service_status)

    def soap_get_static_service_list(self, host):
        service = self.assert_service(host)
        return service.soapGetStaticServiceList(ServiceInformationResponse='')

    def soap_do_control_services(self, host, node_name, control_type, service_name):
        assert control_type in ['Start', 'Stop', 'Restart']
        service = self.assert_service(host)
        request = {
            'NodeName': node_name,
            'ControlType': control_type,
            'ServiceList': service_name
        }
        return service.soapDoControlServices(ControlServiceRequest=request)

    def soap_do_service_deployment(self, host, node_name, deploy_type='Deploy', service_name=None):
        assert service_name is not None
        service = self.assert_service(host)
        request = {
            'NodeName': node_name,
            'DeployType': deploy_type,
            'ServiceList': service_name
        }
        return service.soapDoServiceDeployment(DeploymentServiceRequest=request)

