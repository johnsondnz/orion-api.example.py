# orionsdk 
# https://github.com/solarwinds/orionsdk-python

from orionsdk import SwisClient
import re
import datetime 
import requests

# import now for timezone aware, uses UTC
from django.utils.timezone import now

# import application settings
from classes.settings import Settings

class Orion():

    def __init__(self):
        
        # start the connection
        self.server = 'server fqdn or ip'
        self.username = 'orion username'
        self.password = 'orion password'

        self.con = SwisClient(self.server,self.username,self.password)

        requests.packages.urllib3.disable_warnings()  

    def get_all_juniper_node_ids(self, **kwargs):

        self.q = self.con.query('SELECT NodeID,Caption FROM Orion.Nodes WHERE Vendor LIKE @vendor', vendor='Juniper%')
        return self.q

    def get_all_cisco_node_ids(self, **kwargs):

        self.q = self.con.query('SELECT NodeID,Caption FROM Orion.Nodes WHERE Vendor LIKE @vendor', vendor='Cisco')
        return self.q

    def npm_add_node(self, **kwargs):

        s = Settings()
        settings = s.get_all_settings()

        # first check this device isn't already in Orion
        self.ip_check = self.con.query('SELECT NodeID FROM Orion.Nodes WHERE IPAddress=@ip_address', ip_address=kwargs.get('ip_address'))
        self.hostname_check = self.con.query('SELECT NodeID FROM Orion.Nodes WHERE Caption=@hostname', hostname=kwargs.get('hostname'))
        if len(self.ip_check['results']) > 0 or len(self.hostname_check['results']) > 0:

            # if this is greater than 0, then the device already exists in orion
            return

        else:

            # assign the device poperties for adding to the database
            # support only for SNMPv2 at this stage
            self.properties = {
                'Caption': kwargs.get('hostname'),
                'IPAddress': kwargs.get('ip_address'),
                'DynamicIP': False,
                'EngineID': kwargs.get('engine_id') or 1, 
                'Status': 1,
                'Allow64BitCounters': 1,
                'ObjectSubType': 'SNMP',
                'SNMPVersion': kwargs.get('snmp_version') or 2,
                'Community': kwargs.get('community'),
                # Set NextRediscovery to now + 2 mins so that rediscovery happens at the next rediscovery interval, default 30mins
                'NextRediscovery': datetime.datetime.now() + datetime.timedelta(minutes = 2)
            }

            # create the node
            self.results = self.con.create('Orion.Nodes', **self.properties)

            # get the NodeID
            self.node_id = re.search('(\d+)$', self.results).group(0)

            # setup device pollers
            self.pollers_enabled = {
                'N.Status.ICMP.Native': True,
                'N.Status.SNMP.Native': False,
                'N.ResponseTime.ICMP.Native': True,
                'N.ResponseTime.SNMP.Native': False,
                'N.Details.SNMP.Generic': True,
                'N.Uptime.SNMP.Generic': True,
                'N.Cpu.SNMP.HrProcessorLoad': True,
                'N.Memory.SNMP.NetSnmpReal': True,
                'N.AssetInventory.Snmp.Generic': True,
                'N.Topology_Layer3.SNMP.ipNetToMedia': False,
                'N.Routing.SNMP.Ipv4CidrRoutingTable': False
            }  

            # create a list of dictionarys for each poller
            self.pollers = []
            for self.k in self.pollers_enabled:
                self.pollers.append(
                    {
                        'PollerType': self.k,
                        'NetObject': 'N:' + self.node_id,
                        'NetObjectType': 'N',
                        'NetObjectID': self.node_id,
                        'Enabled': self.pollers_enabled[self.k]
                    }
                )

            # loop through pollers and turn them on
            for self.poller in self.pollers:
                 self.response = self.con.create('Orion.Pollers', **self.poller)

            # add the custom properties
            self.results = self.con.query(
                "SELECT Uri FROM Orion.Nodes WHERE NodeID=@id",
                id=self.node_id
            )

            # grab the uri - whatever this is
            self.uri = self.results['results'][0]['Uri']

            # update the custom properties
            self.con.update(
                self.uri + '/CustomProperties',
                City = kwargs.get('city'),
                Site = kwargs.get('site'),
                Network = kwargs.get('network')
            )

            return self.node_id

    def npm_add_interfaces(self, node_id):

        # run interface discovery
        self.interfaces = self.con.invoke('Orion.NPM.Interfaces', 'DiscoverInterfacesOnNode', node_id)
        # imports only interfaces with a description
        # alternatively any physical Cisco interfaces with and up status could be added
        self.descr_only = [
            self.x for self.x
            in self.interfaces['DiscoveredInterfaces']
            if re.search('\xb7', self.x['Caption'])
        ]

        # add the interfaces
        self.execute = self.con.invoke(
            'Orion.NPM.Interfaces',
            'AddInterfacesOnNode',
            node_id,
            self.descr_only,
            'AddDefaultPollers'
        )

    def npm_poll_now(self, node_id, **kwargs):
        self.con.invoke('Orion.Nodes', 'PollNow', 'N:%s' % self.node_id)

    def ncm_add_node(self, node_id, **kwargs):

        s = Settings()
        settings = s.get_all_settings()

        # check that device isn't already managed in Orion NCM
        self.ip_check = self.con.query('SELECT NodeID FROM Cirrus.Nodes WHERE AgentIP=@ip_address', ip_address=kwargs.get('ip_address'))
        self.hostname_check = self.con.query('SELECT NodeID FROM Cirrus.Nodes WHERE NodeCaption=@hostname', hostname=kwargs.get('hostname'))
        if len(self.ip_check['results']) > 0 or len(self.hostname_check['results']) > 0:
            
            # if this is greater than 0, then the device already exists in orion
            return

        else:

            self.con.invoke('Cirrus.Nodes', 'AddNodeToNCM', node_id)

            # now update the selected columns to ensure we can log into this device
            # first using rhe NodeID from Orion.NPM get the Guid
            self.ncm_node_id = self.con.query('SELECT NodeID FROM Cirrus.Nodes WHERE CoreNodeID=@node', node=node_id)['results'][0]['NodeID']  

            # fetch the NCM Node Object
            self.ncm_node_data = self.con.invoke('Cirrus.Nodes', 'GetNode', self.ncm_node_id)

            # verfify that the submitted connection_profile exists
            # if it doesn't set the profile to '-1'
            self.profiles = self.con.invoke('Cirrus.Nodes', 'GetAllConnectionProfiles')
            for self.pro in self.profiles:
                if self.pro['ID'] == kwargs.get('connection_profile'):
                    self.connection_profile_id = kwargs.get('connection_profile')
                else:
                    self.connection_profile_id = -1

            # modify the device properties but only if the submitted profile is valid
            if self.connection_profile_id != -1:
                self.ncm_node_data['Username'] = ''
                self.ncm_node_data['Password'] = ''
                self.ncm_node_data['ConnectionProfile'] = self.connection_profile_id 

             # Commit our changes  
            self.con.invoke('Cirrus.Nodes', 'UpdateNode', self.ncm_node_data)

    def ncm_get_guid(self, hostname):
        # used to determine the guid for a hostname as it exists in Orion NCM
        self.node_id = self.con.query("SELECT NodeID FROM Cirrus.Nodes WHERE NodeCaption=@node", node=hostname)
        if self.node_id is not None:
            return self.node_id
        else:
            return False


    def ncm_download_configs(self, hostname):
        # cannot be called until a device has been discovered, this action in Orion depends on a known sysObjectID OID

        # get the System.Guid[] into a list, if submitted as a simple string the API errors out
        # HTTPError: 400 Client Error: Verb Cirrus.ConfigArchive.DownloadConfig cannot unpackage parameter 0 with type System.Guid[] \
        # for url: https://lab-win2012.it-ninja.xyz:17778/SolarWinds/InformationService/v3/Json/Invoke/Cirrus.ConfigArchive/DownloadConfig
        self.node_ids = []
        self.node_data = self.con.query("SELECT NodeID FROM Cirrus.Nodes WHERE NodeCaption=@node", node=hostname)
        self.node_ids.append(self.node_data['results'][0]['NodeID'])

        configs = ['Active', 'Set', 'Rescue']
        for c in configs:
            self.con.invoke("Cirrus.ConfigArchive",  "DownloadConfig", self.node_ids, c)

    def get_connection_profiles(self):
        self.profiles = self.con.invoke('Cirrus.Nodes', 'GetAllConnectionProfiles')
        return self.profiles

    def ncm_remove_node(self, hostname):
        # used to unmange a node from Orion NCM
        # called pre-delete node from Orion NPM
        self.node_id = self.ncm_get_guid(hostname)
        if self.node_id is not False:
            self.con.invoke("Cirrus.Nodes",  "RemoveNode", self.node_id)

    def npm_get_uri(self, hostname):
        # used to get the node_id of a pre-existing node in Orion NPM

        self.node_uri = self.con.query("SELECT Uri FROM Orion.Nodes WHERE Caption=@hostname", hostname=hostname)
        return self.node_uri

    def npm_delete_node(self, hostname):
        
        # get the devices uri.  This is a list of dictionaries
        self.node_uri = self.npm_get_uri(hostname)
        # call swis to delete the node
        if self.node_uri is not False:
            self.con.delete(self.node_uri['results'][0]['Uri'])
