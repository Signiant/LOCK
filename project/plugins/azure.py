from azure.keyvault import KeyVaultClient, KeyVaultId
from azure.common.credentials import UserPassCredentials


from azure.mgmt.network import NetworkManagementClient, NetworkManagementClientConfiguration

from azure.mgmt.compute import ComputeManagementClient
from msrestazure.azure_active_directory import ServicePrincipalCredentials


def do_stuff(configMap, username,  **key_args):
    key_vault_uri = key_args.get('vault_uri')
    username = key_args.get('user')
    password = key_args.get('password')

    subscription_id = key_args.get('subscription_id')

    credentials = UserPassCredentials(username, password)


    from azure.mgmt.resource import ResourceManagementClient
#    client = ResourceManagementClient(credentials, subscription_id)
    #client.resource_groups.create(RESOURCE_GROUP_NAME, {'location':'eastus'})

    #ServicePrincipalCredentials
    # for item in client.resource_groups.list_resources('devops'):
    #     print(item)

    ############## ROTATE KEY IN KEY VAULT
    # for item in client.resource_groups.list():
    #     print(item)
    #

    #
    # credentials = UserPassCredentials(username, password, resource='https://vault.azure.net')
    # client = KeyVaultClient(credentials)
    #
    # secret_bundle = client.set_secret(key_vault_uri, 'FirstSecret', 'Hush you, that is secret!!')
    # secret_id = KeyVaultId.parse_secret_id(secret_bundle.id)
    # print(secret_id)

    credentials = ServicePrincipalCredentials(
        client_id='',  # name of created app
        secret='',  # secret of app
        tenant=''  # id ot signant add
    )
    #list resource groups in a subs
    client = ResourceManagementClient(credentials, subscription_id)
    # for item in client.resource_groups.list():
    #     print(item)

    ####list resource within a resource group
    # for item in client.resources.list_by_resource_group(''):
    #     print(item)
    # print('')

    credentials = UserPassCredentials(username, password)

    network_client = NetworkManagementClient(

            credentials,
            subscription_id

    )
    #https://stackoverflow.com/questions/37265885/is-there-any-python-api-which-can-get-the-ip-address-internal-or-external-of-v
    # GROUP_NAME = '--Group-'
    # VM_NAME = ''
    # PUBLIC_IP_NAME = VM_NAME
    # ip_address = network_client.public_ip_addresses
    # public_ip_address = network_client.public_ip_addresses.get(GROUP_NAME, PUBLIC_IP_NAME)
    # print(public_ip_address.ip_address)
    # print(public_ip_address.ip_configuration.private_ip_address)
    #



# Unfortunate and convoluted way of obtaining public IP of selected instance
    # List istances
    compute_client = ComputeManagementClient(
        credentials,
        subscription_id
    )
    instance_list = compute_client.virtual_machines.list_all()
    for i, instance in enumerate(instance_list):
        print((instance.name))

#https://github.com/Azure/azure-sdk-for-python/issues/897
    ni_reference = instance.network_profile.network_interfaces[0]
    ni_reference = ni_reference.id.split('/')
    ni_group = ni_reference[4]
    ni_name = ni_reference[8]

    net_interface = network_client.network_interfaces.get(ni_group, ni_name)
    ip_reference = net_interface.ip_configurations[0].public_ip_address
    ip_reference = ip_reference.id.split('/')
    ip_group = ip_reference[4]
    ip_name = ip_reference[8]

    public_ip = network_client.public_ip_addresses.get(ip_group, ip_name)
    public_ip = public_ip.ip_address
    print (public_ip)
    # use ip to rotate


