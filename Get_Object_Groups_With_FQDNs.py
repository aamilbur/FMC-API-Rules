import requests
import sys
import json

# GET IP address of FMC and login credentials
user = input("Enter your FMC API username: ")
password = input("Enter your FMC API password: ")
fmc_ip = input("Enter your FMC IP address: ")

# set up variables
url = f"https://{fmc_ip}"


def get_token(url, user, password):
    headers = {'Content-Type': 'application/json'}
    login_url = "/api/fmc_platform/v1/auth/generatetoken"
    try:
        #POST the username and password to the FMC
        login_response = requests.post(
            f"{url}{login_url}", auth=(user, password), verify=False)
        login_response.raise_for_status()

        # print(login_response)
        #Parse out the headers
        response_headers = login_response.headers

        #Grab the token from the response headers
        token = response_headers.get("X-auth-access-token", default=None)
        # print(token)
        if token == None:
            print("Failed to get a token.  Try again")
            sys.exit

        #Set the token in the headers to be used in the next call
        headers["X-auth-access-token"] = token
        return headers
    except Exception as err:
        print(f"Error raised!  {err}")
        return None

def get_domains(url, headers):
    # get domains on the FMC
    specific_path = "/api/fmc_platform/v1/info/domain"
    obj_list = []

    try:
        object_response = requests.get(
            f"{url}{specific_path}", headers=headers, verify=False)
        object_response.raise_for_status()
        results = object_response.json()

        # add each object into a list
        for item in results["items"]:
            obj_list.append(item['uuid'])

        return obj_list
    except Exception as err:
        print(f"Error raised!  {err}")
        return obj_list

def get_object_groups(url, headers, domainUUID):
    # get fqdn objects

    specific_path = f"/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups"
    obj_list = []

    try:
        object_response = requests.get(
            f"{url}{specific_path}", headers=headers, verify=False)
        object_response.raise_for_status()
        results = object_response.json()

        # add each object into a list
        for item in results["items"]:
            obj_list.append(item)

        return obj_list
    except Exception as err:
        print(f"Error raised!  {err}")
        return obj_list

def check_network_group_for_fqdns(url, headers, domainUUID, group_id):
    # return TRUE if network group contains an FQDN object

    specific_path = f"/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups/{group_id}"
    obj_list = []
    #initialize return value
    fqdns_in_group = False
    dict_key = 'literals'

    try:
        object_response = requests.get(
            f"{url}{specific_path}", headers=headers, verify=False)
        object_response.raise_for_status()
        results = object_response.json()
        if 'literals' in results:
            dict_key = 'literals'
        else:
            dict_key = 'objects'

        # add each object into a list
        for item in results[dict_key]:
            obj_list.append(item)
            if item['type'] == 'FQDN':
                fqdns_in_group = True

        return fqdns_in_group
    except Exception as err:
        print(f"Error raised!  {err}")
        return fqdns_in_group



#############################################################################################

#call function to get token
headers = get_token(url, user, password)

#get all domains
domains = get_domains(url=url, headers=headers)

#initialize group list for network groups that have FQDNs in them
fqdn_groups = []

for x in domains:
    domainUUID = x
    objects = get_object_groups(url=url, headers=headers, domainUUID=domainUUID)
    for item in objects:
        #obj_list.append(item['uuid'])
        #check to see if the network group has any fqdns in it
        #print(item['name'])
        #print(item['id'])
        if check_network_group_for_fqdns(url, headers, domainUUID, group_id=item['id']) == True:
            fqdn_groups.append(item['id'])

    #if list is not empty, go through each group and get all elements.

    print(fqdn_groups)