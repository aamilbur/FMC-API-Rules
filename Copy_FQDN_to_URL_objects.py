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

def get_objects(fmc_obj, url, headers, domainUUID):
    # get fqdn objects

    specific_path = f"/api/fmc_config/v1/domain/{domainUUID}/object/{fmc_obj}"
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


def get_specific_fqdn_object(headers, id, domainUUID):
    fqdn_path = f"/api/fmc_config/v1/domain/{domainUUID}/object/fqdns/{id}"

    try:
        object_response = requests.get(
            url=f"{url}{fqdn_path}", headers=headers, verify=False)
        object_response.raise_for_status()
        results = object_response.json()
        name = results['name']
        value = results['value']

        return [name, value]

    except Exception as err:
        print(f"Error raised!  {err}")

def copy_to_url(headers, obj_list, domainUUID):
    #copies all fqdn objects over to URL objects
    specific_path = f"/api/fmc_config/v1/domain/{domainUUID}/object/urls"
    for item in obj_list:
        #print(item['id'])
        list_value = get_specific_fqdn_object(headers=headers, id=item['id'], domainUUID=domainUUID)
        #print(list_value[0])
        payload = json.dumps(
            {
                "type": "Url",
                "name": list_value[0],
                "description": list_value[1],
                "url": list_value[1]
            }
        )
        try:
            object_response = requests.post(
                url=f"{url}{specific_path}", headers=headers, data=payload, verify=False)
            object_response.raise_for_status()

        except Exception as err:
            print(f"Error raised!  {err}")




######################################################################################################
fmc_obj = "fqdns"

#call function to get token
headers = get_token(url, user, password)
#get all domains
domains = get_domains(url=url, headers=headers)

for x in domains:
    domainUUID = x
    objects = get_objects(fmc_obj=fmc_obj, url=url, headers=headers, domainUUID=domainUUID)

    if objects:
            #call function to delete unused objects
            #delete_objects(headers=headers, obj_list=objects)
        #call function to copy FQDN objects to URL objects
        copy_to_url(headers=headers, obj_list=objects, domainUUID=domainUUID)
