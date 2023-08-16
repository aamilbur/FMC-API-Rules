import requests
import sys
import json
import pandas

# GET IP address of FMC and login credentials
user = input("Enter your FMC API username: ")
password = input("Enter your FMC API password: ")
fmc_ip = input("Enter your FMC IP address: ")

# set up variables
url = f"https://{fmc_ip}"
uuid = "e34e9598-8248-f189-2dfd-000000000000"

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

def CSV_to_List(data):
    #create list
    csv_list = []
    mac_array = data.to_numpy()

    #Loop through CSV data

    for x in mac_array:
        #website_name = x[1]
        #print(website_name)
        csv_list.append(x[1])

    return(csv_list)

def Create_FQDN_Objects(headers, obj_list, uuid):
    # copies all fqdn objects over to URL objects
    specific_path = f"/api/fmc_config/v1/domain/{uuid}/object/fqdns"
    for item in obj_list:

        print(item)
        payload = json.dumps(
            {
                #"type": "Url",
                #"name": list_value[0],
                #"description": list_value[1],
                #"url": list_value[1]
                "name": item,
                "type": "FQDN",
                "value": item,
                "dnsResolution": "IPV4_AND_IPV6",
                "description": ""

            }
        )
        try:
            object_response = requests.post(
                url=f"{url}{specific_path}", headers=headers, data=payload, verify=False)
            object_response.raise_for_status()

        except Exception as err:
            print(f"Error raised!  {err}")


######################################################################################################

#call function to get token
headers = get_token(url, user, password)

#Get data from CSV
data = pandas.read_csv("websites.csv")

websites = CSV_to_List(data)

#Create FQDN objects
#Create_FQDN_Objects(headers="test", obj_list=websites, uuid=uuid)
Create_FQDN_Objects(headers=headers, obj_list=websites, uuid=uuid)