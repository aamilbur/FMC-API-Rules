import requests
import sys
import json

# GET IP address of FMC and login credentials
user = input("Enter your FMC API username: ")
password = input("Enter your FMC API password: ")
fmc_ip = input("Enter your FMC IP address: ")

# set up variables
url = f"https://{fmc_ip}"
querystring = {"limit":"1000"}

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

######################################################################################################
fmc_obj = "fqdns"

#call function to get token
headers = get_token(url, user, password)

#Get data from CSV

#Create FQDN objects

