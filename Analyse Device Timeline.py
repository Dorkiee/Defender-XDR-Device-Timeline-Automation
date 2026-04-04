
import requests
import pandas as pd
import requests
import time
import base64
from IPython.display import display
from datetime import datetime, timedelta, timezone


url_vt = 'https://www.virustotal.com/api/v3/ip_addresses/'
url_otx = 'https://otx.alienvault.com:443/api/v1/indicators/IPv4/'
api_key = "your_virustotal_api_key"
otx_api_key = "your_otx_api_key"


all_responses = []

#Gets responses from VIRUSTOTAL, OTX, AND SCAMALYTICS. Prints out a date frame and creats a csv file with the data
def get_ipv6_analysis(ip_address): 
    # Loop through each resource
    print(f"IP Analysis Summary:")


    for IP_Add in  ip_address:
        IP_Add = IP_Add.strip() # remove spaces
        headers_vt = {'x-apikey': api_key}
        
        
        response_vt = requests.get(f'{url_vt}{IP_Add}', headers=headers_vt)
        response_otx = requests.get(f'{url_otx}{IP_Add}/general', headers={'X-OTX-API-KEY': otx_api_key})
        SCAM_api_key = ""
        url_scamalytics = f'https://api11.scamalytics.com/YourCompanyNameHere/?key={SCAM_api_key}&ip={IP_Add}'
        response_scamalytics = requests.get(url_scamalytics)
    

        if response_vt.status_code == 200:
            data_vt = response_vt.json()  

            if "data" in data_vt:
                attributes = data_vt["data"]["attributes"]
                asn = attributes.get('asn', '')
                country = attributes.get('country', '')
                positives = attributes.get('last_analysis_stats', {}).get('malicious', 0)
                security_vendors = attributes.get('last_analysis_results', {})
                vendor_names = [vendor_name for vendor_name, result in security_vendors.items() if result['category'] == 'malicious']


                if response_otx.status_code == 200:
                    data_otx = response_otx.json()
                    otx_pulses = data_otx.get("pulse_info", {}).get("count")
                    otx_malicious = data_otx.get("pulse_info").get("is_malicious")
                    otx_lastmod = data_otx.get("last_modified")

                    if response_scamalytics.status_code == 200:
                        data_scamalytics = response_scamalytics.json()
                        risk_score = data_scamalytics.get('score')
                        is_high_risk = data_scamalytics.get('risk')

                        if (positives or otx_pulses) != 0:
                            print(f"IP address {IP_Add} - from the country {country}, "
                                f"with {positives} VT positives detected from these vendors {vendor_names}, "
                                f"had {otx_pulses} OTX pulses, {otx_malicious} OTX Malicious, an SA Score of {risk_score} "
                                f"and a {is_high_risk} SA Risk.")
                        else:
                            print(f"IP address {IP_Add} was not observed to be malicious.")
                            all_responses.append([IP_Add, asn, country, positives, vendor_names, otx_pulses,otx_malicious, otx_lastmod, risk_score, is_high_risk])
                    else:
                        print(f"Error fetching Scamalytics information for IP address: {IP_Add}")
                else:
                    print(f"Error fetching OTX information for IP address: {IP_Add}")
            else:
                print(f"Error fetching information for IP address: {IP_Add}")

        colums = ["IPAdress","ASN", "country", "VT positives", "VT vendors", "OTX pluses", "OTX malicious", "OTX last seen", "SA score", "SA Risk"]

        df = pd.DataFrame(all_responses, columns=colums)
        condition_col1= df['VT positives'] == 0
        condition_col2= df['OTX pluses'] == 0
        condition_col3 = df['SA score'] == 0
        combined_condtion = condition_col1 & condition_col2 & condition_col3# & condition_col4
        df_filtered = df[~combined_condtion]
        print("IP Details:")   
        #display(df_filtered)     


    filename = f"IPV6_Analysis.csv"
    df.to_csv(filename, index=False)
    return all_responses
    

API_KEY = ''

from datetime import datetime, timedelta, timezone

def check_existing_data(remote_ip=None, remote_url=None, days=None):
    if remote_ip:
        partition_key = "IP"
        row_key = remote_ip
    elif remote_url:
        partition_key = "URL"
        row_key = remote_url
    else:
        return None

    if days is None:
        days = 7 

    # Define the time frame limit
    days_ago = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        # Build the filter query for Azure Table
        query_filter = (
            f"PartitionKey eq '{partition_key}' and "
            f"RowKey eq '{row_key}' and "
            f"Timestamp ge datetime'{days_ago.isoformat()}'"
        )
        print(f"Query filter: {query_filter}")

        # Query the table for matching entities
        entities = list(table_client.query_entities(query_filter=query_filter))

        if entities:
            print(f"Entity found within time frame: {entities[0]}")
            return entities[0]  # Return the first matching entity
        else:
            print("No entity found within the specified time frame.")
            return None
    except Exception as e:
        print(f"Error occurred while querying data: {e}")
        return None

def store_vt_response(remote_ip=None, remote_url=None, all_responses=None):
    # Check if all_responses is valid and has at least 4 elements
    if not all_responses or len(all_responses) < 3:
        print("Invalid all_responses parameter")
        return

    # Determine the partition key and row key based on the provided parameters
    if remote_ip:
        partition_key = "IP"
        row_key = remote_ip
    elif remote_url:
        partition_key = "URL"
        row_key = remote_url
    else:
        print("Either remote_ip or remote_url must be provided")
        return

    # Convert list elements to strings 
    all_responses = [str(item) if isinstance(item, list) else item for item in all_responses]

    # Create the entity to be upserted
    entity = {
        "PartitionKey": partition_key,
        "RowKey": row_key,
        "ASN": all_responses[0],
        "Country": all_responses[1],
        "Positives": all_responses[2],
        "RemoteIP": remote_ip or "",
        "RemoteURL": remote_url or ""
    }

    try:
        # upsert the entity into the table
        table_client.upsert_entity(entity)
        print(f"Entity upserted successfully: {entity}")
    except Exception as e:
        # Handle any errors that occur during the upsert operation
        print(f"Error upserting entity: {e}")

def encode_to_base64(url):
    url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url

ip_columns = ["IP ASN", "IP Country", "IP VT Positives"]
url_columns = ["URL ASN", "URL Country", "URL VT Positives"]

for col in ip_columns + url_columns:
    network_events_df[col] = None

def query_url(url):
    url_id = encode_to_base64(url)
    api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(api_url, headers=headers)
    data_vt = response.json()
    all_responses = [None, None, 0, None]  # Default empty response
    if "data" in data_vt:
        attributes = data_vt["data"]["attributes"]

        asn = attributes.get('asn', '')
        country = attributes.get('country', '')
        positives = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        security_vendors = attributes.get('last_analysis_results', {})
        vendor_names = [vendor_name for vendor_name, result in security_vendors.items() if result['category'] == 'malicious']
        all_responses = [asn, country, positives]
    return all_responses if response.status_code == 200 else print(f"Error fetching information for URL address: {url}")

def query_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    data_vt = response.json()
    all_responses = [None, None, 0, None]  # Default empty response
    if "data" in data_vt:
        attributes = data_vt["data"]["attributes"]
        # Extract IP analysis info
        asn = attributes.get('asn', '')
        country = attributes.get('country', '')
        positives = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        security_vendors = attributes.get('last_analysis_results', {})
        vendor_names = [vendor_name for vendor_name, result in security_vendors.items() if result['category'] == 'malicious']
        all_responses = [asn, country, positives]
    return all_responses if response.status_code == 200 else print(f"Error fetching information for IP address: {ip}")

def query_virustotal(df):
    for index, row in df.iterrows():
        if row['RemoteUrl']:
            cleaned_url = row['RemoteUrl'].replace("https://", "").replace("http://", "")
            existing_data = check_existing_data(remote_url=cleaned_url, days=7)
            if existing_data:
                print(f"Data for URL {row['RemoteUrl']} already exists, skipping API call.")
                mapping = {"URL ASN": "ASN", "URL Country": "Country", "URL VT Positives": "Positives"}
                for col in url_columns:
                    df.at[index, col] = existing_data.get(mapping[col], None)
            else:
                print(f"Data for URL {row['RemoteUrl']} not found, making API call.")
                url_response = query_url(url=row['RemoteUrl'])
                store_vt_response(remote_url=cleaned_url, all_responses=url_response)
                if url_response:
                    for col, value in zip(url_columns, url_response):
                        df.at[index, col] = value
        
        if row['RemoteIP']:
            existing_data = check_existing_data(remote_ip=row['RemoteIP'], days=7)
            if existing_data:
                print(f"Data for IP {row['RemoteIP']} already exists, skipping API call.")
                mapping = {"IP ASN": "ASN", "IP Country": "Country", "IP VT Positives": "Positives"}
                for col in ip_columns:
                    df.at[index, col] = existing_data.get(mapping[col], None)
            else:
                print(f"Data for URL {row['RemoteIP']} not found, making API call.")
                ip_response = query_ip(ip=row['RemoteIP'])
                store_vt_response(remote_ip=row['RemoteIP'], all_responses=ip_response)
                if ip_response:
                    for col, value in zip(ip_columns, ip_response):
                        df.at[index, col] = value
    

    return df

def style_dataframe(df):
    return (df.style
            .set_properties(**{
                'background-color': 'f0f0f0',
                'color': 'black',
                'border-color': 'white',
                'border-style': 'solid',
                'border-width': '1px',
                'text-align': 'left'
            })
            .set_table_styles([{
                'selector': 'th',
                'props': [('background-color', '#4a86e8'), 
                          ('color', 'white'),
                          ('font-weight', 'bold'),
                          ('text-align', 'left'),
                          ('border', '1px solid white')]
            }])
           )
           
# //////// Perform the VirusTotal queries and populate the DataFrame
network_events_df = query_virustotal(network_events_df)

# //////// Drop rows where both IP and URL have no positives
network_events_df = network_events_df[~(((network_events_df['IP VT Positives'] == 0) | network_events_df['IP VT Positives'].isna()) &
          ((network_events_df['URL VT Positives'] == 0) | network_events_df['URL VT Positives'].isna()))]

network_events_df['Total Positives'] = network_events_df['IP VT Positives'].fillna(0) + network_events_df['URL VT Positives'].fillna(0)

df_sorted = network_events_df.sort_values(by="Total Positives", ascending=False)

# Reset index after dropping rows
df_sorted.reset_index(drop=True, inplace=True)

styled_df = style_dataframe(df_sorted)
display(styled_df)

