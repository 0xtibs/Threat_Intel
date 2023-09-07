import os
import vt
import json
import requests
import ipaddress
import openai
import shodan
import streamlit as st
import pandas as pd
from apikey import openai_api_key, greynoise_api_key, virustotal_api_key, otx_api_key, abuseipdb_api_key, shodan_api_key
from OTXv2 import OTXv2, IndicatorTypes


api_key = greynoise_api_key
openai.api_key = openai_api_key
otx = OTXv2(otx_api_key)

os.environ['OPENAI_API_KEY'] = openai.api_key

def is_valid_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def get_threat_intel(ip_address):
    headers = {
        'Accept': 'application/json',
        'key': api_key,
    }
    url = f'https://api.greynoise.io/v2/noise/context/{ip_address}'
    url2 = f'https://api.greynoise.io/v2/riot/{ip_address}'
    response = requests.get(url, headers=headers)
    response2 = requests.get(url2, headers=headers)
    data = response.json()
    data2 = response2.json()

    combined_intel = {
        'classification': data.get('classification'),
        'actor': data.get('actor'),
        'metadata': data.get('metadata'),
        'last_seen': data.get('last_seen'),
        'analysis': data.get('analysis'),
        'cve': data.get('cve'),
        'riot': data2.get('riot'),
        'category': data2.get('category'),
        'description': data2.get('description'),
        'last_updated': data2.get('last_updated'),
        'trust_level': data2.get('trust_level'),
        'otx': get_otx_intel(ip_address)
    }
    virustotal_data = get_virustotal_intel(ip_address)
    combined_intel.update(virustotal_data)
    abuseipdb_data = get_abuseipdb_intel(ip_address)
    combined_intel.update(abuseipdb_data)
    shodan_data = get_shodan_info(ip_address)
    combined_intel.update(shodan_data)

    return combined_intel

def get_virustotal_intel(ip_address):
    client = vt.Client(virustotal_api_key)
    object = client.get_object(f"/ip_addresses/{ip_address}")
    virustotal_intel = {
        'as_owner': object.as_owner,
        'country': object.country,
        'reputation': object.reputation
    }
    return virustotal_intel

def get_otx_intel(ip_address):
    # This function returns intel data from OTX for a specific IP address
    intel = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
    return intel

def get_abuseipdb_intel(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": abuseipdb_api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": True
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json().get("data", {})
    else:
        return {}


def get_shodan_info(ip_address):
    shodan_api = shodan.Shodan(shodan_api_key)

    try:
        result = shodan_api.host(ip_address)
        return {
            'ip_str': result.get('ip_str'),
            'os': result.get('os'),
            'ports': result.get('ports'),
            'hostnames': result.get('hostnames'),
            'org': result.get('org'),
            'data': result.get('data')
        }
    except shodan.APIError as e:
        print(f"Error: {e}")
        return {}


def generate_report(intel_data):
    # Set up the prompt for GPT-4
    messages = [
        {"role": "system", "content": "You are a helpful assistant. Generate a threat intel summary paragraph with consistent style everytime with 3 paragraphs. don't leave out any information from the content unless it's empty. don't create situations or information that doesn't exist. just give out the facts only"},
        {"role": "user",
         "content": f" always mention which service or API gave you which information. make it easy to read and not long and also include everything but don't create any new situations. always start with, this ip is...:\n{json.dumps(intel_data)}\n"}
    ]

    # Use the chat completions API with GPT-4
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=messages
    )

    return response['choices'][0]['message']['content']


st.title('☠️ EnrichIP☠️ : ')

single_ip = st.text_input("Enter a single IP address to check threat intel: ")
uploaded_file = st.file_uploader("Or upload a CSV file", type=['csv'])
no_data_count = 0

if single_ip:
    intel_data = get_threat_intel(single_ip)
    report = generate_report(intel_data)
    st.subheader(f'Threat Intel for IP: {single_ip}')
    st.write(report)

elif uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    if 'IP' in df.columns:
        for ip in df['IP']:
            if is_valid_ip(ip):
                intel_data = get_threat_intel(ip)
                report = generate_report(intel_data)
                st.subheader(f'Threat Intel for IP: {ip}')
                st.write(report)
            else:
                st.write(f'{ip} is not a valid, routable IP address.')
    else:
        st.error("No 'IP' column in CSV file.")
