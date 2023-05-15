import os
import json
import requests
import ipaddress
import openai
import streamlit as st
import pandas as pd
from apikey import openai_api_key, greynoise_api_key


api_key = greynoise_api_key
openai.api_key = openai_api_key
os.environ['OPENAI_API_KEY'] = openai.api_key


def is_valid_ip():
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
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = json.loads(response.text)
        # Extract specific fields
        intel = {
            'classification': data.get('classification'),
            'actor': data.get('actor'),
            'metadata': data.get('metadata'),
            'last_seen': data.get('last_seen'),
            'analysis': data.get('analysis'),
            'cve': data.get('cve')
        }
        return intel
    else:
        raise Exception(f"Error: {response.status_code}, {response.text}")



def filter_empty_values(data):
    filtered_data = {}
    for key, value in data.items():
        if value and value != '':
            filtered_data[key] = value
    return filtered_data


def generate_report(prompt):
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=prompt,
        max_tokens=300,
        n=1,
        stop=None,
        temperature=0,
    )

    return response.choices[0].text.strip()



# Application Framework
st.title('☠️ Threat ☠️ Information Finder: ')

single_ip = st.text_input("Enter a single IP address to check threat intel: ")
uploaded_file = st.file_uploader("Or upload a CSV file", type=['csv'])

# Counter for IPs with no data
no_data_count = 0

if single_ip:
    try:
        threat_intel = get_threat_intel(single_ip)
        if not any(threat_intel.values()):
            no_data_count += 1
        else:
            st.subheader(f'Threat Intel for IP: {single_ip}')
            with st.expander("See report"):
                formatted_intel = json.dumps(threat_intel, indent=2)
                prompt = f"Write a threat intel report for this paragraph:\n{formatted_intel}\n"
                report = generate_report(prompt)
                st.write("\nGenerated Threat Intel Report:\n", report)
    except Exception as e:
        st.write(e)

elif uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    if 'IP' in df.columns:
        for ip in df['IP']:
            if is_valid_ip():
                try:
                    threat_intel = get_threat_intel(ip)
                    if not any(threat_intel.values()):
                        no_data_count += 1
                    else:
                        st.subheader(f'Threat Intel for IP: {ip}')
                        with st.expander("See report"):
                            formatted_intel = json.dumps(threat_intel, indent=2)
                            prompt = f"Write a threat intel report for this paragraph:\n{formatted_intel}\n"
                            report = generate_report(prompt)
                            st.write("\nGenerated Threat Intel Report:\n", report)
                except Exception as e:
                    st.write(e)
            else:
                st.write(f'{ip} is not a valid, routable IP address.')
    else:
        st.error("No 'IP' column in CSV file.")

# Display the count of IPs with no data
st.write(f'Number of IPs with no data: {no_data_count}')
