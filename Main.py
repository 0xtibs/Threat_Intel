import requests
import json
import openai

# Replace with your GreyNoise API key
api_key = ''

# Replace with your OpenAI API key
openai.api_key = ''

def get_threat_intel(ip_address):
    headers = {
        'Accept': 'application/json',
        'key': api_key,
    }
    url = f'https://api.greynoise.io/v2/noise/context/{ip_address}'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return json.loads(response.text)
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
        max_tokens=150,
        n=1,
        stop=None,
        temperature=0.7,
    )

    return response.choices[0].text.strip()

if __name__ == '__main__':
    ip = input("Enter an IP address to check threat intel: ")
    try:
        threat_intel = get_threat_intel(ip)
        filtered_intel = filter_empty_values(threat_intel)
        formatted_intel = json.dumps(filtered_intel, indent=2)
        print("Filtered Threat Intel:\n", formatted_intel)
        
        prompt = f"Write a threat intel report for this in a paragraph way:\n{formatted_intel}\n"
        report = generate_report(prompt)
        print("\nGenerated Threat Intel Report:\n", report)
    except Exception as e:
        print(e)

