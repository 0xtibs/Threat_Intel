
<img width="616" alt="image" src="https://github.com/0xtibs/Threat_Intel/assets/81789402/7ee611cc-ef3f-4fd0-bea6-07477078bb37">





# Threat Information Finder

This application is a Streamlit-based web application that checks for available threat intelligence of IP addresses using GreyNoise and generates reports using OpenAI.

### Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

Prerequisites

    Python 3.6 or newer.
    Streamlit, pandas, requests, openai, and ipaddress Python libraries.
    GreyNoise and OpenAI API keys.

The required Python libraries can be installed via pip:

```pip install streamlit pandas requests openai ipaddress```

Please replace the placeholders in apikey.py with your actual GreyNoise and OpenAI API keys.
Installing

Clone the repository to your local machine:

```git clone https://github.com/0xtibs/Threat_Intel```

# API Keys

You will need an OpenAI and Greynoise account with API access. once you retrieve the APIs, please place them in the apikey.py script.

# Running the Application

Navigate to the directory containing the project files and run the following command:

```python3 -m streamlit run Main.py```

Usage

This Streamlit application allows you to enter a single IP address or upload a CSV file with a list of IP addresses. After you provide the IP addresses, the application will fetch threat intelligence for each IP address from the GreyNoise API, generate a report using OpenAI, and display the reports in the web interface.
Built With

    Python
    Streamlit
    GreyNoise
    OpenAI

    Thanks to GreyNoise and OpenAI for their powerful APIs.

