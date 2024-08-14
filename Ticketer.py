import requests
import json

API_KEY = "70a9822e-8056-4191-9da9-7996e5d00720"  
BASE_URL = "https://analyze.intezer.com"
NOTION_TOKEN = "secret_ydVuGN8pUIlB5wKD2ukCwUBfqkomvpaRB4Lg4Mr821H"  
DATABASE_ID = "c75c5d16e08a43d3b732ae99f878b17f"  
VIRUSTOTAL_API_KEY = "923c8341acacb45f1ec40affd83487f757c993065e439f2539b6befe9d2bbce1"

def get_access_token(api_key):
    url = f"{BASE_URL}/api/v2-0/get-access-token"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "api_key": api_key
    }
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        token = response.json().get('result')
        return token
    else:
        print(f"Failed to get access token: {response.status_code}")
        return None

def fetch_trending_threats():
    url = f"{BASE_URL}/user-trends/latest-analyses"
    response = requests.get(url)
    
    if response.status_code == 200:
        trending_threats = response.json()
        return trending_threats
    else:
        print(f"Failed to fetch trending threats: {response.status_code}")
        return None

def fetch_dynamic_ttps(analysis_id, token):
    url = f"{BASE_URL}/api/v2-0/analyses/{analysis_id}/dynamic-ttps"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch dynamic TTPs for analysis ID {analysis_id}: {response.status_code}")
        return None

def fetch_virustotal_detections(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch VirusTotal detections for SHA256 {sha256}: {response.status_code}")
        return None

def create_notion_page(family_name, analysis_id, sha256, vt_detections, original_file_name, gene_type, gene_count, diagnosis_first_seen):
    url = "https://api.notion.com/v1/pages"
    headers = {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28"
    }
    data = {
        "parent": {
            "database_id": DATABASE_ID
        },
        "cover": {
            "external": {
                "url": "https://nordvpn.com/wp-content/uploads/blog-featured-remove-malware-from-mac.svg"
            }
        },
        "properties": {
            "Name": {
                "title": [
                    {
                        "text": {
                            "content": family_name
                        }
                    }
                ]
            }
        },
        "children": [
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": "Tool and Analysis"
                            }
                        }
                    ]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": "Dynamic TTP Table",
                                "link": {
                                    "url": f"https://analyze.intezer.com/analyses/{analysis_id}/dynamic-ttps"
                                }
                            }
                        }
                    ]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": "Intezer Scan",
                                "link": {
                                    "url": f"https://analyze.intezer.com/analyses/{analysis_id}"
                                }
                            }
                        }
                    ]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": f"VirusTotal Scan, Score: {vt_detections['data']['attributes']['last_analysis_stats']['malicious']}",
                                "link": {
                                    "url": f"https://www.virustotal.com/gui/file/{sha256}"
                                }
                            }
                        }
                    ]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": f"file name: {original_file_name}, \nGene type: {gene_type} \nGene count {gene_count}\nFirst seen on {diagnosis_first_seen}"
                            }
                        }
                    ]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": "Have a safe day!"
                            }
                        }
                    ]
                }
            }
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        print("Notion page created successfully.")
    else:
        print(f"Failed to create Notion page: {response.status_code}")

trending_threats = fetch_trending_threats()

if trending_threats:
    print("Trending Threats Structure:", json.dumps(trending_threats, indent=4))
    token = get_access_token(API_KEY)
    if token:
        try:
            for threat in trending_threats['result']:  
                if threat['dynamic_ttps_count'] > 0:
                    analysis_id = threat['analysis_id']
                    sha256 = threat['sha256']
                    original_file_name = threat['original_file_name']
                    gene_type = threat['gene_type']
                    gene_count = threat['gene_count']
                    diagnosis_first_seen = threat['diagnosis_first_seen']

                    dynamic_ttps = fetch_dynamic_ttps(analysis_id, token)
                    vt_detections = fetch_virustotal_detections(sha256)
                    family_name = threat.get("family", "Unknown Family")
                    
                    if dynamic_ttps and vt_detections:
                        create_notion_page(family_name, analysis_id, sha256, vt_detections, original_file_name, gene_type, gene_count, diagnosis_first_seen)
        except KeyError as e:
            print(f"KeyError: {e} - Check the structure of the response.")
            print(json.dumps(trending_threats, indent=4))
    else:
        print("Failed to obtain access token.")
else:
    print("Unable to fetch trending threats.")
