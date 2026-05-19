#!/usr/bin/env python3
"""
Algono Outbound Calling Script
Uses Vapi API to make calls with Uncle Framework agent

Configuration (working IDs):
- Assistant ID: 39136214-e3d2-4862-9424-af5824a5ebba
- Phone Number ID: 35ba4e2d-fcf0-42b1-8985-60fa9ea328ae
- Caller ID: +18339374329
"""

import requests
import json
import sys
from pathlib import Path

# Configuration - WORKING IDs from successful test
VAPI_API_KEY = "5bbb70bc-10b0-41cb-8f16-168b5c7e4fc6"
VAPI_BASE_URL = "https://api.vapi.ai"
ASSISTANT_ID = "39136214-e3d2-4862-9424-af5824a5ebba"
PHONE_NUMBER_ID = "35ba4e2d-fcf0-42b1-8985-60fa9ea328ae"
CALLER_ID = "+18339374329"

headers = {
    "Authorization": f"Bearer {VAPI_API_KEY}",
    "Content-Type": "application/json"
}

def make_call(phone_number, company_name, contact_name):
    """Make outbound call to prospect"""
    
    # Clean phone number
    phone = phone_number.replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
    if not phone.startswith("+"):
        phone = "+1" + phone
    
    payload = {
        "assistantId": ASSISTANT_ID,
        "phoneNumberId": PHONE_NUMBER_ID,
        "customer": {
            "number": phone,
            "name": contact_name
        },
        "assistantOverrides": {
            "variableValues": {
                "company_name": company_name,
                "contact_name": contact_name
            }
        }
    }
    
    response = requests.post(f"{VAPI_BASE_URL}/call", headers=headers, json=payload)
    
    if response.status_code in [200, 201]:
        call_data = response.json()
        print(f"✅ Call initiated successfully!")
        print(f"   Call ID: {call_data.get('id')}")
        print(f"   Status: {call_data.get('status')}")
        print(f"   To: {contact_name} at {phone_number}")
        return True
    else:
        print(f"❌ Error making call: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def call_venture_general():
    """Call first prospect: Venture General Contracting"""
    print("\n=== Calling Venture General Contracting ===")
    print("Ask for: Steve Schuler (IT Manager)")
    return make_call(
        phone_number="206-582-4500",
        company_name="Venture General Contracting",
        contact_name="Steve Schuler"
    )

def call_test():
    """Test call to user's mobile"""
    print("\n=== Making Test Call ===")
    return make_call(
        phone_number="+16462426842",
        company_name="Test",
        contact_name="User"
    )

def call_from_prospects_json(index=0):
    """Call prospect from prospects.json by index"""
    prospects_path = Path(__file__).parent.parent / "prospecting" / "prospects.json"
    
    with open(prospects_path) as f:
        prospects = json.load(f)
    
    if index >= len(prospects):
        print(f"Invalid prospect index. Found {len(prospects)} prospects.")
        return False
    
    p = prospects[index]
    phone = p.get("phone")
    
    if not phone:
        print(f"❌ No phone number for {p['company_name']}")
        return False
    
    print(f"\n=== Calling {p['company_name']} ===")
    print(f"Ask for: {p.get('contact_name', 'IT Manager')}")
    return make_call(
        phone_number=phone,
        company_name=p['company_name'],
        contact_name=p.get('contact_name', 'IT Manager')
    )

def main():
    """Main entry point"""
    print("=" * 60)
    print("Algono Outbound Calling System")
    print("=" * 60)
    print(f"Caller ID: {CALLER_ID}")
    print(f"Assistant: {ASSISTANT_ID[:8]}...")
    print(f"Phone Number ID: {PHONE_NUMBER_ID[:8]}...")
    print()
    print("Uncle Framework Opening:")
    print('"This is Algono. We audit IT access for businesses with fifty to')
    print('five hundred employees. Do you handle IT security there?"')
    print()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "venture":
            call_venture_general()
        elif sys.argv[1] == "test":
            call_test()
        elif sys.argv[1] == "prospect" and len(sys.argv) > 2:
            call_from_prospects_json(int(sys.argv[2]))
        else:
            print("\nUsage:")
            print("  python make_call.py venture      # Call Venture General")
            print("  python make_call.py test         # Test call your mobile")
            print("  python make_call.py prospect 0   # Call first prospect")
    else:
        print("\n📋 Available commands:")
        print("  python make_call.py venture")
        print("  python make_call.py test")
        print("  python make_call.py prospect 0")

if __name__ == "__main__":
    main()
