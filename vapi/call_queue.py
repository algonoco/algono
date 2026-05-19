#!/usr/bin/env python3
"""
Algono Call Queue System
Manages 2-concurrency limit for Vapi outbound calls
Keeps pipeline full until all prospects contacted
"""

import json
import time
import requests
from datetime import datetime
from pathlib import Path

VAPI_API_KEY = "5bbb70bc-10b0-41cb-8f16-168b5c7e4fc6"
VAPI_BASE_URL = "https://api.vapi.ai"
ASSISTANT_ID = "39136214-e3d2-4862-9424-af5824a5ebba"
PHONE_NUMBER_ID = "35ba4e2d-fcf0-42b1-8985-60fa9ea328ae"

HEADERS = {
    "Authorization": f"Bearer {VAPI_API_KEY}",
    "Content-Type": "application/json"
}

class CallQueue:
    def __init__(self):
        self.prospects = []
        self.active_calls = {}  # call_id -> prospect_info
        self.completed_calls = []
        self.load_prospects()
        
    def load_prospects(self):
        """Load all prospects from both batches"""
        base_path = Path(__file__).parent.parent / "prospecting"
        
        # Load batch 1 (raw list format)
        try:
            with open(base_path / "prospects.json") as f:
                batch1 = json.load(f)
                # Handle both list and dict formats
                if isinstance(batch1, list):
                    prospects_list = batch1
                else:
                    prospects_list = batch1.get("prospects", [])
                
                for p in prospects_list:
                    p["batch"] = 1
                    self.prospects.append(p)
        except Exception as e:
            print(f"⚠️ Error loading batch 1: {e}")
        
        # Load batch 2 (dict format with 'prospects' key)
        try:
            with open(base_path / "algono_prospects_batch_2.json") as f:
                batch2 = json.load(f)
                for p in batch2.get("prospects", []):
                    p["batch"] = 2
                    self.prospects.append(p)
        except Exception as e:
            print(f"⚠️ Error loading batch 2: {e}")
        
        # Filter to only call prospects with phone numbers
        self.prospects = [p for p in self.prospects if p.get("phone")]
        print(f"✅ Loaded {len(self.prospects)} prospects")
        
    def get_pending_prospects(self):
        """Get prospects not yet called"""
        called = {c["prospect"]["name"] for c in self.completed_calls}
        called.update({info["prospect"]["name"] for info in self.active_calls.values()})
        return [p for p in self.prospects if p["name"] not in called]
    
    def make_call(self, prospect):
        """Initiate a call to a prospect"""
        payload = {
            "assistantId": ASSISTANT_ID,
            "phoneNumberId": PHONE_NUMBER_ID,
            "customer": {
                "number": prospect["phone"],
                "name": prospect["contact"]["name"]
            }
        }
        
        try:
            response = requests.post(
                f"{VAPI_BASE_URL}/call",
                headers=HEADERS,
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                call_id = data.get("id")
                self.active_calls[call_id] = {
                    "prospect": prospect,
                    "started_at": datetime.now().isoformat(),
                    "status": "queued"
                }
                print(f"📞 Call {call_id} to {prospect['name']} ({prospect['phone']}) - {prospect['contact']['title']}")
                return call_id
            else:
                print(f"❌ Failed to call {prospect['name']}: {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ Error calling {prospect['name']}: {e}")
            return None
    
    def check_call_status(self, call_id):
        """Check status of an active call"""
        try:
            response = requests.get(
                f"{VAPI_BASE_URL}/call/{call_id}",
                headers=HEADERS,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get("status")
                
                if status in ["ended", "failed", "canceled"]:
                    # Call completed
                    info = self.active_calls.pop(call_id)
                    info["ended_at"] = datetime.now().isoformat()
                    info["final_status"] = status
                    info["duration"] = data.get("duration", 0)
                    self.completed_calls.append(info)
                    
                    print(f"✅ Call {call_id} completed - {info['prospect']['name']} ({status})")
                    return True
                else:
                    self.active_calls[call_id]["status"] = status
                    return False
            return False
        except Exception as e:
            print(f"⚠️ Error checking {call_id}: {e}")
            return False
    
    def print_status(self):
        """Print current queue status"""
        pending = len(self.get_pending_prospects())
        active = len(self.active_calls)
        completed = len(self.completed_calls)
        total = len(self.prospects)
        
        print(f"\n{'='*60}")
        print(f"QUEUE STATUS")
        print(f"{'='*60}")
        print(f"Pending:    {pending}/{total}")
        print(f"Active:     {active}/2")
        print(f"Completed:  {completed}/{total}")
        print(f"{'='*60}\n")
    
    def run(self):
        """Main loop - keep 2 calls active until all prospects contacted"""
        print("=" * 60)
        print("ALGONO CALL QUEUE SYSTEM")
        print("2-Concurrency Management")
        print("=" * 60)
        print()
        
        try:
            while True:
                # Check current active calls
                completed_now = []
                for call_id in list(self.active_calls.keys()):
                    if self.check_call_status(call_id):
                        completed_now.append(call_id)
                
                # Get pending prospects
                pending = self.get_pending_prospects()
                
                # Print status
                self.print_status()
                
                # Fill up to 2 concurrent calls
                while len(self.active_calls) < 2 and pending:
                    prospect = pending.pop(0)
                    self.make_call(prospect)
                    time.sleep(2)  # Brief delay between calls
                
                # Check if complete
                if not pending and not self.active_calls:
                    print("\n🎉 ALL PROSPECTS CONTACTED!")
                    break
                
                # Wait before next check
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\n\n⚠️ Queue stopped by user")
            self.print_status()

if __name__ == "__main__":
    queue = CallQueue()
    queue.run()
