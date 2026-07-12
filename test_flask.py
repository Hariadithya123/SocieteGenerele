import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app, state

if __name__ == "__main__":
    print("Initializing test client...")
    client = app.test_client()
    
    print("\n--- FIRST REQUEST ---")
    response = client.get('/')
    
    print("\n--- SECOND REQUEST ---")
    response = client.get('/')
