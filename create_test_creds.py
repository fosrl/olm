
import requests

def create_olm(base_url, user_token, olm_name, user_id):
    url = f"{base_url}/api/v1/user/{user_id}/olm"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "pangolin-cli",
        "X-CSRF-Token": "x-csrf-protection",
        "Cookie": f"p_session_token={user_token}"
    }
    payload = {"name": olm_name}
    response = requests.put(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    print(f"Response Data: {data}")

def create_client(base_url, user_token, client_name):
    url = f"{base_url}/api/v1/api/clients"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "pangolin-cli",
        "X-CSRF-Token": "x-csrf-protection",
        "Cookie": f"p_session_token={user_token}"
    }
    payload = {"name": client_name}
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    print(f"Response Data: {data}")

if __name__ == "__main__":
    # Example usage
    base_url = input("Enter base URL (e.g., http://localhost:3000): ")
    user_token = input("Enter user token: ")
    user_id = input("Enter user ID: ")
    olm_name = input("Enter OLM name: ")
    client_name = input("Enter client name: ")

    create_olm(base_url, user_token, olm_name, user_id)
    # client_id = create_client(base_url, user_token, client_name)