import json

import requests

from config import get_config

config = get_config()


class XSOARAPIError(Exception):
    """Custom exception for XSOAR API errors"""
    pass


def check_response(response, operation):
    """Check if response is valid and return JSON data"""
    try:
        if 'text/html' in response.headers.get('Content-Type', ''):
            raise XSOARAPIError(f"Received HTML instead of JSON. This usually indicates an authentication error or incorrect endpoint.\nStatus code: {response.status_code}\nResponse preview: {response.text[:200]}...")

        if response.status_code == 401:
            raise XSOARAPIError("Authentication failed. Please check your auth tokens.")

        if not 200 <= response.status_code < 300:
            raise XSOARAPIError(f"{operation} failed with status code {response.status_code} : {response.text}")

        return response.json()
    except json.JSONDecodeError:
        raise XSOARAPIError(f"Failed to decode JSON response for {operation}. Response: {response.text[:200]}...")


def get_incident(base_url, incident_id, auth_id, auth_key):
    """Fetch incident details from source environment"""
    headers = {
        'Accept': 'application/json',
        'authorization': auth_key,
        'x-xdr-auth-id': auth_id
    }

    try:
        incident_url = f"{base_url}/xsoar/public/v1/incident/load/{incident_id}"
        # print(f"Fetching incident from: {incident_url}")
        response = requests.get(
            incident_url,
            headers=headers,
            verify=False,  # Note: Only for testing. Use proper cert verification in production
            timeout=30
        )
        return check_response(response, "Get incident")

    except requests.exceptions.RequestException as e:
        raise XSOARAPIError(f"Network error while fetching incident: {str(e)}")


def create_incident(base_url, incident_data, auth_id, auth_key):
    """Create incident in target environment"""
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'authorization': auth_key,
        'x-xdr-auth-id': auth_id
    }

    try:
        create_url = f"{base_url}/xsoar/public/v1/incident"
        payload = {
            "details": incident_data.get('details', 'Details not found'),
            "name": incident_data.get('name', 'Name not found'),
            "severity": incident_data.get('severity', 1),
            "type": incident_data.get('type', f'{config.ticket_type_prefix} Case'),
            "CustomFields": {
                'detectionsource': incident_data.get('CustomFields', {}).get('detectionsource', 'Unknown'),
                'securitycategory': incident_data.get('CustomFields', {}).get('securitycategory', 'Unknown'),
                'qradareventid': incident_data.get('CustomFields', {}).get('qradareventid', 'Unknown'),
            },
            "all": True,
            "createInvestigation": True,
            "data": incident_data,
            "force": True,
        }

        response = requests.post(
            create_url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        # print("Create Incident Response: ", response.json())
        return check_response(response, "Create incident")

    except requests.exceptions.RequestException as e:
        raise XSOARAPIError(f"Network error while creating incident: {str(e)}")


def transfer_incident(source_url, target_url, incident_id, source_auth, target_auth):
    """Main function to transfer incident between environments"""
    try:
        # Get incident from source
        # print(f"Fetching incident {incident_id} from source environment...")
        incident_data = get_incident(
            source_url,
            incident_id,
            auth_id=source_auth['auth_id'],
            auth_key=source_auth['auth_key']
        )

        # print("Successfully retrieved incident data")

        # Create incident in target
        # print("Creating incident in target environment...")
        new_incident = create_incident(
            target_url,
            incident_data,
            auth_id=target_auth['auth_id'],
            auth_key=target_auth['auth_key']
        )

        return {
            'status': 'success',
            'source_incident_id': incident_id,
            'target_incident_id': new_incident.get('id'),
            'message': 'Incident transferred successfully'
        }

    except XSOARAPIError as e:
        return {
            'status': 'error',
            'error_type': 'API_ERROR',
            'message': str(e)
        }
    except Exception as e:
        return {
            'status': 'error',
            'error_type': 'UNEXPECTED_ERROR',
            'message': f"Unexpected error: {str(e)}"
        }


def import_ticket(source_ticket_number):
    # Configuration
    source_env = {
        'url': 'https://api-msoar.crtx.us.paloaltonetworks.com',
        'auth': {
            'auth_id': '25',
            'auth_key': 'OP2JKkAze7xIW6ca4YnYhpvkqFQTzD8L2AOnTLZ8IoeTOPuyzvDxuStSfuxQLoZkm4sjRNLvT4nfPialwnDgdBY986o1ps8wV5EZfD0gRulObNPAd3uRBr0LfSITkKBe',
        }
    }

    target_env = {
        'url': 'https://api-msoardev.crtx.us.paloaltonetworks.com',
        'auth': {
            'auth_id': '66',
            'auth_key': 'bumyL61MBpjgMiZ2AoYsqyShcRnBUm9LwIYII7nCQZkNXGMAc5QPYov3tis9IDmHhOugMQnDP7Z0IB8REERT1vHqUSAtNm0WcU5jNM9ssHOGBEFkjmwRj3CKuxfbRzz7'
        }
    }

    result = transfer_incident(
        source_env['url'],
        target_env['url'],
        source_ticket_number,
        source_env['auth'],
        target_env['auth']
    )

    destination_ticket_number = result.get('target_incident_id')
    return destination_ticket_number, f'https://msoardev.crtx.us.paloaltonetworks.com/Custom/caseinfoid/{destination_ticket_number}'


if __name__ == "__main__":
    ticket_number = "538806"
    destination_ticket_number, destination_ticket_link = import_ticket(ticket_number)
    print(f"Ticket {ticket_number} transferred to {destination_ticket_number}. Link: {destination_ticket_link}")
