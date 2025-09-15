#!/usr/bin/env python3
"""
Script to fetch GraphQL schema from Tanium API
"""
import json

import requests

from my_config import get_config

# GraphQL introspection query
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


def fetch_schema():
    """Fetch GraphQL schema from Tanium API"""

    # Get credentials from config
    config = get_config()
    token = config.tanium_cloud_api_token
    base_url = config.tanium_cloud_api_url
    url = f"{base_url}/plugin/products/gateway/graphql"

    if not token:
        print("Error: TANIUM_CLOUD_API_TOKEN not found in configuration")
        return None

    headers = {
        'session': token,
        'Content-Type': 'application/json'
    }

    payload = {
        'query': INTROSPECTION_QUERY
    }

    try:
        print(f"Fetching schema from: {url}")
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()

        schema_data = response.json()

        # Save schema to file
        import os
        output_file = os.path.join(os.path.dirname(__file__), '..', 'transient', 'tanium_schema.json')
        with open(output_file, 'w') as f:
            json.dump(schema_data, f, indent=2)

        print(f"Schema saved to: {output_file}")

        # Print summary
        if 'data' in schema_data and '__schema' in schema_data['data']:
            types = schema_data['data']['__schema']['types']
            query_type = schema_data['data']['__schema']['queryType']['name']
            mutation_type = schema_data['data']['__schema'].get('mutationType', {})
            mutation_name = mutation_type.get('name') if mutation_type else 'None'

            print(f"\nSchema Summary:")
            print(f"- Total types: {len(types)}")
            print(f"- Query type: {query_type}")
            print(f"- Mutation type: {mutation_name}")

            # Show available queries and mutations
            for type_def in types:
                if type_def['name'] == query_type:
                    queries = [field['name'] for field in type_def.get('fields', [])]
                    print(f"- Available queries: {len(queries)}")
                    if queries:
                        print(f"  Examples: {', '.join(queries[:5])}")

                if mutation_type and type_def['name'] == mutation_name:
                    mutations = [field['name'] for field in type_def.get('fields', [])]
                    print(f"- Available mutations: {len(mutations)}")
                    if mutations:
                        print(f"  Examples: {', '.join(mutations[:5])}")

        return schema_data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching schema: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Response: {e.response.text}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


if __name__ == "__main__":
    fetch_schema()
