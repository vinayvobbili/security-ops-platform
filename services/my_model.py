from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferMemory
import requests
import json


# Define your API functions as tools
@tool
def call_api_endpoint(endpoint: str, method: str = "GET", params: dict = None) -> str:
    """Make API calls to various endpoints

    Args:
        endpoint: The API endpoint URL
        method: HTTP method (GET, POST, etc.)
        params: Parameters to send with the request
    """
    try:
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Python-Agent'}

        print(f"Making {method} request to: {endpoint}")

        if method.upper() == "GET":
            response = requests.get(endpoint, params=params, headers=headers, timeout=10)
        elif method.upper() == "POST":
            response = requests.post(endpoint, json=params, headers=headers, timeout=10)
        elif method.upper() == "PUT":
            response = requests.put(endpoint, json=params, headers=headers, timeout=10)
        elif method.upper() == "DELETE":
            response = requests.delete(endpoint, headers=headers, timeout=10)
        else:
            return f"Unsupported HTTP method: {method}"

        result = f"Status Code: {response.status_code}\n"
        try:
            json_data = response.json()
            result += f"JSON Response: {json.dumps(json_data, indent=2)[:800]}..."
        except:
            result += f"Text Response: {response.text[:500]}..."

        return result

    except requests.exceptions.RequestException as e:
        return f"Network error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def get_weather_info(city: str) -> str:
    """Get weather information for a specific city

    Args:
        city: Name of the city to get weather for
    """
    weather_data = {
        "san francisco": "Sunny, 68°F, light breeze from the west",
        "new york": "Cloudy, 45°F, chance of rain later",
        "london": "Rainy, 52°F, heavy clouds and drizzle",
        "tokyo": "Clear, 72°F, humid with light winds"
    }

    city_lower = city.lower()
    if city_lower in weather_data:
        return f"Current weather in {city}: {weather_data[city_lower]}"
    else:
        return f"Weather data not available for {city}. I have data for: {', '.join(weather_data.keys())}"


@tool
def calculate_math(expression: str) -> str:
    """Calculate basic math expressions safely

    Args:
        expression: Math expression like '2 + 3 * 4' or '(10 + 5) / 3'
    """
    try:
        # Safety check for allowed characters
        allowed_chars = set('0123456789+-*/.() ')
        if not all(c in allowed_chars for c in expression.replace(' ', '')):
            return "Error: Only basic math operations (+, -, *, /, parentheses) and numbers are allowed"

        result = eval(expression)
        return f"Calculation: {expression} = {result}"
    except ZeroDivisionError:
        return "Error: Division by zero"
    except Exception as e:
        return f"Math error: {str(e)}"


# Simple function calling without complex agents
def simple_function_caller(user_input: str, llm, tools):
    """Simple function calling approach that works better with smaller models"""

    # Create tool descriptions
    tool_descriptions = []
    for tool in tools:
        tool_descriptions.append(f"- {tool.name}: {tool.description}")

    tools_text = "\n".join(tool_descriptions)

    prompt = f"""You are a helpful assistant with access to these tools:

{tools_text}

User question: {user_input}

If you need to use a tool, just name the tool and its parameters naturally.

Response:"""

    response = llm.invoke(prompt)
    response_text = response.content if hasattr(response, 'content') else str(response)

    print(f"Model response: {response_text}")

    # Parse for tool usage - handle the model's natural format
    response_lower = response_text.lower()

    # Check for tool usage patterns
    if any(tool.name in response_lower for tool in tools):
        try:
            # Parse different formats the model might use
            if "get_weather_info" in response_lower:
                # Extract city from various formats
                if 'city=' in response_text:
                    city = response_text.split('city=')[1].split('"')[1] if '"' in response_text.split('city=')[1] else response_text.split('city=')[1].split()[0]
                    print(f"Executing get_weather_info with city: {city}")
                    result = get_weather_info.invoke({"city": city})
                    return f"Weather info: {result}"

            elif "calculate_math" in response_lower:
                # Extract expression from various formats
                expr = None
                if 'expression=' in response_text:
                    expr = response_text.split('expression=')[1].split('"')[1] if '"' in response_text.split('expression=')[1] else response_text.split('expression=')[1].strip()
                elif "'" in response_text and any(op in response_text for op in ['+', '-', '*', '/']):
                    # Extract from quotes like '15 * 7 + 23'
                    import re
                    expr_match = re.search(r"'([^']*[+\-*/][^']*)'", response_text)
                    if expr_match:
                        expr = expr_match.group(1)

                if expr:
                    print(f"Executing calculate_math with expression: {expr}")
                    result = calculate_math.invoke({"expression": expr})
                    return f"Math result: {result}"

            elif "call_api_endpoint" in response_lower:
                # Extract endpoint and method
                endpoint = None
                method = "GET"

                lines = response_text.split('\n')
                for line in lines:
                    if 'http' in line.lower():
                        # Extract URL
                        import re
                        url_match = re.search(r'https?://[^\s]+', line)
                        if url_match:
                            endpoint = url_match.group()
                    if 'method' in line.lower():
                        if 'post' in line.lower():
                            method = "POST"
                        elif 'put' in line.lower():
                            method = "PUT"
                        elif 'delete' in line.lower():
                            method = "DELETE"

                if endpoint:
                    # Clean up endpoint (remove extra quotes)
                    endpoint = endpoint.replace('"', '').replace(',', '')
                    print(f"Executing call_api_endpoint with endpoint: {endpoint}, method: {method}")
                    result = call_api_endpoint.invoke({"endpoint": endpoint, "method": method})
                    return f"API result: {result}"
                else:
                    return "Could not extract API endpoint from response"

        except Exception as e:
            print(f"Tool parsing error: {e}")
            return response_text

    return response_text


# Initialize the model
print("Initializing Llama 3.2 model...")
llm = ChatOllama(
    model="llama3.2:latest",
    temperature=0.1
)

# Setup tools
tools = [call_api_endpoint, get_weather_info, calculate_math]

# Test the setup
if __name__ == "__main__":
    print("Testing simple function calling...")

    test_cases = [
        "What's the weather like in San Francisco?",
        "Calculate 15 * 7 + 23",
        "Make a GET request to https://httpbin.org/json",
        "What's 2 + 2?",  # Should not need a tool
    ]

    for i, test_input in enumerate(test_cases, 1):
        print(f"\n{'=' * 60}")
        print(f"Test {i}: {test_input}")
        print('=' * 60)

        try:
            result = simple_function_caller(test_input, llm, tools)
            print(f"Final Result: {result}")
        except Exception as e:
            print(f"Error in test {i}: {e}")

    print(f"\n{'=' * 60}")
    print("Function calling tests complete!")
    print('=' * 60)
