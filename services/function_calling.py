import json

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


def setup_llama2():
    # Load Llama-2-7b or similar variant
    model = AutoModelForCausalLM.from_pretrained(
        "meta-llama/Llama-2-7b-hf",
        torch_dtype=torch.float16,
        device_map="auto"
    )
    tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-hf")
    return model, tokenizer


def create_function_schema():
    # Define the schema for weather function
    schema = {
        "name": "get_weather",
        "description": "Get the current weather for a location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City and state/country"
                },
                "unit": {
                    "type": "string",
                    "enum": ["celsius", "fahrenheit"],
                    "description": "Temperature unit"
                }
            },
            "required": ["location"]
        }
    }
    return schema


def generate_function_call(model, tokenizer, user_input, schema):
    # Create prompt that instructs the model to generate a function call
    prompt = f"""Given the following function schema:
{json.dumps(schema, indent=2)}

User input: {user_input}

Generate a JSON function call that matches the schema. Response should be valid JSON like:
{{"name": "function_name", "arguments": {{"param1": "value1"}}}}

Function call:"""

    # Generate response
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    outputs = model.generate(
        inputs.input_ids,
        max_new_tokens=100,
        temperature=0.1,
        pad_token_id=tokenizer.eos_token_id
    )
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)

    # Extract just the JSON part
    try:
        response = response.split("Function call:")[-1].strip()
        function_call = json.loads(response)
        return function_call
    except json.JSONDecodeError:
        return {"error": "Failed to generate valid JSON"}


# Example usage
def main():
    model, tokenizer = setup_llama2()
    schema = create_function_schema()

    # Test with sample user input
    user_input = "What's the weather like in San Francisco?"
    result = generate_function_call(model, tokenizer, user_input, schema)
    print(f"User input: {user_input}")
    print(f"Function call: {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    main()
