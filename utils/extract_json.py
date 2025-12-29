import re
import json

def normalize_attributes(attributes):
    """Normalize attributes to have consistent format"""
    normalized = []
    seen_keys = {}

    for attr in attributes:
        if not attr or ":" not in attr:
            continue

        key, value = attr.split(":", 1)
        key = key.strip()
        value = value.strip()

        # Normalize volume units
        if key == "volume":
            # Remove ALL spaces and convert units
            value = re.sub(r'\s+', '', value)  # Remove all spaces
            # Convert to lowercase
            value = value.replace('ML', 'ml').replace('มล.', 'ml').replace('G', 'g')

        # Normalize PA values (remove extra spaces)
        if key == "pa":
            value = re.sub(r'PA\s+', 'PA', value)

        # Store normalized attribute
        normalized_attr = f"{key}: {value}"

        # Track unique keys to avoid duplicates
        if key not in seen_keys:
            seen_keys[key] = []

        # Add only if not duplicate
        if value not in seen_keys[key]:
            seen_keys[key].append(value)
            normalized.append(normalized_attr)

    return normalized

def extract_json(text):
    """Extract and normalize JSON from text response"""
    # Try to find JSON in code blocks (both array and object)
    pattern_array = r"```(?:json)?\s*(\[.*?\])\s*```"
    pattern_object = r"```(?:json)?\s*(\{.*?\})\s*```"

    match = re.search(pattern_array, text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        match = re.search(pattern_object, text, re.DOTALL)
        if match:
            json_str = match.group(1)
        elif text.strip().startswith("[") or text.strip().startswith("{"):
            json_str = text.strip()
        else:
            return None

    try:
        # Parse JSON
        data = json.loads(json_str)

        # Normalize attributes in each item
        if isinstance(data, list):
            for item in data:
                if "attributes" in item and isinstance(item["attributes"], list):
                    item["attributes"] = normalize_attributes(item["attributes"])
        elif isinstance(data, dict):
            if "attributes" in data and isinstance(data["attributes"], list):
                data["attributes"] = normalize_attributes(data["attributes"])

        # Return normalized JSON string
        return json.dumps(data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        # If parsing fails, return original string
        return json_str
    

    