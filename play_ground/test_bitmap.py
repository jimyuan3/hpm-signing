import json

# Load the JSON data into a Python dictionary
with open('file.json', 'r') as f:
    data = json.load(f)


# Get the values of each key in ImageCapabilities
values = [bin(int(data['ImageCapabilities'][key]['value'], 16))[2:] for key in data['ImageCapabilities']]

print(values)

# Concatenate the binary strings and convert to an integer
byte = int(''.join(values), 2)

print(byte)  # For '1011', Output: 11
