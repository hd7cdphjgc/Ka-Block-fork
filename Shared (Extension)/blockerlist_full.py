import json

def extract_full_domains(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    unique_domains = set()

    for line in lines:
        parts = line.strip().split(' ')
        if len(parts) == 2:
            ip, full_domain = parts
            unique_domains.add(full_domain)

    return list(unique_domains)

def generate_json(domain_list, output_file):
    json_data = []

    for domain in domain_list:
        # Escaping dots for regex
        escaped_domain = domain.replace('.', '\\.')
        rule = {
            "trigger": {
                "url-filter": f"^https?://+([^/:]+\\.)?{escaped_domain}[:/]",
                "url-filter-is-case-sensitive": True,
                "load-type": ["third-party", "first-party"]
            },
            "action": {
                "type": "block"
            }
        }
        json_data.append(rule)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

# Example usage
input_file_path = 'sblack.txt'  # Replace with the path to your text file
output_json_path = 'processed_blocker_list_full_domain.json'  # Output file name

# Extract full domains and generate JSON
domains = extract_full_domains(input_file_path)
generate_json(domains, output_json_path)

print(f"JSON file generated at {output_json_path}")
