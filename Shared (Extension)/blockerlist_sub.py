import json

def extract_domains_with_subdomain(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    unique_domains = set()

    for line in lines:
        parts = line.strip().split(' ')
        if len(parts) == 2:
            ip, full_domain = parts
            domain_parts = full_domain.split('.')
            if len(domain_parts) >= 3:
                # Extract domain with one subdomain level (if exists) and the TLD
                subdomain_with_domain = '.'.join(domain_parts[-3:])
                unique_domains.add(subdomain_with_domain)
            elif len(domain_parts) == 2:
                # Just the domain and TLD
                domain_with_tld = '.'.join(domain_parts[-2:])
                unique_domains.add(domain_with_tld)

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
output_json_path = 'processed_blocker_list_sblack.json'  # Output file name

# Extract domains with subdomains and generate JSON
domains = extract_domains_with_subdomain(input_file_path)
generate_json(domains, output_json_path)

print(f"JSON file generated at {output_json_path}")
