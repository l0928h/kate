# nuclei_parser.py
# v1.1

import re
import argparse
import os
from datetime import datetime
from urllib.parse import urlparse
import csv

def parse_log(file_path):
    targets = [
        "Shopify", "Wix", "Squarespace", "Webflow", "Weebly",
        "Blogger", "Bitrix", "Duda", "Jimdo", "HubSpot CMS", "Adobe Experience Manager", "Contao",
        "ExpressionEngine", "phpMyAdmin", "cPanel", "VestaCP", "Webmin", "ISPConfig", "CentOS Web Panel",
        "Joomla", "Drupal", "WordPress"
    ]
    results = {target: [] for target in targets}

    with open(file_path, 'r') as file:
        for line in file:
            for target in targets:
                # Match CMS lines, e.g., "[wordpress-detect]"
                if f"[{target.lower()}-detect" in line.lower():
                    url_match = re.search(r'https?://\S+', line)
                    if url_match:
                        url = url_match.group()
                        # Normalize to base URL for Joomla and Drupal
                        if target.lower() in ["joomla", "drupal", "wordpress"]:
                            parsed_url = urlparse(url)
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            results[target].append(base_url)
                        else:
                            results[target].append(url)
    return results

def find_no_cms_domains(raw_domains_file, cms_results):
    with open(raw_domains_file, 'r') as file:
        raw_domains = set(line.strip() for line in file if line.strip())

    detected_domains = set()
    for urls in cms_results.values():
        detected_domains.update(urls)

    normalized_detected_domains = set(urlparse(url).netloc for url in detected_domains)
    no_cms_domains = raw_domains - normalized_detected_domains
    return no_cms_domains

def save_no_cms_domains(no_cms_domains, output_dir):
    no_cms_file = os.path.join(output_dir, "no_cms.txt")
    with open(no_cms_file, 'w') as file:
        for domain in sorted(no_cms_domains):
            file.write(f"{domain}\n")
    print(f"Domains with no CMS detected have been saved to: {no_cms_file}")

def save_results(results):
    unique_dir = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(unique_dir, exist_ok=True)

    cms_detected = False  # Track if any CMS is detected

    for target, urls in results.items():
        if urls:
            cms_detected = True
            output_file = os.path.join(unique_dir, f"{target.replace(' ', '_')}.txt")
            with open(output_file, 'w') as file:
                for url in urls:
                    file.write(f"{url}\n")
            print(f"Results for {target} have been saved to: {output_file}")

    if not cms_detected:
        print("No CMS results were detected in the input log.")

    return unique_dir

def save_summary_csv(results, no_cms_domains, output_dir):
    summary_file = os.path.join(output_dir, "summary.csv")
    with open(summary_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Domain", "CMS"])

        # Write detected CMS domains
        for cms, urls in results.items():
            for url in urls:
                domain = urlparse(url).netloc
                csvwriter.writerow([domain, cms])

        # Write no CMS domains
        for domain in sorted(no_cms_domains):
            csvwriter.writerow([domain, "nocms"])

    print(f"Summary CSV has been saved to: {summary_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Parse log files to extract URLs associated with specific CMS/tools, and compare with a full domain list.",
        epilog="\nExample:\n  python nuclei_cms_parser.py logs/nuclei_output_log.txt --raw-domains domains_list.txt\n\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "file_path",
        type=str,
        help="Path to the log file, must be a plain text file, e.g., logs/nuclei_output_log.txt."
    )
    parser.add_argument(
        "--raw-domains",
        type=str,
        required=True,
        help="Path to the file containing the list of all original domains."
    )

    args = parser.parse_args()

    results = parse_log(args.file_path)
    output_dir = save_results(results)
    no_cms_domains = find_no_cms_domains(args.raw_domains, results)
    save_no_cms_domains(no_cms_domains, output_dir)
    save_summary_csv(results, no_cms_domains, output_dir)

if __name__ == "__main__":
    main()








