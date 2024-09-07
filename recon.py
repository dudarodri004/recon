import subprocess
import os

# SecurityTrails API Key
SECURITY_TRAILS_API_KEY = '5TWkBXVdf-1JO9JbiiLB0kSaOJGi6-D9'

# Utility function to run a shell command and print output in real-time
def run_command(command, description):
    print(f"[INFO] {description}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Print stdout and stderr line by line
    for stdout_line in iter(process.stdout.readline, ""):
        print(stdout_line, end="")  # Print stdout
    for stderr_line in iter(process.stderr.readline, ""):
        print(stderr_line, end="")  # Print stderr
    
    process.stdout.close()
    process.stderr.close()
    return_code = process.wait()
    
    if return_code != 0:
        print(f"[ERROR] Command '{command}' failed with return code {return_code}\n")
    else:
        print(f"[INFO] Command '{command}' executed successfully\n")
    
    return return_code

def main(domain):
    # Create a directory for storing results
    os.makedirs(domain, exist_ok=True)
    
    # Step 1: Subdomain Enumeration with assetfinder
    assetfinder_output = f"{domain}/assetfinder.txt"
    run_command(f"assetfinder --subs-only {domain} > {assetfinder_output}", "Running assetfinder for subdomain enumeration")
    
    # Step 2: Subdomain Enumeration with subfinder
    subfinder_output = f"{domain}/subfinder.txt"
    run_command(f"subfinder -d {domain} -o {subfinder_output}", "Running subfinder for subdomain enumeration")
    
    # Combine results from assetfinder, subfinder, and SecurityTrails using anew
    combined_subdomains = f"{domain}/combined_subdomains.txt"
    run_command(f"cat {assetfinder_output} {subfinder_output} | anew {combined_subdomains}", "Combining subdomains from assetfinder and subfinder using anew")

    # Step 4: Subdomain Permutations with ripgen
    ripgen_output = f"{domain}/ripgen.txt"
    run_command(f"ripgen -d {combined_subdomains} > {ripgen_output}", "Running ripgen for subdomain permutations")
    
    # Combine all subdomain results using anew
    all_subdomains = f"{domain}/all_subdomains.txt"
    run_command(f"cat {ripgen_output} | anew {all_subdomains}", "Combining all subdomains using anew")

    # Step 5: Grab A records with dnsx
    dnsx_output = f"{domain}/dnsx_output.txt"
    run_command(f"cat {all_subdomains} | dnsx -a -resp-only -o {dnsx_output}", "Running dnsx to grab A records")
    
    # Step 6: Remove IPs pointing to CDNs
    non_cdn_ips = f"{domain}/non_cdn_ips.txt"
    cdn_ips = ["104.16.", "104.17.", "151.101."]  # Extend this list with more CDN ranges
    with open(dnsx_output, 'r') as f:
        with open(non_cdn_ips, 'w') as nf:
            for line in f:
                if not any(cdn_ip in line for cdn_ip in cdn_ips):
                    nf.write(line)
    
    # Step 7: Scan non-CDN IPs with Nmap
    nmap_output = f"{domain}/nmap_scan.txt"
    run_command(f"nmap -iL {non_cdn_ips} -oN {nmap_output}", "Running Nmap scan on non-CDN IPs")

    # Step 8: Use httpx to grab HTTP metadata and location data
    httpx_output = f"{domain}/httpx_output.txt"
    run_command(f"cat {all_subdomains} | httpx -title -tech-detect -status-code -location -o {httpx_output}", "Running httpx to grab HTTP metadata and location data")
    
    # Step 9: Run nuclei on all gathered data
    nuclei_output = f"{domain}/nuclei_output.txt"
    run_command(f"nuclei -l {all_subdomains} -o {nuclei_output}", "Running nuclei on all gathered data")

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")
    main(target_domain)
