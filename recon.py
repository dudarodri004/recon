import subprocess
import os
import argparse

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

def recon(domain):
    # Use the current directory to store results
    directory = '.'

    # Step 1: Subdomain Enumeration with assetfinder
    assetfinder_output = f"{directory}/assetfinder_{domain}.txt"
    run_command(f"assetfinder --subs-only {domain} > {assetfinder_output}", "Running assetfinder for subdomain enumeration")
    
    # Step 2: Subdomain Enumeration with subfinder
    subfinder_output = f"{directory}/subfinder_{domain}.txt"
    run_command(f"subfinder -d {domain} -o {subfinder_output}", "Running subfinder for subdomain enumeration")
    
    # Combine results from assetfinder, subfinder, and SecurityTrails using anew
    combined_subdomains = f"{directory}/combined_subdomains_{domain}.txt"
    run_command(f"cat {assetfinder_output} {subfinder_output} | anew {combined_subdomains}", "Combining subdomains from assetfinder and subfinder using anew")

    # Step 4: Subdomain Permutations with ripgen
    ripgen_output = f"{directory}/ripgen_{domain}.txt"
    run_command(f"ripgen -d {combined_subdomains} > {ripgen_output}", "Running ripgen for subdomain permutations")
    
    # Combine all subdomain results using anew
    all_subdomains = f"{directory}/all_subdomains_{domain}.txt"
    run_command(f"cat {ripgen_output} | anew {all_subdomains}", "Combining all subdomains using anew")

    # Step 5: Grab A records with dnsx
    dnsx_output = f"{directory}/dnsx_output_{domain}.txt"
    run_command(f"cat {all_subdomains} | dnsx -a -resp-only -o {dnsx_output}", "Running dnsx to grab A records")
    
    # Remove duplicate IPs
    unique_ips = f"{directory}/unique_ips_{domain}.txt"
    run_command(f"sort -u {dnsx_output} > {unique_ips}", "Removing duplicate IPs")

    # Step 6: Remove IPs pointing to CDNs
    non_cdn_ips = f"{directory}/non_cdn_ips_{domain}.txt"
    cdn_ips = ["104.16.", "104.17.", "151.101."]  # Extend this list with more CDN ranges
    with open(unique_ips, 'r') as f:
        with open(non_cdn_ips, 'w') as nf:
            for line in f:
                if not any(cdn_ip in line for cdn_ip in cdn_ips):
                    nf.write(line)
    
    # Step 7: Scan non-CDN IPs with Nmap
    nmap_output = f"{directory}/nmap_scan_{domain}.txt"
    run_command(f"nmap -iL {non_cdn_ips} --min-rate 5000 --max-retries 1 --max-scan-delay 20ms -T4 -p- --exclude-ports 22,80,443,53,5060,8080 --open -oN {nmap_output}", "Running Nmap scan on non-CDN IPs")

    # Step 8: Probe live subdomains with httpx
    live_subdomains = f"{directory}/live_subdomains_{domain}.txt"
    run_command(f"cat {all_subdomains} | httprobe -c 50 --prefer-https | anew {live_subdomains}", "Probing live subdomains with httprobe")
    
    # Step 9: Use httpx to grab HTTP metadata and location data
    httpx_output = f"{directory}/httpx_output_{domain}.txt"
    run_command(f"cat {live_subdomains} | httpx -title -tech-detect -status-code -location -o {httpx_output}", "Running httpx to grab HTTP metadata and location data")
    
    # Step 10: Run nuclei on all gathered data
    nuclei_output = f"{directory}/nuclei_output_{domain}.txt"
    run_command(f"nuclei -l {live_subdomains} -o {nuclei_output}", "Running nuclei on all gathered data")

def main():
    parser = argparse.ArgumentParser(description="Recon automation script")
    parser.add_argument('-d', '--domain', help="Target domain for recon")
    parser.add_argument('-l', '--list', help="List of domains or wildcards for recon")
    args = parser.parse_args()

    domains = []

    if args.domain:
        domains.append(args.domain)

    if args.list:
        with open(args.list, 'r') as f:
            domains.extend([line.strip() for line in f.readlines()])

    for domain in domains:
        recon(domain)

if __name__ == "__main__":
    main()
