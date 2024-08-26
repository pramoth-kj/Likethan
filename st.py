import streamlit as st
from bs4 import BeautifulSoup
import pandas as pd
import csv
import requests
import concurrent.futures
import json

URLS = {
    "CISA IT": "https://www.cisa.gov/news-events/bulletins/sb23-100",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
}
OUTPUT_FILE = "vulnerabilities.csv"

def extract_vulnerabilities(url, source):
    try:
        response = requests.get(url)
        response.raise_for_status()
        vulnerabilities = []

        if source.startswith("CISA"):
            soup = BeautifulSoup(response.content, "html.parser")
            table = soup.find("table")
            if table:
                rows = table.find_all("tr")[1:]
                for row in rows:
                    cols = row.find_all("td")
                    vulnerability = {
                        "source": source,
                        "product": cols[0].text.split("--")[0].strip(),
                        "vendor": cols[0].text.split("--")[1].strip(),
                        "description": cols[1].text.strip(),
                        "published": cols[2].text.strip(),
                        "cvss": cols[3].text.strip(),
                        "cve": cols[4].find("a").text.strip(),
                        "reference": cols[4].find("a").get("href"),
                        "date": cols[2].text.strip()
                    }
                    vulnerabilities.append(vulnerability)
        elif source == "NVD":
            data = response.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                vulnerability = {
                    "source": source,
                    "product": cve.get('affected', [{}])[0].get('product', {}).get('name', 'N/A'),
                    "vendor": cve.get('affected', [{}])[0].get('vendor', {}).get('name', 'N/A'),
                    "description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
                    "published": cve.get('published', 'N/A'),
                    "cvss": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                    "cve": cve.get('id', 'N/A'),
                    "reference": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                    "date": cve.get('published', 'N/A')
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    except requests.RequestException as e:
        st.error(f"Failed to retrieve data from {source}: {e}")
        return []
    except Exception as e:
        st.error(f"Error while processing {source}: {e}")
        return []

def write_vulnerabilities_to_csv(vulnerabilities, filename):
    if vulnerabilities:
        fieldnames = vulnerabilities[0].keys()
        with open(filename, "w", encoding='UTF8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for vulnerability in vulnerabilities:
                writer.writerow(vulnerability)

def format_nvd_vulnerabilities(vulnerabilities):
    formatted_vulnerabilities = []
    for vuln in vulnerabilities:
        formatted_vulnerability = {
            "CVE ID": vuln.get("cve", "N/A"),
            "Product": vuln.get("product", "N/A"),
            "Vendor": vuln.get("vendor", "N/A"),
            "Description": vuln.get("description", "N/A"),
            "Published Date": vuln.get("published", "N/A"),
            "CVSS Score": vuln.get("cvss", "N/A"),
            "Reference": vuln.get("reference", "N/A"),
            "Date": vuln.get("date", "N/A")
        }
        formatted_vulnerabilities.append(formatted_vulnerability)
    return pd.DataFrame(formatted_vulnerabilities)

def format_other_vulnerabilities(vulnerabilities):
    formatted_vulnerabilities = []
    for vuln in vulnerabilities:
        formatted_vulnerability = {
            "Source": vuln.get("source", "N/A"),
            "Product": vuln.get("product", "N/A"),
            "Vendor": vuln.get("vendor", "N/A"),
            "Description": vuln.get("description", "N/A"),
            "Published Date": vuln.get("published", "N/A"),
            "CVSS Score": vuln.get("cvss", "N/A"),
            "CVE ID": vuln.get("cve", "N/A"),
            "Reference": vuln.get("reference", "N/A"),
            "Date": vuln.get("date", "N/A")
        }
        formatted_vulnerabilities.append(formatted_vulnerability)
    return pd.DataFrame(formatted_vulnerabilities)

def main():
    st.set_page_config(page_title="Multi-Source Vulnerability Scraper", layout="wide")
    st.title("🚨 Multi-Source Vulnerability Scraper Tool")
    st.write("This tool scrapes vulnerabilities from multiple sources and provides real-time updates.")
    
    st.sidebar.header("Settings")
    st.sidebar.write("Select the sources you want to scrape vulnerabilities from:")
    selected_sources = st.sidebar.multiselect(
        "Sources",
        list(URLS.keys()),
        default=list(URLS.keys())
    )

    st.sidebar.write("Click the button to start scraping.")
    if st.sidebar.button("Start Scraping"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        source_vulnerabilities = {}
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_source = {executor.submit(extract_vulnerabilities, URLS[source], source): source for source in selected_sources}

            for i, future in enumerate(concurrent.futures.as_completed(future_to_source)):
                source = future_to_source[future]
                status_text.text(f"Scraping {source} vulnerabilities...")
                try:
                    vulnerabilities = future.result()
                    source_vulnerabilities[source] = vulnerabilities
                except Exception as exc:
                    st.error(f"{source} generated an exception: {exc}")
                
                progress = (i + 1) / len(selected_sources)
                progress_bar.progress(progress)
        
        all_vulnerabilities = [vuln for vulns in source_vulnerabilities.values() for vuln in vulns]
        write_vulnerabilities_to_csv(all_vulnerabilities, OUTPUT_FILE)
        st.success(f"Vulnerabilities scraped and saved to {OUTPUT_FILE}")
        
        if all_vulnerabilities:
            st.write("### Extracted Vulnerabilities")
            for source, vulnerabilities in source_vulnerabilities.items():
                if vulnerabilities:
                    st.subheader(f"{source} Vulnerabilities")
                    df = format_nvd_vulnerabilities(vulnerabilities) if source == "NVD" else format_other_vulnerabilities(vulnerabilities)
                    st.dataframe(df)
                else:
                    st.warning(f"No vulnerabilities found for {source}.")
            
            st.download_button(
                label="Download CSV",
                data=pd.DataFrame(all_vulnerabilities).to_csv(index=False).encode('utf-8'),
                file_name=OUTPUT_FILE,
                mime='text/csv'
            )
        else:
            st.warning("No vulnerabilities found.")

    st.sidebar.info("Supported sources: CISA IT and NVD. More sources may be added in future updates.")

if __name__ == "__main__":
    main()
