import requests
from bs4 import BeautifulSoup
import pandas as pd
import random

def scrape_training_data():
    """
    Scrapes basic company index lists (e.g., from Wikipedia S&P 500) and 
    synthesises the proprietary ESG/Cyber metrics for training purposes, 
    as actual raw ESG/Cyber data sits behind paid APIs (Bloomberg, MSCI).
    """
    url = "https://en.wikipedia.org/wiki/List_of_S%26P_500_companies"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    table = soup.find('table', {'class': 'wikitable'})
    
    companies = []
    for row in table.find_all('tr')[1:251]: # Limit to ~250 for SECORA panel scale
        cols = row.find_all('td')
        companies.append({
            "name": cols[1].text.strip(),
            "sector": cols[3].text.strip(),
            "env_score": round(random.uniform(40, 95), 2),
            "soc_score": round(random.uniform(40, 95), 2),
            "gov_score": round(random.uniform(40, 95), 2),
            "composite": round(random.uniform(40, 95), 2),
            "yoy_change": round(random.uniform(-5, 5), 2),
            "revenue": round(random.uniform(1e7, 1e10), 2),
            "emissions": round(random.uniform(1000, 100000), 2),
            "esg_expenditure": round(random.uniform(1e5, 1e7), 2)
        })
        
    cyber = []
    for i in range(len(companies)):
        # Inject anomalies into ~15% of the dataset
        is_anomaly = random.random() < 0.15
        cyber.append({
            "company_id": i + 1,
            "incidents": random.randint(50, 150) if is_anomaly else random.randint(0, 10),
            "breaches": random.randint(5, 20) if is_anomaly else random.randint(0, 2),
            "flow_duration": random.uniform(100, 500) if is_anomaly else random.uniform(10, 50)
        })
        
    pd.DataFrame(companies).to_csv("demo_companies.csv", index=False)
    pd.DataFrame(cyber).to_csv("demo_cyber.csv", index=False)
    print("Scraped and synthesised training data generated successfully.")

if __name__ == "__main__":
    scrape_training_data()
