from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

import re

def clean_domain(domain):
    domain = domain.lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    return domain

@app.get("/")
async def home():
    return {"message":"Always OK"}

@app.post("/lookup")
async def lookup(body: dict):
    domain = clean_domain(body["domain"])
    
    async with httpx.AsyncClient() as client:
        dns_data, whois_data, server_data = await asyncio.gather(
            get_dns(client, domain),
            get_whois(client, domain),
            get_server_info(client, domain),
            return_exceptions=True
        )
    
    ip = dns_data.get("ip") if isinstance(dns_data, dict) else None
    ip_data = {}
    if ip:
        async with httpx.AsyncClient() as client:
            ip_data = await get_ip(client, ip)

    if not dns_data and not whois_data:
        return {"message": "No data found for this domain"}
    
    return {
        "dns": dns_data if isinstance(dns_data, dict) else {},
        "ip": ip_data,
        "whois": whois_data if isinstance(whois_data, dict) else {},
        "server": server_data if isinstance(server_data, dict) else {}
    }

async def get_dns(client, domain):
    resp = await client.get(f"https://dns.google/resolve?name={domain}&type=A")
    data = resp.json()
    ip = None
    if "Answer" in data and len(data["Answer"]) > 0:
        ip = data["Answer"][0].get("data")
    return {"ip": ip, "raw": data}

async def get_ip(client, ip):
    try:
        resp = await client.get(f"http://ip-api.com/json/{ip}")
        data =  resp.json()  

        if data["status"] == "success":
            return {
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "region": data.get("regionName"),
                "timezone": data.get("timezone")
            }
    except Exception as e:
        print(f"Error fetching IP info: {e}")
    return {"ip": ip}  

async def get_whois(client, domain):
    try:
        bootstrap = await client.get("https://data.iana.org/rdap/dns.json")
        bootstrap_data = bootstrap.json()

        tld = domain.split(".")[-1]
        rdap_url = None

        for service in bootstrap_data["services"]:
            if tld in service[0]:
                rdap_url = service[1][0]
                break

        if not rdap_url:
            return {}

        resp = await client.get(f"{rdap_url}domain/{domain}")
        data = resp.json()

    except Exception:
        return {}

    registrar = None
    registrant = None

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        fn = None

        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn":
                    fn = item[3]

        if "registrar" in roles:
            registrar = fn
        if "registrant" in roles:
            registrant = fn

    return {
        "domain": data.get("ldhName"),
        "registrar": registrar,
        "registrant": registrant,
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])]
    }

async def get_server_info(client, domain):
    for scheme in ("https://", "http://"):
        try:
            resp = await client.get(f"{scheme}{domain}", follow_redirects=True, timeout=10)
            return {
                "server": resp.headers.get("server"),
                "powered_by": resp.headers.get("x-powered-by"),
                "cdn": resp.headers.get("x-cdn")
            }
        except httpx.RequestError:
            continue
    return {}