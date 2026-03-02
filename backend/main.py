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

@app.post("/lookup")
async def lookup(body: dict):
    domain = body["domain"]
    
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

    return {
        "dns": dns_data if isinstance(dns_data, dict) else {},
        "ip": ip_data,
        "whois": whois_data if isinstance(whois_data, dict) else {},
        "server": server_data if isinstance(server_data, dict) else {}
    }

async def get_dns(client, domain):
    resp = await client.get(f"https://dns.google/resolve?name={domain}&type=A")
    data = resp.json()
    ip = data["Answer"][0]["data"] if "Answer" in data else None
    return {"ip": ip, "raw": data}

async def get_ip(client, ip):
    resp = await client.get(f"https://ip-api.com/json/{ip}")
    data = resp.json()
    if data["status"] == "success":
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp")
        }
    return {}

async def get_whois(client, domain):
    resp = await client.get(f"https://rdap.org/domain/{domain}")
    data = resp.json()

    registered = expiry = updated = registrar = None

    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action == "registration": registered = date
        elif action == "expiration": expiry = date
        elif action == "last changed": updated = date

    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = entity.get("handle")

    return {"registrar": registrar, "registered": registered, "expiry": expiry, "updated": updated}

async def get_server_info(client, domain):
    resp = await client.get(f"https://{domain}", follow_redirects=True)
    return {
        "server": resp.headers.get("server"),
        "powered_by": resp.headers.get("x-powered-by"),
        "cdn": resp.headers.get("x-cdn")
    }