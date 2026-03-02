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

    print(whois_data)
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
    resp = await client.get(f"https://rdap.verisign.com/com/v1/domain/{domain}")
    data = resp.json()

    registrar = None
    registrant = None
    registered = None
    expiry = None
    updated = None

    nameservers = [ns.get("ldhName") for ns in data.get("nameservers", [])]
    dnssec_signed = data.get("secureDNS", {}).get("delegationSigned", False)
    handle = data.get("handle")
    domain_name = data.get("ldhName")

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        fn = None
        email = None
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn":
                    fn = item[3]
                if item[0] == "email":
                    email = item[3]

        if "registrar" in roles:
            registrar = fn
        if "registrant" in roles:
            registrant = fn if fn else "Privacy/Proxy Service"
    
    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action == "registration":
            registered = date
        elif action == "expiration":
            expiry = date
        elif action in ("last changed", "last update of RDAP database"):
            updated = date

    return {
        "handle": handle,
        "domain": domain_name,
        "registrar": registrar,
        "registrant": registrant,
        "registered": registered,
        "expiry": expiry,
        "updated": updated,
        "nameservers": nameservers,
        "dnssec_signed": dnssec_signed,
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