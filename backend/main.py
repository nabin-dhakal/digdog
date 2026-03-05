from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import httpx
import asyncio
import re
from datetime import datetime
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
import psutil
import os

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

cache = {}
cache_timeout = 3600

class LookupRequest(BaseModel):
    domain: str
    
    @validator('domain')
    def validate_domain(cls, v):
        v = v.lower().strip()
        v = re.sub(r'^https?://', '', v)
        v = v.split('/')[0].split(':')[0]
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')
        return v

@app.get("/")
async def home():
    return {"message": "Always OK", "timestamp": datetime.now().isoformat()}

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/metrics")
async def metrics():
    process = psutil.Process(os.getpid())
    return {
        "cpu_percent": process.cpu_percent(),
        "memory_percent": process.memory_percent(),
        "connections": len(process.connections()),
        "cache_size": len(cache)
    }

@app.post("/lookup")
@limiter.limit("60/minute")
async def lookup(request: Request, body: LookupRequest):
    domain = body.domain
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            dns_task = get_dns(client, domain)
            whois_task = get_whois(client, domain)
            server_task = get_server_info(client, domain)
            
            results = await asyncio.gather(
                dns_task, whois_task, server_task,
                return_exceptions=True
            )
            
            dns_data, whois_data, server_data = results
            
            if isinstance(dns_data, Exception):
                dns_data = {"ip": None, "error": str(dns_data)}
            if isinstance(whois_data, Exception):
                whois_data = {"error": str(whois_data)}
            if isinstance(server_data, Exception):
                server_data = {}
            
            ip_data = {}
            if dns_data and dns_data.get("ip"):
                ip_data = await get_ip(client, dns_data["ip"])
            
            return {
                "dns": dns_data,
                "ip": ip_data,
                "whois": whois_data,
                "server": server_data
            }
            
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def get_dns(client, domain):
    cache_key = f"dns:{domain}"
    now = datetime.now()
    
    if cache_key in cache:
        data, timestamp = cache[cache_key]
        if (now - timestamp).total_seconds() < cache_timeout:
            return data
    
    try:
        resp = await client.get(f"https://dns.google/resolve?name={domain}&type=A")
        resp.raise_for_status()
        data = resp.json()
        
        if "Answer" in data and data["Answer"]:
            a_records = [ans for ans in data["Answer"] if ans.get("type") == 1]
            if a_records:
                result = {"ip": a_records[0]["data"]}
                cache[cache_key] = (result, now)
                return result
        
        result = {"ip": None}
        cache[cache_key] = (result, now)
        return result
    except Exception as e:
        print(f"DNS lookup error for {domain}: {e}")
        return {"ip": None, "error": str(e)}

async def get_ip(client, ip):
    cache_key = f"ip:{ip}"
    now = datetime.now()
    
    if cache_key in cache:
        data, timestamp = cache[cache_key]
        if (now - timestamp).total_seconds() < cache_timeout:
            return data
    
    try:
        resp = await client.get(f"http://ip-api.com/json/{ip}")
        data = resp.json()

        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "region": data.get("regionName"),
                "timezone": data.get("timezone")
            }
            cache[cache_key] = (result, now)
            return result
    except Exception as e:
        print(f"Error fetching IP info: {e}")
    
    result = {"ip": ip}
    cache[cache_key] = (result, now)
    return result

async def get_whois(client, domain):
    cache_key = f"whois:{domain}"
    now = datetime.now()
    
    if cache_key in cache:
        data, timestamp = cache[cache_key]
        if (now - timestamp).total_seconds() < cache_timeout:
            return data
    
    tld = domain.split('.')[-1]
    
    rdap_urls = {
        'com': 'https://rdap.verisign.com/com/v1/domain/',
        'net': 'https://rdap.verisign.com/net/v1/domain/',
        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
        'io': 'https://rdap.nic.io/v1/domain/',
        'app': 'https://rdap.nic.google/v1/domain/',
        'dev': 'https://rdap.nic.google/v1/domain/'
    }
    
    base_url = rdap_urls.get(tld, f'https://rdap.verisign.com/{tld}/v1/domain/')
    
    try:
        resp = await client.get(f"{base_url}{domain}")
        
        if resp.status_code == 404:
            return await get_whois_fallback(client, domain)
            
        resp.raise_for_status()
        data = resp.json()

        registrar = None
        registrant = None
        registered = None
        expiry = None
        updated = None
        nameservers = []
        handle = data.get("handle")
        domain_name = data.get("ldhName")

        for ns in data.get("nameservers", []):
            if ns.get("ldhName"):
                nameservers.append(ns.get("ldhName"))

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

        result = {
            "handle": handle,
            "domain": domain_name,
            "registrar": registrar,
            "registrant": registrant,
            "registered": registered,
            "expiry": expiry,
            "updated": updated,
            "nameservers": nameservers
        }
        
        cache[cache_key] = (result, now)
        return result
        
    except Exception as e:
        print(f"RDAP error for {domain}: {e}")
        return await get_whois_fallback(client, domain)

async def get_whois_fallback(client, domain):
    try:
        resp = await client.get(f"https://whoisjson.com/api/v1/whois?domain={domain}")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "registrar": data.get("registrar"),
                "registered": data.get("created"),
                "expiry": data.get("expires"),
                "updated": data.get("updated")
            }
    except:
        pass
    return {}

async def get_server_info(client, domain):
    cache_key = f"server:{domain}"
    now = datetime.now()
    
    if cache_key in cache:
        data, timestamp = cache[cache_key]
        if (now - timestamp).total_seconds() < cache_timeout:
            return data
    
    for scheme in ("https://", "http://"):
        try:
            resp = await client.get(f"{scheme}{domain}", follow_redirects=True)
            result = {
                "server": resp.headers.get("server"),
                "powered_by": resp.headers.get("x-powered-by"),
                "cdn": resp.headers.get("x-cdn") or (
                    "Cloudflare" if resp.headers.get("cf-ray") else
                    "Fastly" if resp.headers.get("x-served-by") else
                    "AWS/CloudFront" if resp.headers.get("x-cache") else None
                )
            }
            cache[cache_key] = (result, now)
            return result
        except httpx.RequestError:
            continue
    
    result = {}
    cache[cache_key] = (result, now)
    return result