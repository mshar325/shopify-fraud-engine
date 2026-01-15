from fastapi import FastAPI, Request, Header, HTTPException
import psycopg2, os, ipaddress, hmac, hashlib, base64, requests
import geoip2.database
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# ───────── CONFIG ─────────
SUPABASE_URL   = os.environ["SUPABASE_URL"]
SHOPIFY_SECRET = os.environ["SHOPIFY_SECRET"]
CITY_URL = os.environ["GEOIP_CITY_URL"]
ASN_URL  = os.environ["GEOIP_ASN_URL"]

CITY_DB = "GeoLite2-City.mmdb"
ASN_DB  = "GeoLite2-ASN.mmdb"

TELCOS    = ["jio","airtel","vodafone","idea","bsnl","tata"]
PLATFORMS = ["meta","facebook","google","whatsapp","cloudflare","amazon","aws"]

# ───────── Download GeoIP ─────────
def download(url, path):
    if not os.path.exists(path):
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        with open(path,"wb") as f:
            f.write(r.content)

download(CITY_URL, CITY_DB)
download(ASN_URL,  ASN_DB)

city_reader = geoip2.database.Reader(CITY_DB)
asn_reader  = geoip2.database.Reader(ASN_DB)

app = FastAPI()

# ───────── DATABASE ─────────
db = psycopg2.connect(SUPABASE_URL, sslmode="require")
db.autocommit = True
cur = db.cursor()

INSERT_SQL = """
INSERT INTO shopify_orders_marketing (
row_id,date,date_time,order_id,order_name,
customer_name,phone,address1,address2,city,state,zip,country,
product_id,variant_id,product_name,variant_name,vendor,price,quantity,weight,
utm_source,utm_medium,utm_campaign,utm_content,utm_term,utm_id,full_url,ip_address,
store_name,location_match,ip_checked,fraud_bucket,risk_score
) VALUES (
%(row_id)s,%(date)s,%(date_time)s,%(order_id)s,%(order_name)s,
%(customer_name)s,%(phone)s,%(address1)s,%(address2)s,%(city)s,%(state)s,%(zip)s,%(country)s,
%(product_id)s,%(variant_id)s,%(product_name)s,%(variant_name)s,%(vendor)s,%(price)s,%(quantity)s,%(weight)s,
%(utm_source)s,%(utm_medium)s,%(utm_campaign)s,%(utm_content)s,%(utm_term)s,%(utm_id)s,%(full_url)s,%(ip_address)s,
%(store_name)s,%(location_match)s,%(ip_checked)s,%(fraud_bucket)s,%(risk_score)s
);
"""

# ───────── SHOPIFY HMAC ─────────
def verify(data, hmac_header):
    if not hmac_header:
        return False
    digest = hmac.new(SHOPIFY_SECRET.encode(), data, hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), hmac_header)

# ───────── HELPERS ─────────
def clean(x): return str(x).strip() if x else None
def digits(x): return "".join(c for c in str(x) if c.isdigit()) if x else None

def extract_utms(url):
    if not url: return {}
    q = urlparse(url).query
    return {k:v[0] for k,v in parse_qs(q).items() if k.startswith("utm_")}

def parse_notes(attrs):
    out={}
    for a in attrs or []:
        k=(a.get("name") or "").lower().replace(" ","_")
        v=clean(a.get("value"))
        if v: out[k]=v
    return out

# ───────── GEO ─────────
def geo(ip):
    try:
        ipaddress.ip_address(ip)
        c = city_reader.city(ip)
        a = asn_reader.asn(ip)
        return {
            "country": c.country.name,
            "state": c.subdivisions.most_specific.name,
            "org": (a.autonomous_system_organization or "").lower()
        }
    except:
        return None

# ───────── FRAUD BRAIN ─────────
def seen_before(field, value):
    if not value:
        return False
    cur.execute(f"SELECT 1 FROM shopify_orders_marketing WHERE {field}=%s LIMIT 1", (value,))
    return cur.fetchone() is not None

def burst():
    cur.execute("SELECT COUNT(*) FROM shopify_orders_marketing WHERE date_time > NOW() - interval '2 minutes'")
    return cur.fetchone()[0] > 12

def address_entropy(addr):
    if not addr:
        return 0
    words = addr.lower().split()
    return len(set(words)) / max(len(words),1)

def classify(note, utm, ipg):
    risk = 0
    org = ipg.get("org","") if ipg else ""

    if any(t in org for t in TELCOS): risk += 10
    if any(p in org for p in PLATFORMS): risk += 15
    if utm in ["facebook","instagram"]: risk += 15

    if seen_before("ip_address", note.get("ip_address")): risk += 25
    if seen_before("phone", note.get("phone")): risk += 35

    if burst(): risk += 30

    addr = (note.get("address1") or "") + " " + (note.get("address2") or "")
    if address_entropy(addr) < 0.5: risk += 20

    if note.get("country") and ipg and note["country"].lower()!= (ipg["country"] or "").lower():
        risk += 40

    if risk >= 80: return "REAL_FRAUD", risk
    if risk >= 60: return "TELECOM", risk
    if risk >= 30: return "PLATFORM", risk
    return "CLEAN", risk

# ───────── FLATTENER ─────────
def build_row(order, li, store):
    note = parse_notes(order.get("note_attributes",[]))
    landing = order.get("landing_site_ref") or order.get("landing_site")
    utms = extract_utms(landing)

    return {
        "row_id": f"{store}_{order['id']}_{li['product_id']}_{li['variant_id']}",
        "date": order["created_at"][:10],
        "date_time": order["created_at"],
        "order_id": order["id"],
        "order_name": order.get("name"),
        "customer_name": note.get("full_name"),
        "phone": digits(note.get("phone")),
        "address1": note.get("house_no._&_colony/apartment"),
        "address2": note.get("nearby_school,_hospital,_shop"),
        "city": note.get("city"),
        "state": note.get("state"),
        "zip": digits(note.get("zip_code")),
        "country": note.get("country"),
        "product_id": li.get("product_id"),
        "variant_id": li.get("variant_id"),
        "product_name": li.get("title"),
        "variant_name": li.get("variant_title"),
        "vendor": li.get("vendor"),
        "price": li.get("price"),
        "quantity": li.get("quantity"),
        "weight": li.get("grams"),
        "utm_source": note.get("utm_source") or utms.get("utm_source"),
        "utm_medium": note.get("utm_medium") or utms.get("utm_medium"),
        "utm_campaign": note.get("utm_campaign") or utms.get("utm_campaign"),
        "utm_content": note.get("utm_content") or utms.get("utm_content"),
        "utm_term": note.get("utm_term") or utms.get("utm_term"),
        "utm_id": note.get("utm_id"),
        "full_url": note.get("full_url") or landing,
        "ip_address": note.get("ip_address"),
        "store_name": store
    }

# ───────── WEBHOOK ─────────
@app.post("/shopify")
async def shopify(req: Request, x_shopify_hmac_sha256: str = Header(None), x_shopify_shop_domain: str = Header(None)):
    raw = await req.body()
    if not verify(raw, x_shopify_hmac_sha256):
        raise HTTPException(401,"Bad HMAC")

    store = x_shopify_shop_domain or "unknown"

    order = await req.json()
    note = parse_notes(order.get("note_attributes",[]))
    landing = order.get("landing_site_ref") or order.get("landing_site")
    utm = note.get("utm_source") or extract_utms(landing).get("utm_source")
    ip  = note.get("ip_address")

    ipg = geo(ip)
    bucket,score = classify(note, utm, ipg)

    for li in order["line_items"]:
        row = build_row(order, li, store)
        row["location_match"] = False
        row["ip_checked"] = True if ipg else False
        row["fraud_bucket"] = bucket
        row["risk_score"] = score
        cur.execute(INSERT_SQL,row)

    return {"status":"ok"}
