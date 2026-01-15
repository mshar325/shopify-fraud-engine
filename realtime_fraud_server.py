from fastapi import FastAPI, Request, Header, HTTPException
import psycopg2, os, ipaddress, hmac, hashlib
import geoip2.database
from urllib.parse import urlparse, parse_qs

# ───────── CONFIG ─────────
SUPABASE_URL = os.environ["SUPABASE_URL"]
SHOPIFY_SECRET = os.environ["SHOPIFY_SECRET"]

CITY_DB = "GeoLite2-City.mmdb"
ASN_DB  = "GeoLite2-ASN.mmdb"

TELCOS    = ["jio","airtel","vodafone","idea","bsnl","tata"]
PLATFORMS = ["meta","facebook","google","whatsapp","cloudflare","amazon","aws"]

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
) ON CONFLICT (row_id) DO NOTHING;
"""

# ───────── HELPERS ─────────
def verify(data, hmac_header):
    digest = hmac.new(SHOPIFY_SECRET.encode(), data, hashlib.sha256).digest()
    return hmac.compare_digest(digest, bytes.fromhex(hmac_header))

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

# ───────── FRAUD ─────────
def classify(country,state,utm,ipg):
    if any(t in ipg["org"] for t in TELCOS):
        return ("TELECOM",5)
    if any(p in ipg["org"] for p in PLATFORMS) or utm in ["facebook","google","instagram","whatsapp"]:
        return ("PLATFORM",10)
    if country and ipg["country"] and country.lower()!=ipg["country"].lower():
        return ("REAL_FRAUD",95)
    if state and ipg["state"] and state.lower()!=ipg["state"].lower():
        return ("REAL_FRAUD",80)
    return ("CLEAN",0)

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
async def shopify(req: Request, x_shopify_hmac_sha256: str = Header(None)):
    raw = await req.body()
    if not verify(raw, x_shopify_hmac_sha256):
        raise HTTPException(401,"Bad HMAC")

    order = await req.json()
    note = parse_notes(order.get("note_attributes",[]))
    landing = order.get("landing_site_ref") or order.get("landing_site")
    utm = note.get("utm_source") or extract_utms(landing).get("utm_source")
    ip  = note.get("ip_address")

    ipg = geo(ip)
    location_match = False
    bucket,score = ("UNKNOWN",50)

    if ipg:
        location_match = (note.get("country") or "").lower() == (ipg["country"] or "").lower()
        bucket,score = classify(note.get("country"),note.get("state"),utm,ipg)

    for li in order["line_items"]:
        row = build_row(order,li,order["shop_id"])
        row["location_match"] = location_match
        row["ip_checked"] = True if ipg else False
        row["fraud_bucket"] = bucket
        row["risk_score"] = score
        cur.execute(INSERT_SQL,row)

    return {"status":"ok"}
