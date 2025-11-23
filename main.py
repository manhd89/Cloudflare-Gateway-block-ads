import re
import requests
import logging
import sys
import os 
from cloudflare import Cloudflare
from typing import List, Dict, Any, Optional, Set

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

ACCOUNT_ID: str = os.getenv("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN: str = os.getenv("CLOUDFLARE_API_TOKEN")

if not ACCOUNT_ID or not API_TOKEN:
    logger.critical("FATAL: CLOUDFLARE_ACCOUNT_ID or CLOUDFLARE_API_TOKEN must be defined in environment variables.")
    sys.exit(1)

AD_BLOCK_LISTS: List[str] = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
]

LIST_PREFIX: str = "Auto_AdBlock_Part_"
POLICY_NAME: str = "Ad Block Policy (Auto-Generated)"
CHUNK_SIZE: int = 1000 
CLEANUP_MODE: bool = False 

try:
    cf = Cloudflare(api_token=API_TOKEN)
    zero = cf.zero_trust.gateway
    logger.info("Cloudflare Zero Trust Gateway client initialized successfully.")
except Exception as e:
    logger.critical(f"Cloudflare Client initialization error: {e}")
    sys.exit(1)

ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){1,3}$")
url_pattern = re.compile(r"^(https?://)?([^/]+)")
domain_pattern = re.compile(
    r"(?=^.{4,255}$)(^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$)"
)

replace_pattern = re.compile(
    r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+|"    

    r"^(\|\||@@\|\||\*\.|\*|https?://)|"     

    r"[\^\/#].*$"                           

)

def clean_domain(raw: str) -> Optional[str]:
    """Cleans adblock/hosts/URL into a pure domain."""
    raw = raw.strip()

    if not raw or raw.startswith(("#", "!", "@@", "[")):
        return None

    raw = replace_pattern.sub("", raw).strip()

    if "/" in raw:
        m = url_pattern.match(raw)
        if m:
            raw = m.group(2)

    raw = raw.strip().strip(".")

    if not raw:
        return None

    if ip_pattern.match(raw):
        return None

    if domain_pattern.match(raw):
        return raw.lower()

    return None

def download_and_parse_blocklist(urls: List[str]) -> List[str]:
    logger.info("Starting download and processing of blocklists...")
    total_domains = set()

    for url in urls:
        logger.info(f"-> Processing list: {url}")
        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading list {url}: {e}")
            continue

        domains_in_list = set()
        for line in resp.text.splitlines():
            domain = clean_domain(line)
            if domain:
                domains_in_list.add(domain)

        count = len(domains_in_list)
        total_domains.update(domains_in_list)
        logger.info(f"   Found {count} unique domains in this list.")

    return sorted(total_domains)

def chunk_list(data: List[str], size: int) -> List[List[str]]:
    return [data[i:i + size] for i in range(0, len(data), size)]

def remove_subdomains_if_higher(domains: set[str]) -> set[str]:
    top_level_domains = set()
    logger.info("--- Filtering Subdomains (Optimizing List Size) ---")

    domains_set = set(domains)
    initial_count = len(domains_set)

    for domain in domains_set:
        parts = domain.split(".")
        is_lower_subdomain = False

        for i in range(1, len(parts)):
            higher_domain = ".".join(parts[i:])
            if higher_domain in domains_set:
                is_lower_subdomain = True
                break

        if not is_lower_subdomain:
            top_level_domains.add(domain)

    filtered_count = len(top_level_domains)
    logger.info(f"Initial domain count: {initial_count}")
    logger.info(f"Domains removed (subdomains): {initial_count - filtered_count}")
    logger.info(f"Final domain count: {filtered_count}")

    return top_level_domains

def get_all_prefixed_lists() -> List[Dict[str, str]]:
    try:
        existing_lists = zero.lists.list(account_id=ACCOUNT_ID).result or []
        return [{"id": lst.id, "name": lst.name} for lst in existing_lists if lst.name.startswith(LIST_PREFIX)]
    except Exception as e:
        logger.error(f"Failed to list existing Gateway Lists: {e}")
        return []

def create_or_update_gateway_lists(chunks: List[List[str]]) -> tuple[List[str], List[Dict[str, str]]]:
    logger.info("--- Updating Gateway Lists ---")
    all_current_prefixed_lists = get_all_prefixed_lists()
    existing_map = {lst['name']: lst for lst in all_current_prefixed_lists}
    final_list_ids = []

    for i, chunk in enumerate(chunks):
        list_name = f"{LIST_PREFIX}{i+1}"
        items = [{"value": d} for d in chunk]
        description = f"Auto-generated list part {i+1} ({len(chunk)} domains)"

        try:
            if list_name in existing_map:
                lst = existing_map[list_name]
                logger.info(f"[+] Updating list: {list_name} ({lst['id']})")
                zero.lists.update(
                    account_id=ACCOUNT_ID,
                    list_id=lst['id'],
                    name=list_name,
                    description=description,
                    items=items
                )
                final_list_ids.append(lst['id'])
            else:
                logger.info(f"[+] Creating new list: {list_name}")
                created = zero.lists.create(
                    account_id=ACCOUNT_ID,
                    name=list_name,
                    description=description,
                    type="DOMAIN",
                    items=items
                )
                final_list_ids.append(created.id)
        except Exception as e:
            logger.error(f"Failed to create/update list {list_name}: {e}")

    return final_list_ids, all_current_prefixed_lists

def format_list_ids_for_traffic(list_ids: List[str]) -> str:
    return " or ".join([f"any(dns.domains[*] in ${list_id})" for list_id in list_ids])

def create_or_update_gateway_policy(list_ids: List[str]):
    logger.info("--- Updating Gateway DNS Rule ---")

    if not list_ids:
        logger.warning("No list IDs provided. Skipping rule creation/update.")
        return

    rules_api = zero.rules
    try:
        existing_rules = rules_api.list(account_id=ACCOUNT_ID).result or []
    except Exception as e:
        logger.error(f"Failed to list Gateway Rules: {e}")
        return

    existing = next((r for r in existing_rules if r.name == POLICY_NAME), None)
    traffic_expression = format_list_ids_for_traffic(list_ids)

    rule_data: Dict[str, Any] = {
        "action": "block",
        "enabled": True,
        "name": POLICY_NAME,
        "description": "Auto-generated Ad Block Rule from combined hosts (DNS Filtering)",
        "traffic": traffic_expression,
        "precedence": 10,
        "rule_settings": {"block_reason": "Blocked by Ad Block Policy (DNS)"}
    }

    try:
        if existing:
            logger.info(f"[+] Updating existing rule: {existing.id}")
            rules_api.update(account_id=ACCOUNT_ID, rule_id=existing.id, **rule_data)
        else:
            logger.info("[+] Creating new rule")
            rules_api.create(account_id=ACCOUNT_ID, **rule_data)

        logger.info(f"Gateway Rule '{POLICY_NAME}' updated/created successfully.")
    except Exception as e:
        logger.error(f"Failed to create/update Gateway Rule '{POLICY_NAME}': {e}")

def delete_unused_lists(final_list_ids: List[str], all_current_prefixed_lists: List[Dict[str, str]]):
    logger.info("--- Deleting Unused Lists ---")
    final_set = set(final_list_ids)
    deleted_count = 0

    for lst in all_current_prefixed_lists:
        if lst["id"] not in final_set:
            logger.info(f"[-] Deleting old list: {lst['name']} ({lst['id']})")
            try:
                zero.lists.delete(account_id=ACCOUNT_ID, list_id=lst['id'])
                deleted_count += 1
            except Exception as e:
                logger.warning(f"Could not delete list {lst['name']} ({lst['id']}). Error: {e}")

    logger.info(f"Total old lists deleted: {deleted_count}")

def cleanup_policy_and_lists():
    logger.warning("!!! CLEANUP MODE ACTIVATED !!!")

    rules_api = zero.rules
    rule_deleted = False

    try:
        existing_rules = rules_api.list(account_id=ACCOUNT_ID).result or []
        existing_rule = next((r for r in existing_rules if r.name == POLICY_NAME), None)

        if existing_rule:
            logger.info(f"[X] Deleting Gateway Rule '{POLICY_NAME}' ({existing_rule.id})...")
            rules_api.delete(account_id=ACCOUNT_ID, rule_id=existing_rule.id)
            logger.info("Rule deleted successfully.")
            rule_deleted = True
    except Exception as e:
        logger.error(f"Failed to delete rule '{POLICY_NAME}': {e}")

    lists_to_delete = get_all_prefixed_lists()
    deleted_lists = 0

    for lst in lists_to_delete:
        try:
            zero.lists.delete(account_id=ACCOUNT_ID, list_id=lst["id"])
            deleted_lists += 1
        except Exception as e:
            logger.warning(f"Failed to delete list {lst['name']} ({lst['id']}). Error: {e}")

    logger.info(f"Cleanup complete: {deleted_lists} lists deleted.")

def main():
    logger.info("Starting Cloudflare Auto AdBlock Script.")

    if CLEANUP_MODE:
        cleanup_policy_and_lists()
        return

    domains_list = download_and_parse_blocklist(AD_BLOCK_LISTS)
    if not domains_list:
        logger.error("No domains found. Exiting.")
        return

    final_domains = remove_subdomains_if_higher(set(domains_list))
    chunks = chunk_list(sorted(final_domains), CHUNK_SIZE)
    logger.info(f"Total lists to create after optimization: {len(chunks)}")

    final_list_ids, all_current_prefixed_lists = create_or_update_gateway_lists(chunks)

    if not final_list_ids:
        logger.error("Failed to create/update lists. Aborting.")
        return

    create_or_update_gateway_policy(final_list_ids)
    delete_unused_lists(final_list_ids, all_current_prefixed_lists)

    logger.info("==========================================================")
    logger.info(f"✅ FINAL RESULT: {len(final_list_ids)} Gateway Lists updated/created.")
    logger.info(f"✅ Rule '{POLICY_NAME}' linked successfully.")
    logger.info("==========================================================")

if __name__ == "__main__":
    main()
