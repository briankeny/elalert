from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import sqlite3
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from alerts import  ElasticAlerts
from config import Config

# Configure logger
def logger_config(log_file='Elalert.log',log_level=logging.INFO):
    logging.basicConfig(filename=log_file, 
                        format='%(asctime)s: %(levelname)s: %(message)s', 
                        level=log_level)
    return logging

#configure db
def _initialize_sqlite(verbose=False):
        """Initialize SQLite database and create alerts table."""
        try:
            with sqlite3.connect('alerts.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kibana_alert_rule_uuid TEXT,
                        kibana_alert_instance_id TEXT,
                        kibana_alert_start TEXT,
                        kibana_alert_end TEXT,
                        kibana_alert_status TEXT,
                        UNIQUE(
                            kibana_alert_rule_uuid,
                            kibana_alert_instance_id,
                            kibana_alert_start,
                            kibana_alert_end,
                            kibana_alert_status
                        )
                    )
                ''')
                conn.commit()
                if verbose:
                    logging.info(f'[+] Initialized SQLite database: alerts.db')
                return True
        except sqlite3.Error as e:
            logging.error(f'[?] Error initializing SQLite database: {str(e)}')
            return False

# Load data from json file
def load_from_json(file_name_or_path=None):
        """Loads data from a JSON file."""
        try:
            with open(file_name_or_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f'[?] Error reading from JSON file {file_name_or_path}: {str(e)}')
            return []

# Get env variable with fallback value
def get_env_variable(var_name, default_value, var_type=str):
    """ Retrieves an environment variable, converts it to the specified type, and handles errors."""
    try:
        value = os.getenv(var_name, default_value)
        return var_type(value)  
    except (ValueError, TypeError):
        # Fallback if conversion fails
        return default_value  
    
# Remove empty items from list 
def parse_list_remove_blanks(items=None):
    # Ensure it's a string before splitting
    if isinstance(items, str):  
            items = items.split(',')
            return list(filter(lambda x: x.strip(), items))
    return items  


# Fetch Environment Variables
def load_env_variables(): 
    """Fetch environment variables from .env file."""
    url = os.getenv('elastic_url',None)
    elastic_api_key =  os.getenv('elastic_api_key',None)
    webhook_url = os.getenv('webhook_url',None)
    interval = get_env_variable('interval',60,int)
    max_alerts_per_batch = get_env_variable('max_alerts_per_batch',3,int)
    hits_size = get_env_variable('hits_size',100,int)
    save_file = os.getenv('save_file','alerts.json')
    save =  get_env_variable('save','true', str).lower() in ['yes', 'true', '1', 't', 'y']
    verbose = os.getenv('verbose','True').lower() in ['yes', 'true', '1', 't', 'y']
    pytz_timezone = get_env_variable('pytz_timezone','Africa/Nairobi',str)
    timeframe = get_env_variable('timeframe',interval,int)
    es_index = get_env_variable('es_index','.alerts-*',str)
    ignored_alert_keywords = parse_list_remove_blanks(os.getenv('ignored_alert_keywords',''))
    cleanup_schedule = parse_list_remove_blanks(os.getenv('cleanup_schedule','00:01,12:00'))
    app_log_file = os.getenv('LOG_FILE','Elalert.log')
    return {
            'es_index': es_index, 
            'webhook_url': webhook_url,
            'timeframe':timeframe,
            'max_alerts_per_batch': max_alerts_per_batch,
            'hits_size': hits_size,
            'save': save,
            'save_file': save_file,
            'verbose': verbose,
            'pytz_timezone': pytz_timezone,
            'elastic_url': url,
            'elastic_api_key': elastic_api_key,
            'es_body': None,
            'interval': interval,
            'ignored_alert_keywords': ignored_alert_keywords,
            'cleanup_schedule':cleanup_schedule,
            'message_template':None,
            'app_log_file': app_log_file
            }

# Main function entry point
def main(verbose=False):
    """Fetch Alerts and send notifications."""
    # Set Global Environment Variables
    base_config = load_env_variables() or {}
    verbose = base_config['verbose']
    logger_config(log_file=base_config['app_log_file'])
    print(f'[+] \t IO logs have been redirected to {base_config["app_log_file"]}')
    logging.info("[*] Elalert is starting...")
    logging.info('[*] Loading configuration modules...')
    #Initialize configs and values
    logging.info("[*] Elalert setup started...")
    #If no Elastic api key or kibana url is provided, exit
    if not all ([ base_config['elastic_api_key'], base_config['elastic_url'] ]):
        logging.error('[!] No API key or Elastic URL Endpoint provided. Exiting...')
        return    
    # Test es client
    es_client = None
    try:
        es_client = Elasticsearch(base_config['elastic_url'],api_key=base_config['elastic_api_key'],
        request_timeout=45,max_retries=10,
        retry_on_timeout=True,
        headers={
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
    )
    except Exception as e:
        logging.error(f'[!] Elasticsearch client config error: {str(e)}')
        return
    # Rules Base Folder
    rules_folder = os.getenv('rules_folder','rules')
    # Rules configs json save file
    configs_json_file = 'Elalert_rules.json'
    # lock folder
    lock_folder = 'lock'
    # Start config setup for rules if any in 
    config = Config(client=es_client,configs_json_file=configs_json_file, rules_folder=rules_folder,lock_folder=lock_folder)
    if verbose:
        logging.info("[*] Elalert setup is complete. Monitoring started..")     
    passed_rules = config.configure_app_rules()
    logging.info(f"[*] {len(passed_rules)} custom rules configured. Started monitoring...")
    # Use an initial empty rules
    custom_rules = []
    # Check if rules have been configured
    locked_rules_path = os.path.join(lock_folder,configs_json_file)
    if os.path.exists(locked_rules_path):
    # Load the rules
        loaded = load_from_json(locked_rules_path)
        if loaded and isinstance(loaded,list):
            for rule in loaded:
                # Use base config for missing config keys in rule settings
                complete_rule = {**base_config,**rule}
                # Append to list
                custom_rules.append(complete_rule)
    # If no rules are configured, use base config
    if not custom_rules:
        custom_rules.append(base_config)
    # Initialize db
    initdb = _initialize_sqlite(verbose=verbose)
    if not initdb:
        base_config['storage_type'] = 'file_storage'   
    # Start monitoring  
    with ThreadPoolExecutor(max_workers=min(len(custom_rules), 5) ) as executor:
        while True:
            try:
                futures = []
                for rule in custom_rules:
                    rule_config = {**base_config,**rule}
                    rule_obj = ElasticAlerts(es_client=es_client,**rule_config)
                    futures.append(executor.submit(rule_obj.fetch_kibana_alerts))
                    
                for future in as_completed(futures):
                    try:
                        future.result(timeout= rule_config.get('interval',30) * 2)
                    except Exception as e:
                        logging.error(f"Thread error: {str(e)}")
            except KeyboardInterrupt:
                executor.shutdown(wait=True)
                break

if __name__ == "__main__":
    load_dotenv()
    main()