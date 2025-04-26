import asyncio
import json
import logging 
import os
import time
import pytz
from datetime import datetime, timedelta
from jinja2 import BaseLoader, Environment, select_autoescape
import aiohttp

class ElasticAlerts:
    def __init__(self,es_index='.alerts-*',webhook_url=None,timeframe=60,max_alerts_per_batch=10,hits_size=100,save_file='alerts.json',save=False,verbose=False,pytz_timezone=None,elastic_url=None,elastic_api_key=None,es_body=None,ignored_alert_keywords=[],message_template=None,interval=60,cleanup_schedule=['0:00'],app_log_file='Elalert.log',es_client=None):
        # General Settings
        self.webhook_url = webhook_url
        self.timeframe = timeframe or interval
        self.interval = interval
        self.max_alerts_per_batch = max_alerts_per_batch 
        self.save = save 
        self.verbose = verbose 
        self.ignored_alert_keywords= self.remove_blanks_from_list(ignored_alert_keywords) if isinstance(ignored_alert_keywords,list) else [] 
        self.message_template = message_template
        # JSON save file
        self.app_log_file = app_log_file
        self.JSON_SAVE_FILE = save_file
        self.cleanup_schedule = cleanup_schedule
        # Timezone setting
        self.pytz_timezone = pytz_timezone
        self.TIMEZONE=None
        # DEFAULT REUSABLE QUERY
        self.hits_size = hits_size 
        # General communication hook 
        default_body = {
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{self.timeframe}", "lte": "now"}}}]
                }
            },
            "size": self.hits_size,
        }
        #  Elastic / Kibana Settings
        self.elastic_url = elastic_url 
        self.es_index = es_index if es_index else '.alerts-*'
        self.es_body= es_body if es_body else default_body
        self.elastic_api_key = elastic_api_key 
        # Elastic search module
        self.client = es_client
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
           
    # Load Timezone
    def _load_timezone(self):
        if self.pytz_timezone:
            try:
                # Timezone setting
                self.TIMEZONE= pytz.timezone(self.pytz_timezone)
            except Exception as e:
                logging.error(f'[?] Error loading timezone: {str(e)}')
                # Fallback to UTC
                self.TIMEZONE = pytz.timezone('UTC')

    # Fetch Alerts Data from elastic search
    def _fetch_alerts(self):
        """Fetch alerts from provided Elastic index"""
        try:
            resp = self.client.search(index=self.es_index,body=self.es_body)
            return resp.get('hits', {}).get('hits', [])
        except Exception as e:
            logging.error(f"[?] Error fetching alerts: {e}")
            return []

    # Process the alerts by extracting required fields
    def _process_alerts(self, alerts):
        """Process alerts and extract relevant information."""
        alerts = alerts or []
        if self.verbose:
            logging.info(f'[+] Found {len(alerts)} alerts...')
        extracted_data = []
        for alert in alerts:
            data = alert.get('_source', {})
            if self.TIMEZONE and data.get('kibana.alert.start') and data.get('@timestamp'):
                data['kibana.alert.start'] = datetime.fromisoformat(data['kibana.alert.start']).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
                data['@timestamp'] = datetime.fromisoformat(data['@timestamp']).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
            extracted_data.append(data)
            if self.verbose:
                logging.info(f"[-] {data.get('kibana.alert.status','unknown status')} - {data.get('kibana.alert.reason','')}")
        return extracted_data
    
    # Send notifications via email and webhook
    def _send_notifications(self, alerts):
        """Send notifications via email and webhook"""
        if not alerts:
            if self.verbose:
                logging.info('[?] 0 alerts found. Skipping notifications...')
            return
        notify_count=0
        for _alert in alerts:
            if notify_count <= self.max_alerts_per_batch and not self.ignored_alert(message=_alert.get('kibana.alert.reason','')):
                message = self._render_template(_alert)
                self.brief_notify(message=message,web_hook=self.webhook_url)
                notify_count+=1
    
    # Ignore Certain alerts based on keywords
    def ignored_alert(self,message=''):
        # Ignore Depreciated warnings for TLS certificate
        if self.ignored_alert_keywords and any(keyword in message for keyword in self.ignored_alert_keywords):
            return True
        return False
    
    def remove_blanks_from_list(self,lst):
        return list(filter(None, lst))
    
    # Fetch and process alerts
    def fetch_kibana_alerts(self):
        """Fetch and process alerts """
        self.perform_cleanup()
        self._load_timezone()
        if self.verbose:
            logging.info(f'[-]  Fetching alerts from elastic {self.es_index} index started...')
        alerts = self._fetch_alerts()
        processed_alerts = self._process_alerts(alerts)
        self._send_notifications(processed_alerts)
        if self.verbose:   
            logging.info(f"[+] Fetching Alerts complete. Concluded {len(processed_alerts)} ...") 
        if self.save:
            self.save_alerts(processed_alerts) 
        # Sleep for before next fetch
        if self.verbose:
            logging.info(f'[*] Sleeping for {self.interval} seconds...')
        time.sleep(self.interval)
        return processed_alerts
    def _render_template(self, _alert):
        # Use the template from config or fallback
        template_str = self.message_template or self.default_template()        
        try:
            template = self.env.from_string(template_str)
            return template.render(
                alert=_alert,  # Simplified variable name
                timezone=self.TIMEZONE,
                now=datetime.now(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S'),
                duration_format=self.format_duration
            )
        except Exception as e:
            logging.error(f"[?] Template rendering error: {str(e)}")
            return "Error generating alert message"

    @staticmethod
    def default_template():
        return """\
{% if alert.get('kibana.alert.status','active') == 'active' %}🚨{% else %}✅{% endif %} **{{ alert.get('kibana.alert.rule.name','')|e }}** {% if alert.get('kibana.alert.status','active') == 'active' %}🔴{% else %}🟢{% endif %}

**Alert Status**: {{ alert.get('kibana.alert.status', 'N/A') }}
**Started**: {{ alert.get('kibana.alert.start', 'N/A') }}
**Timestamp**: {{ now }}
**Duration**: {{ duration_format(alert.get('kibana.alert.duration.us', 0)) }}
**Threshold**: {{ alert.get('kibana.alert.evaluation.threshold', 'N/A') }}

**Reason**: {{ alert.get('kibana.alert.reason', 'No reason provided')|e }}
**Rule Category**: {{ alert.get('kibana.alert.rule.category', 'N/A')|e }}
**Features**: {{ alert.get('kibana.alert.rule.consumer', 'N/A') }}
"""

    def format_duration(self, microseconds):
        # Helper function for duration formatting
        hours = microseconds // 3600000000
        minutes = (microseconds % 3600000000) // 60000000
        seconds = (microseconds % 60000000) // 1000000
        return f"{hours}h {minutes}m {seconds}s"
    
     # Send a brief notification 
    def brief_notify(self,message,web_hook=None):
        """ Send A Brief Notification"""
        if web_hook:
            asyncio.run(self.send_via_hook_async(message, web_hook)) 
    
     # Send a notification to a channel via webhook.
    async def send_via_hook_async(self, message, hook=None):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    hook,
                    json={"text": message},
                    timeout=5
                ) as response:
                    response.raise_for_status()
            except Exception as e:
                logging.error(f"[?] Async webhook error: {str(e)}")
            
    # Save alert if save is enabled
    def save_alerts(self,alerts):
        if self.save:
            self.save_to_json(data=alerts)
            
    # Save data to a JSON file
    def save_to_json(self, data=None):
        """Saves data to a JSON file."""
        exists_prev_data = True if os.path.exists(self.JSON_SAVE_FILE) else False
        keep_data = self.load_from_json(self.JSON_SAVE_FILE) if exists_prev_data else []
        keep_data.extend(data)
        try:
            # Only need to check file_name, since data={} is valid
            if self.JSON_SAVE_FILE and isinstance(self.JSON_SAVE_FILE,str):  
                with open(self.JSON_SAVE_FILE, "w") as f:
                    json.dump(data or [], f, indent=4) 
            else:
                raise ValueError('Filename should be a string or a path like object')
        except Exception as e:
            logging.error(f'[?] Could not save JSON file {self.JSON_SAVE_FILE}: {str(e)}')
    
    # Load data from a JSON file 
    def load_from_json(self,file_name_or_path=None):
        """Loads data from a JSON file."""
        try:
            with open(file_name_or_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f'[?] Error reading from JSON file {file_name_or_path}: {str(e)}')
            return []
        
    # Check if it's time to clean up files
    def time_to_cleanup_files(self):
        # Get current time in the specified timezone
        tz = pytz.timezone(self.pytz_timezone)
        now_tz_aware = datetime.now(tz)
        
        # Convert to naive datetime in the target timezone (strip timezone info)
        now_naive = now_tz_aware.replace(tzinfo=None)
        
        if isinstance(self.cleanup_schedule, list):
            for schedule_str in self.cleanup_schedule:
                try:
                    # Parse schedule time (naive datetime)
                    schedule_time = datetime.strptime(schedule_str, "%H:%M").time()
                    
                    # Create start and end datetimes in the same timezone (naive)
                    start_naive = datetime.combine(now_naive.date(), schedule_time)
                    end_naive = start_naive + timedelta(minutes=30)
                    now_naive =now_naive.replace(second=0, microsecond=0)
                    # Handle midnight crossover (e.g., 23:45 → 00:15 next day)
                    if end_naive < start_naive:
                        if now_naive >= start_naive or now_naive <= end_naive:
                            return True
                    else:
                        if start_naive <= now_naive <= end_naive:
                            return True
                except Exception as e:
                    logging.error(f'[?] Error parsing schedule {schedule_str}: {e}')
                    continue
        return False
 
    def perform_cleanup(self):
        cleanup_files = [self.JSON_SAVE_FILE]
        if self.time_to_cleanup_files():
            for fl in cleanup_files:
                try:
                    if os.path.exists(fl):
                        os.remove(fl)
                    if self.verbose:
                        logging.info(f'[+] Cleanup Removed file {fl}')
                except Exception as e:
                    logging.error(f'[?] Error removing file {fl}: {str(e)}')
        with open(self.app_log_file,'w') as f:
            f.write('')