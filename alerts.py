import asyncio
import json
import logging
import os
import sqlite3
import time
import pytz
from datetime import datetime, timedelta, timezone
from jinja2 import BaseLoader, Environment, select_autoescape
import aiohttp
 
class ElasticAlerts:
    def __init__(self,es_index='.alerts-*',webhook_url=None,timeframe=60,max_alerts_per_batch=10,hits_size=100,save_file='alerts.json',save=False,verbose=False,pytz_timezone=None,elastic_url=None,elastic_api_key=None,es_body=None,ignored_alert_keywords=[],message_template=None,interval=60,cleanup_schedule=['0:00'],app_log_file='Elalert.log',es_client=None,storage_type='sqlite', sqlite_db_path='alerts.db'):
        # Settings
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
        self.PROCESSED_ALERT_FILE = 'ALERTS_XCSGQJG.json'
        self.cleanup_schedule = cleanup_schedule
        # Timezone setting
        self.pytz_timezone = pytz_timezone
        self.TIMEZONE=None
        # DEFAULT REUSABLE QUERY
        self.hits_size = hits_size 
        default_body = {
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{self.timeframe}s", "lte": "now"}}}]
                }
            },
            "size": self.hits_size,
        }
        #  Elastic / Kibana Settings
        self.elastic_url = elastic_url 
        self.es_index = es_index if es_index else '.alerts-*'
        self.es_body= es_body if es_body else default_body
        self.elastic_api_key = elastic_api_key 
        self.client = es_client
        # Jinja2 environment
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )    
        self.SQLITE_DB =  sqlite_db_path
        self.storage_type = storage_type
        self.cleanup_days = 1
       
    def parse_interval_timeframe_to_int(self):
        try:
            self.timeframe = int(self.timeframe)
            self.interval = int(self.interval)
        except ValueError:
            self.interval = 60       
            self.timeframe = 60
    
    # Load Timezone
    def _load_timezone(self):
        """Load timezone."""
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
    
    def shortened_save_data(self,data):
        return [ { "kibana.alert.rule.uuid": alert.get('kibana.alert.rule.uuid'), "kibana.alert.instance.id": alert.get('kibana.alert.instance.id'), 'kibana.alert.start': alert.get('kibana.alert.start',None), 'kibana.alert.end':  alert.get('kibana.alert.end',None), 'kibana.alert.status': alert.get('kibana.alert.status','unknown')  } for alert in data if  alert.get('kibana.alert.instance.id')]
    
    def save_to_sqldb(self,alerts):
        if self.storage_type == 'sqlite':
            try:
                with sqlite3.connect(self.SQLITE_DB) as conn:
                    cursor = conn.cursor()
                    for alert in alerts:
                        cursor.execute('''
                            INSERT OR IGNORE INTO alerts (
                                kibana_alert_rule_uuid,
                                kibana_alert_instance_id,
                                kibana_alert_start,
                                kibana_alert_end,
                                kibana_alert_status
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', (
                            alert['kibana.alert.rule.uuid'],
                            alert['kibana.alert.instance.id'],
                            alert['kibana.alert.start'],
                            alert['kibana.alert.end'],
                            alert['kibana.alert.status']
                        ))
                    conn.commit()
                    if self.verbose:
                        logging.info(f'[+] Saved {len(alerts)} alerts to SQLite')
            except sqlite3.Error as e:
                logging.error(f'[?] Error saving alerts to SQLite: {str(e)}')
   
    def _is_alert_processed(self,rule_uuid,instance_id,start_time,end_time,status):
        """Check if an alert has already been processed."""
        if self.storage_type == 'sqlite':
            try:
                with sqlite3.connect(self.SQLITE_DB) as conn:
                    cursor = conn.cursor()
                    conditions = []
                    params = []
                    # Rule UUID and Instance ID are always present
                    conditions.append("kibana_alert_rule_uuid = ?")
                    params.append(rule_uuid)
                    conditions.append("kibana_alert_instance_id = ?")
                    params.append(instance_id)                    
                    # Handle start_time (could be NULL)
                    if start_time is not None:
                        conditions.append("kibana_alert_start = ?")
                        params.append(start_time)
                    else:
                        conditions.append("kibana_alert_start IS NULL")
                    # Handle end_time (could be NULL)
                    if end_time is not None:
                        conditions.append("kibana_alert_end = ?")
                        params.append(end_time)
                    else:
                        conditions.append("kibana_alert_end IS NULL")
                    # Status is always present
                    conditions.append("kibana_alert_status = ?")
                    params.append(status)                    
                    query = f"SELECT 1 FROM alerts WHERE {' AND '.join(conditions)}"
                    cursor.execute(query, params)
                    return cursor.fetchone() is not None
            except sqlite3.Error as e:
                logging.error(f'[?] Error checking alert in SQLite: {str(e)}')
                return False
        else:  
            # JSON        
            existing_alerts = self.load_from_json(self.PROCESSED_ALERT_FILE) if os.path.exists(self.PROCESSED_ALERT_FILE) else []
            for alert in existing_alerts:
                # Check if the alert has already been processed
                if alert.get('kibana.alert.rule.uuid') == rule_uuid and alert.get('kibana.alert.instance.id') == instance_id and alert.get('kibana.alert.start') == start_time:
                    # Match the status if it exists else continue search
                    if alert.get('kibana.alert.status') == status:
                        # Alert already exists
                        # Check status if recovered
                        # Avoid deduplication for recovered alerts
                        if status.lower() == 'recovered'and alert.get('kibana.alert.end') != end_time:
                            # New alert
                            return False
                        # Alert already processed 
                        return True       
            return False

    # Process the alerts by extracting required fields
    def _process_alerts(self, alerts):
        """Process alerts and extract relevant information."""
        alerts = alerts or []
        if self.verbose:
            logging.info(f'[+] Found {len(alerts)} alerts...')
        new_alerts = []
        new_set = set()
        for alert in alerts:
            data = alert.get('_source', {})
            instance_id = data.get('kibana.alert.instance.id')
            rule_uuid = data.get('kibana.alert.rule.uuid')
            if self.ignored_alert(data.get('kibana.alert.reason')):
                continue
            if not rule_uuid:
                logging.warning('[?] Alert missing kibana.alert.instance.id, skipping')
                continue            
            alert_key = (
                rule_uuid,
                instance_id,
                data.get('kibana.alert.start',None),
                data.get('kibana.alert.end',None),
                data.get('kibana.alert.status', 'unknown')
            )
            if alert_key in new_set:
                continue
            # Avoid batch deduplication
            new_set.add(alert_key)
            # Check if alert is already processed
            if self._is_alert_processed( rule_uuid=rule_uuid,instance_id=instance_id,start_time=data.get('kibana.alert.start',None),end_time=data.get('kibana.alert.end',None),status=data.get('kibana.alert.status', 'unknown')):
                if self.verbose:
                    logging.info(f'[-] Skipping duplicate alert: {rule_uuid}')
                continue           
            # Save the processed alert
            save_data = self.shortened_save_data([data])
            if self.storage_type == 'sqlite':
                self.save_to_sqldb(save_data)
            else:
                self.save_to_json(save_data,self.PROCESSED_ALERT_FILE)
            if self.TIMEZONE and data.get('kibana.alert.start') and data.get('@timestamp'):
                data['kibana.alert.start'] = datetime.fromisoformat(data['kibana.alert.start']).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
                data['@timestamp'] = datetime.fromisoformat(data['@timestamp']).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
            new_alerts.append(data)                        
            if self.verbose:
                logging.info(f"[-] {data.get('kibana.alert.status','unknown status')} - {data.get('kibana.alert.reason','')}")
        return new_alerts
    
    # Send notifications via email and webhook
    def _send_notifications(self, alerts):
        """Send notifications via email and webhook"""
        if not alerts:
            if self.verbose:
                logging.info('[?] 0 alerts found. Skipping notifications...')
            return
        notify_count=0
        for _alert in alerts:
            if notify_count <= self.max_alerts_per_batch:
                message = self._render_template(_alert)
                self.brief_notify(message=message,web_hook=self.webhook_url)
                notify_count+=1
    
    # Ignore Certain alerts based on keywords
    def ignored_alert(self,message=''):
        """Ignore alerts based on keywords."""
        if self.ignored_alert_keywords and any(keyword in message for keyword in self.ignored_alert_keywords):
            return True
        return False
    
    def remove_blanks_from_list(self,lst):
        """Remove blank entries from a list."""
        return list(filter(None, lst))
    
    # Fetch and process alerts
    def fetch_kibana_alerts(self):
        """Fetch and process alerts """
        self.parse_interval_timeframe_to_int()
        self._load_timezone()
        if self.verbose:
            logging.info(f'[-]  Fetching alerts from elastic {self.es_index} index...')
        alerts = self._fetch_alerts()
        processed_alerts = self._process_alerts(alerts)
        self._send_notifications(processed_alerts)
        if self.verbose:   
            logging.info(f"[+] Fetching Alerts complete. Concluded {len(processed_alerts)} ...") 
        # Save new alerts if save is enabled
        if self.save and processed_alerts:
            self.save_to_json(processed_alerts,self.JSON_SAVE_FILE)
        # Sleep before next fetch
        if self.verbose:
            logging.info(f'[*] Sleeping for {self.interval} seconds...')
        time.sleep(self.interval)
        self.perform_cleanup()
        return processed_alerts
    
    # Render template
    def _render_template(self, _alert):
        """Render alert message using Jinja2 template."""
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
    # Helper function for duration formatting
    def format_duration(self, microseconds):
        """Format duration in hours, minutes, seconds."""
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
        """Send a notification to a webhook asynchronously."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    hook,
                    json={"text": message},
                    timeout=10
                ) as response:
                    response.raise_for_status()
            except Exception as e:
                logging.error(f"[?] Async webhook error: {str(e)}")
     
    # Save data to a JSON file
    def save_to_json(self, data=None, file_name_or_path=None):
        """Saves data to a JSON file."""
        exists_prev_data = True if os.path.exists(file_name_or_path) else False
        keep_data = self.load_from_json(file_name_or_path) if exists_prev_data else []
        keep_data.extend(data)
        try:
            # Only need to check file_name, since data={} is valid
            if file_name_or_path and isinstance(file_name_or_path,str):
                with open(file_name_or_path, "w") as f:
                    json.dump(keep_data or [], f, indent=4) 
            else:
                raise ValueError('Filename should be a string or a path like object')
        except Exception as e:
            logging.error(f'[?] Could not save JSON file {file_name_or_path}: {str(e)}')
    
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
        """Check if it's time to clean up files."""
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
                    end_naive = start_naive + timedelta(seconds=self.interval)
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
        """Perform cleanup of old alerts."""
        if not self.time_to_cleanup_files():
            return
        if self.storage_type == 'sqlite':
            try:
                with sqlite3.connect(self.SQLITE_DB) as conn:
                    cursor = conn.cursor()
                    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=7)
                    cutoff = cutoff_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                    cursor.execute('DELETE FROM alerts WHERE kibana_alert_end < ?', (cutoff,))
                    conn.commit()
                    if self.verbose:
                        logging.info(f'[+] Cleaned up SQLite alerts older than {self.cleanup_days} days')
            except sqlite3.Error as e:
                logging.error(f'[?] Error cleaning up SQLite database: {str(e)}')
        else:  # JSON
            try:
                if os.path.exists(self.JSON_SAVE_FILE):
                    os.remove(self.JSON_SAVE_FILE)
                    if self.verbose:
                        logging.info(f'[+] Cleanup Removed file {self.JSON_SAVE_FILE}')
            except Exception as e:
                logging.error(f'[?] Error removing file {self.JSON_SAVE_FILE}: {str(e)}')
            with open(self.app_log_file, 'w') as f:
                f.write('')