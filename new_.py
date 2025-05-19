import asyncio
import json
import logging
import os
import time
import pytz
import sqlite3
from datetime import datetime, timedelta
from jinja2 import Environment, BaseLoader, select_autoescape
import aiohttp

class ElasticAlerts:
    def __init__(
        self,
        es_index='.alerts-*',
        webhook_url=None,
        timeframe=60,
        max_alerts_per_batch=10,
        hits_size=100,
        save_file='alerts.json',
        storage_type='json',  # 'json' or 'sqlite'
        sqlite_db='alerts.db',
        save=False,
        verbose=False,
        pytz_timezone=None,
        elastic_url=None,
        elastic_api_key=None,
        es_body=None,
        ignored_alert_keywords=[],
        message_template=None,
        interval=60,
        cleanup_schedule=['0:00'],
        cleanup_days=7,  # Keep alerts for 7 days
        app_log_file='cloudalert.log',
        es_client=None
    ):
        # General Settings
        self.webhook_url = webhook_url
        self.timeframe = timeframe or interval
        self.interval = interval
        self.max_alerts_per_batch = max_alerts_per_batch
        self.save = save
        self.verbose = verbose
        self.ignored_alert_keywords = self.remove_blanks_from_list(ignored_alert_keywords) if isinstance(ignored_alert_keywords, list) else []
        self.message_template = message_template
        # Storage Settings
        self.storage_type = storage_type.lower()
        self.JSON_SAVE_FILE = save_file
        self.SQLITE_DB = sqlite_db
        self.cleanup_schedule = cleanup_schedule
        self.cleanup_days = cleanup_days
        self.app_log_file = app_log_file
        # Timezone setting
        self.pytz_timezone = pytz_timezone
        self.TIMEZONE = None
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
        # Elastic / Kibana Settings
        self.elastic_url = elastic_url
        self.es_index = es_index if es_index else '.alerts-*'
        self.es_body = es_body if es_body else default_body
        self.elastic_api_key = elastic_api_key
        # Elasticsearch module
        self.client = es_client
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        # Initialize storage
        self._initialize_storage()

    def _initialize_storage(self):
        """Initialize storage (SQLite or JSON)."""
        if self.storage_type == 'sqlite':
            self._initialize_sqlite()
        elif self.storage_type == 'json':
            if self.verbose:
                logging.info(f'[+] Using JSON storage: {self.JSON_SAVE_FILE}')
        else:
            raise ValueError("storage_type must be 'sqlite' or 'json'")

    def _initialize_sqlite(self):
        """Initialize SQLite database and create alerts table."""
        try:
            with sqlite3.connect(self.SQLITE_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        kibana_alert_rule_uuid TEXT PRIMARY KEY,
                        kibana_alert_status TEXT,
                        kibana_alert_start TEXT,
                        timestamp TEXT,
                        kibana_alert_duration_us INTEGER,
                        kibana_alert_evaluation_threshold TEXT,
                        kibana_alert_reason TEXT,
                        kibana_alert_rule_name TEXT,
                        created_at TEXT
                    )
                ''')
                conn.commit()
                if self.verbose:
                    logging.info(f'[+] Initialized SQLite database: {self.SQLITE_DB}')
        except sqlite3.Error as e:
            logging.error(f'[?] Error initializing SQLite database: {str(e)}')
            raise

    def _load_timezone(self):
        """Load timezone."""
        if self.pytz_timezone:
            try:
                self.TIMEZONE = pytz.timezone(self.pytz_timezone)
            except Exception as e:
                logging.error(f'[?] Error loading timezone: {str(e)}')
                self.TIMEZONE = pytz.timezone('UTC')

    def _fetch_alerts(self):
        """Fetch alerts from provided Elastic index."""
        try:
            resp = self.client.search(index=self.es_index, body=self.es_body)
            return resp.get('hits', {}).get('hits', [])
        except Exception as e:
            logging.error(f"[?] Error fetching alerts: {e}")
            return []

    def _process_alerts(self, alerts):
        """Process alerts, check for duplicates, and return new alerts to send."""
        alerts = alerts or []
        if self.verbose:
            logging.info(f'[+] Found {len(alerts)} alerts...')
        new_alerts = []
        for alert in alerts:
            data = alert.get('_source', {})
            rule_uuid = data.get('kibana.alert.rule.uuid')
            if not rule_uuid:
                logging.warning('[?] Alert missing kibana.alert.rule.uuid, skipping')
                continue

            # Check if alert is already processed
            if self._is_alert_processed(rule_uuid):
                if self.verbose:
                    logging.info(f'[-] Skipping duplicate alert: {rule_uuid}')
                continue

            # Format timestamps if timezone is set
            if self.TIMEZONE:
                if data.get('kibana.alert.start'):
                    data['kibana.alert.start'] = datetime.fromisoformat(
                        data['kibana.alert.start'].replace('Z', '+00:00')
                    ).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
                if data.get('@timestamp'):
                    data['@timestamp'] = datetime.fromisoformat(
                        data['@timestamp'].replace('Z', '+00:00')
                    ).astimezone(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')

            # Prepare alert data for storage
            alert_data = {
                'kibana.alert.rule.uuid': rule_uuid,
                'kibana.alert.status': data.get('kibana.alert.status', ''),
                'kibana.alert.start': data.get('kibana.alert.start', ''),
                'timestamp': data.get('@timestamp', ''),
                'kibana.alert.duration.us': data.get('kibana.alert.duration.us', 0),
                'kibana.alert.evaluation.threshold': str(data.get('kibana.alert.evaluation.threshold', '')),
                'kibana.alert.reason': data.get('kibana.alert.reason', ''),
                'kibana.alert.rule.name': data.get('kibana.alert.rule.name', ''),
                'created_at': datetime.now(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S') if self.TIMEZONE else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            }
            new_alerts.append(alert_data)
            if self.verbose:
                logging.info(f"[-] {alert_data['kibana.alert.status']} - {alert_data['kibana.alert.reason']}")

        # Save new alerts if save is enabled
        if self.save and new_alerts:
            self._save_alerts(new_alerts)

        return new_alerts

    def _is_alert_processed(self, rule_uuid):
        """Check if an alert has already been processed."""
        if self.storage_type == 'sqlite':
            try:
                with sqlite3.connect(self.SQLITE_DB) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'SELECT 1 FROM alerts WHERE kibana_alert_rule_uuid = ?',
                        (rule_uuid,)
                    )
                    return cursor.fetchone() is not None
            except sqlite3.Error as e:
                logging.error(f'[?] Error checking alert in SQLite: {str(e)}')
                return False
        else:  # JSON
            existing_alerts = self.load_from_json(self.JSON_SAVE_FILE)
            return any(alert.get('kibana.alert.rule.uuid') == rule_uuid for alert in existing_alerts)

    def _save_alerts(self, alerts):
        """Save alerts to SQLite or JSON."""
        if self.storage_type == 'sqlite':
            try:
                with sqlite3.connect(self.SQLITE_DB) as conn:
                    cursor = conn.cursor()
                    for alert in alerts:
                        cursor.execute('''
                            INSERT OR IGNORE INTO alerts (
                                kibana_alert_rule_uuid,
                                kibana_alert_status,
                                kibana_alert_start,
                                timestamp,
                                kibana_alert_duration_us,
                                kibana_alert_evaluation_threshold,
                                kibana_alert_reason,
                                kibana_alert_rule_name,
                                created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            alert['kibana.alert.rule.uuid'],
                            alert['kibana.alert.status'],
                            alert['kibana.alert.start'],
                            alert['timestamp'],
                            alert['kibana.alert.duration.us'],
                            alert['kibana.alert.evaluation.threshold'],
                            alert['kibana.alert.reason'],
                            alert['kibana.alert.rule.name'],
                            alert['created_at']
                        ))
                    conn.commit()
                    if self.verbose:
                        logging.info(f'[+] Saved {len(alerts)} alerts to SQLite')
            except sqlite3.Error as e:
                logging.error(f'[?] Error saving alerts to SQLite: {str(e)}')
        else:  # JSON
            self.save_to_json(alerts)

    def _send_notifications(self, alerts):
        """Send notifications via webhook for new alerts."""
        if not alerts:
            if self.verbose:
                logging.info('[?] 0 new alerts found. Skipping notifications...')
            return
        notify_count = 0
        for alert in alerts:
            if notify_count >= self.max_alerts_per_batch or self.ignored_alert(alert.get('kibana.alert.reason', '')):
                continue
            message = self._render_template(alert)
            self.brief_notify(message=message, web_hook=self.webhook_url)
            notify_count += 1
            if self.verbose:
                logging.info(f'[+] Sent notification for alert: {alert["kibana.alert.rule.uuid"]}')

    def ignored_alert(self, message=''):
        """Ignore alerts based on keywords."""
        return self.ignored_alert_keywords and any(keyword in message for keyword in self.ignored_alert_keywords)

    def remove_blanks_from_list(self, lst):
        """Remove blank entries from a list."""
        return list(filter(None, lst))

    def fetch_kibana_alerts(self):
        """Fetch and process alerts."""
        self._load_timezone()
        if self.verbose:
            logging.info(f'[-] Fetching alerts from elastic {self.es_index} index...')
        alerts = self._fetch_alerts()
        processed_alerts = self._process_alerts(alerts)
        self._send_notifications(processed_alerts)
        if self.verbose:
            logging.info(f"[+] Fetching Alerts complete. Processed {len(processed_alerts)} new alerts...")
        self.perform_cleanup()
        time.sleep(int(self.interval))
        return processed_alerts

    def _render_template(self, alert):
        """Render alert message using Jinja2 template."""
        template_str = self.message_template or self.default_template()
        try:
            template = self.env.from_string(template_str)
            return template.render(
                alert=alert,
                timezone=self.TIMEZONE,
                now=datetime.now(self.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S') if self.TIMEZONE else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                duration_format=self.format_duration
            )
        except Exception as e:
            logging.error(f"[?] Template rendering error: {str(e)}")
            return "Error generating alert message"

    @staticmethod
    def default_template():
        """Default Jinja2 template for alert messages."""
        return """\
{% if alert['kibana.alert.status'] == 'active' %}🚨{% else %}✅{% endif %} **{{ alert['kibana.alert.rule.name']|e }}** {% if alert['kibana.alert.status'] == 'active' %}🔴{% else %}🟢{% endif %}

**Alert Status**: {{ alert['kibana.alert.status'] }}
**Started**: {{ alert['kibana.alert.start'] }}
**Timestamp**: {{ alert['timestamp'] }}
**Duration**: {{ duration_format(alert['kibana.alert.duration.us']) }}
**Threshold**: {{ alert['kibana.alert.evaluation.threshold'] }}

**Reason**: {{ alert['kibana.alert.reason']|e }}
**Rule Category**: {{ alert['kibana.alert.rule.category']|e }}
**Features**: {{ alert['kibana.alert.rule.consumer'] }}
"""

    def format_duration(self, microseconds):
        """Format duration in hours, minutes, seconds."""
        hours = microseconds // 3600000000
        minutes = (microseconds % 3600000000) // 60000000
        seconds = (microseconds % 60000000) // 1000000
        return f"{hours}h {minutes}m {seconds}s"

    def brief_notify(self, message, web_hook=None):
        """Send a brief notification."""
        if web_hook:
            asyncio.run(self.send_via_hook_async(message, web_hook))

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

    def save_to_json(self, data=None):
        """Save data to a JSON file."""
        data = data or []
        existing_data = self.load_from_json(self.JSON_SAVE_FILE) if os.path.exists(self.JSON_SAVE_FILE) else []
        existing_data.extend(data)
        try:
            with open(self.JSON_SAVE_FILE, "w") as f:
                json.dump(existing_data, f, indent=4)
            if self.verbose:
                logging.info(f'[+] Saved {len(data)} alerts to JSON')
        except Exception as e:
            logging.error(f'[?] Could not save JSON file {self.JSON_SAVE_FILE}: {str(e)}')

    def load_from_json(self, file_name_or_path=None):
        """Load data from a JSON file."""
        try:
            with open(file_name_or_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f'[?] Error reading from JSON file {file_name_or_path}: {str(e)}')
            return []

    def time_to_cleanup_files(self):
        """Check if it's time to clean up files or database."""
        tz = pytz.timezone(self.pytz_timezone) if self.pytz_timezone else pytz.UTC
        now_tz_aware = datetime.now(tz)
        now_naive = now_tz_aware.replace(tzinfo=None)
        if isinstance(self.cleanup_schedule, list):
            for schedule_str in self.cleanup_schedule:
                try:
                    schedule_time = datetime.strptime(schedule_str, "%H:%M").time()
                    start_naive = datetime.combine(now_naive.date(), schedule_time)
                    end_naive = start_naive + timedelta(minutes=30)
                    now_naive = now_naive.replace(second=0, microsecond=0)
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
                    cutoff = (datetime.now(self.TIMEZONE) - timedelta(days=self.cleanup_days)).strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute('DELETE FROM alerts WHERE created_at < ?', (cutoff,))
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
