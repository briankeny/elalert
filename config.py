import json
import yaml
import os
import logging

# This python function loads rules config from rules folder
class Config:
    def __init__(self,client,rules_folder='rules',configs_json_file='Elalert_rules.json',lock_folder='lock'):
        self.es_client = client
        self.RULES_FOLDER_PATH = rules_folder
        self.LOCK_FOLDER = lock_folder
        self.CONFIGS_JSON_FILE= configs_json_file
    
    # Put everything together and save to configs json file
    def configure_app_rules(self):
        config_list = []
        if self.RULES_FOLDER_PATH and os.path.exists(self.RULES_FOLDER_PATH):
            yaml_files = self.mount_rules_folder_return_yaml_files()
            if yaml_files and isinstance(yaml_files,list):
                for rule_file in yaml_files:
                    try:
                        rule_file_path = os.path.join(self.RULES_FOLDER_PATH,rule_file)
                        content = self.read_rule_yaml_file_content(rule_file_path)
                        formated = self.extract_data_from_yaml(content)
                        config  = formated.get('config',{})
                        es_body = config.get('es_body',{})
                        es_index = config.get('es_index','.alerts-*')
                        rule_name = formated.get('rule_name',rule_file)
                        passed = self.check_es_query_validity(es_index=es_index,es_body=es_body,rule_name=rule_name)
                        if passed:
                            config_list.append(config)
                        if len(config_list) > 0:
                            self.save_passed_rules_configs_to_file_in_lock_folder(data=config_list)
                    except Exception as e:
                        logging.error(f'[!] Config Error: {str(e)}')
                        continue
        return config_list
    
    
    # Test the rule from yaml file
    def check_es_query_validity(self,es_index,es_body,rule_name=''):
        try:
            resp = self.es_client.indices.validate_query(index=es_index,body=es_body,explain=True)
            is_valid =  True if resp.get('valid',False) == True else False
            if not is_valid:
                explanation = resp.get('explanations',[{}])[0].get('error',f' {rule_name} Validation Error')
                raise ValueError(str(explanation))
            return is_valid
        except Exception as e:
            raise ValueError(str(e))
    
    # Extract config data from yaml file
    def extract_data_from_yaml(self,file_content):
        if file_content and isinstance(file_content,dict):
            mandatory = ['config','name']
            for key in mandatory:
                if key not in file_content.keys():
                    raise ValueError(f'Missing config or name keys. name: str, config: dict')
            extracted_config = self.check_yaml_syntax(config=file_content.get('config',{}))
            return {
                'rule_name': file_content.get('name'),
                'config': extracted_config
            }
        else:
            raise ValueError(f'Content {file_content} is not a proper Elalert rule format')
    
    # Check the yaml syntax
    def check_yaml_syntax(self, config=None, mandatory_config_keys=None):
        if config is None:
            config = {}
        if mandatory_config_keys is None:
            mandatory_config_keys = ['es_body', 'es_index']

        configurable_config_keys = [
            'pytz_timezone', 'hits_size', 'save', 'verbose', 'elastic_url', 'elastic_api_key',
            'cleanup_schedule', 'interval', 'timeframe', 'save_file', 'max_alerts_per_batch',
            'webhook_url', 'ignored_alert_keywords', 'message_template'
        ]
        
        configurable_config_keys.extend(mandatory_config_keys)
        config_data = {}

        for key in mandatory_config_keys:
            if key not in config:
                raise ValueError(f'Missing mandatory key {key}')
        
        for k in configurable_config_keys:
            if k in config:
                config_data[k] = config[k]

        return config_data

            
    # Return a list of yaml files in the rules directory
   # config.py (adjust path handling)
    def mount_rules_folder_return_yaml_files(self):
        yaml_files = []
        if os.path.exists(self.RULES_FOLDER_PATH):
            for root, _, files in os.walk(self.RULES_FOLDER_PATH):
                for f in files:
                    if f.lower().endswith(('.yaml', '.yml')):
                        # Use relative path from mount root
                        rel_path = os.path.relpath(os.path.join(root, f), self.RULES_FOLDER_PATH)
                        yaml_files.append(rel_path)
        return yaml_files

    # Save a formatted rule config to rule json file
    def save_passed_rules_configs_to_file_in_lock_folder(self,data=None):
        if not os.path.exists(self.LOCK_FOLDER):
            os.mkdir(self.LOCK_FOLDER)
        new_file_path = os.path.join(self.LOCK_FOLDER,self.CONFIGS_JSON_FILE)
        unique_data = [json.loads(x) for x in {json.dumps(d, sort_keys=True) for d in data}]
        self.save_to_json(data=unique_data,file_name_or_path=new_file_path)
    
    # Read the contents of yaml rule file 
    def read_rule_yaml_file_content(self,file_name_or_path=None):
        if file_name_or_path:
            try:
                with open(file_name_or_path,'r') as fl:
                    data =  yaml.safe_load(fl.read())
                return data
            except Exception as e:
                raise ValueError(str(e))
            
    # Save data to a JSON file
    def save_to_json(self, data=None, file_name_or_path=None):
        """Saves data to a JSON file."""
        try:
            # Only need to check file_name, since data={} is valid
            if file_name_or_path and isinstance(file_name_or_path,str):  
                with open(file_name_or_path, "w") as f:
                    json.dump(data or [], f, indent=4) 
            else:
                raise ValueError('Filename should be a string or a path like object')
        except Exception as e:
            logging.error(f'[?] Could not save JSON file {file_name_or_path}: {str(e)}')
            