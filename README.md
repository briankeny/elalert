# Elalert
Elalert is an alerting tool for Elastic Stack. It monitors Elasticsearch data for alerts and sends notifications via a callback url. Configurable alerts fetching using custom rules declared in a yaml files inside rules directory or path string set in .env rules_directory setting

## Prerequisites
- Python 3.x
- Required dependencies installed (see installation section)
- Elastic Kibana API key stored in a `.env` file or passed via cli arguments

## Installation
1. Clone the repository:
   
   **HTTPS**
   ```bash
   git clone https://github.com/briankeny/elalert
   ```
   
   **or SSH**
   ```bash
   git clone git@github.com:briankeny/elalert.git
   ```
   
   Then navigate to the project directory:
   ```bash
   cd elalert
   ```

2. Create a Virtual Environment and Install dependencies:
   
   ```bash
   python -m venv venv
   ```

   Activate it:
   ```bash
   source venv/bin/activate
   ```  

   Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file and add the required variables as referenced in `.env.example`:   
   ```bash
   elastic_url=<your-elastic-url>
   elastic_api_key=<your-elastic-api-key>
   ```
4. Create a rules directory and add rules using format in example_rule.yaml

### 2. Run with Docker
#### Build the Docker image:
```bash
docker build -t elalert:latest .
```

#### Run the container:

-d: Runs the container in the background (detached mode).

--name Elalert: Assigns a specific name to the container.

-e Run the container datetime using Nairobi Timezone

```bash
docker run -d --name elalert
```
or without -d flag

```bash
docker run --name elalert 
```
to run the container in foreground.

#### ReStart/Stop the container:
```bash
docker start Elalert
docker stop Elalert
```

#### Remove the container (after stopping)
```bash
docker rm elalert
```

### Remove the image (optional)
```bash
docker rmi elalert:latest
```

### 3. Run as an Executable Script
Ensure all your environment variables are properly configured

```bash
 python main.py
```

Alternatively

Make the script executable:
```bash
chmod +x main.py
```

Add a shebang line at the beginning of `main.py`: Ensure that the path to your bin/env is correct

```python
#!/usr/bin/env python3
```
Then execute the script directly:
```bash
./main.py 
```

## Testing

For quick mock testing

```bash
pytest test_config.py -v
```

## Logging
Logs are saved to `Elalert.log` (or the specified file) and include timestamps.

## Error Handling
- The script handles unexpected errors and retries after the specified interval.
- Error messages are logged to the console and the log file.

## Features
- Fetch Alerts from Elastic Kibana via Elasticsearch module
- Send notifications via a webhook for alerts 
- Customizable monitoring interval
- Docker support for easy deployment
- Customizable alert message jinja2 template
- Script mock tests using pytest
- Rule examples in examples dir