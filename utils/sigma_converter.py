"""
SIGMA Rule Converter Utility

This module provides functionality to convert SIGMA detection rules into different formats:
- SQL queries for database-based detection
- Python functions for Detection as Code (DAC)
"""

import re
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class SigmaConverter:
    """Converts SIGMA rules to various formats (SQL, Python DAC)"""
    
    def __init__(self, llm_integration=None):
        self.llm_integration = llm_integration
        self.logger = logging.getLogger(__name__)
        
        # Common field mappings for different log sources
        self.field_mappings = {
            'windows': {
                'EventID': 'event_id',
                'Image': 'process_name',
                'CommandLine': 'command_line',
                'ParentImage': 'parent_process_name',
                'ParentCommandLine': 'parent_command_line',
                'User': 'username',
                'LogonId': 'logon_id',
                'ProcessId': 'process_id',
                'ParentProcessId': 'parent_process_id',
                'TargetFilename': 'file_path',
                'DestinationHostname': 'destination_host',
                'DestinationPort': 'destination_port',
                'SourceIp': 'source_ip',
                'DestinationIp': 'destination_ip'
            },
            'linux': {
                'exe': 'executable',
                'comm': 'command',
                'pid': 'process_id',
                'ppid': 'parent_process_id',
                'uid': 'user_id',
                'gid': 'group_id',
                'syscall': 'system_call'
            },
            'web': {
                'c-ip': 'client_ip',
                'cs-method': 'http_method',
                'cs-uri-stem': 'uri_path',
                'sc-status': 'status_code',
                'cs(User-Agent)': 'user_agent',
                'cs(Referer)': 'referer'
            },
            'sysmon': {
                'EventID': 'event_id',
                'Image': 'process_name',
                'CommandLine': 'command_line',
                'ParentImage': 'parent_process_name',
                'ParentCommandLine': 'parent_command_line',
                'User': 'username',
                'ProcessId': 'process_id',
                'ParentProcessId': 'parent_process_id',
                'TargetFilename': 'file_path',
                'DestinationHostname': 'destination_host',
                'DestinationPort': 'destination_port',
                'SourceIp': 'source_ip',
                'DestinationIp': 'destination_ip',
                'Hashes': 'file_hashes',
                'Company': 'file_company',
                'Description': 'file_description'
            },
            'crowdstrike_epp': {
                'event_simpleName': 'event_type',
                'ComputerName': 'hostname',
                'UserName': 'username',
                'ImageFileName': 'process_name',
                'CommandLine': 'command_line',
                'ParentBaseFileName': 'parent_process_name',
                'ProcessId': 'process_id',
                'ParentProcessId': 'parent_process_id',
                'SHA256HashData': 'file_hash_sha256',
                'MD5HashData': 'file_hash_md5'
            },
            'windows_defender': {
                'EventID': 'event_id',
                'ProcessName': 'process_name',
                'ProcessCommandLine': 'command_line',
                'User': 'username',
                'ThreatName': 'threat_name',
                'Path': 'file_path',
                'ActionType': 'action_type'
            },
            'palo_alto': {
                'src': 'source_ip',
                'dst': 'destination_ip',
                'sport': 'source_port',
                'dport': 'destination_port',
                'app': 'application',
                'action': 'action',
                'rule': 'rule_name',
                'user': 'username',
                'url': 'url',
                'threat': 'threat_name'
            },
            'okta': {
                'eventType': 'event_type',
                'actor.alternateId': 'username',
                'client.ipAddress': 'source_ip',
                'client.userAgent.rawUserAgent': 'user_agent',
                'target.alternateId': 'target_user',
                'outcome.result': 'result',
                'displayMessage': 'message'
            },
            'azure_ad': {
                'operationName': 'operation',
                'userPrincipalName': 'username',
                'ipAddress': 'source_ip',
                'userAgent': 'user_agent',
                'resultType': 'result_code',
                'resultDescription': 'result_description',
                'location': 'location'
            },
            'aws_cloudtrail': {
                'eventName': 'event_name',
                'eventSource': 'event_source',
                'userIdentity.type': 'user_type',
                'userIdentity.userName': 'username',
                'sourceIPAddress': 'source_ip',
                'userAgent': 'user_agent',
                'errorCode': 'error_code',
                'errorMessage': 'error_message'
            },
            'gcp_audit': {
                'protoPayload.methodName': 'method_name',
                'protoPayload.serviceName': 'service_name',
                'protoPayload.authenticationInfo.principalEmail': 'username',
                'protoPayload.requestMetadata.callerIp': 'source_ip',
                'severity': 'severity',
                'logName': 'log_name'
            },
            'office365': {
                'Operation': 'operation',
                'UserId': 'username',
                'ClientIP': 'source_ip',
                'UserAgent': 'user_agent',
                'ResultStatus': 'result_status',
                'ObjectId': 'object_id',
                'Workload': 'workload'
            },
            'splunk': {
                'sourcetype': 'source_type',
                'host': 'hostname',
                'source': 'source',
                'index': 'index_name',
                '_time': 'timestamp'
            },
            'elastic': {
                '@timestamp': 'timestamp',
                'host.name': 'hostname',
                'user.name': 'username',
                'process.name': 'process_name',
                'process.command_line': 'command_line',
                'source.ip': 'source_ip',
                'destination.ip': 'destination_ip'
            },
            'suricata': {
                'event_type': 'event_type',
                'src_ip': 'source_ip',
                'dest_ip': 'destination_ip',
                'src_port': 'source_port',
                'dest_port': 'destination_port',
                'proto': 'protocol',
                'alert.signature': 'signature',
                'alert.category': 'category'
            },
            'zeek': {
                'id.orig_h': 'source_ip',
                'id.resp_h': 'destination_ip',
                'id.orig_p': 'source_port',
                'id.resp_p': 'destination_port',
                'proto': 'protocol',
                'service': 'service',
                'duration': 'duration'
            },
            'osquery': {
                'name': 'query_name',
                'hostIdentifier': 'hostname',
                'calendarTime': 'timestamp',
                'unixTime': 'unix_timestamp',
                'columns.pid': 'process_id',
                'columns.name': 'process_name',
                'columns.cmdline': 'command_line'
            }
        }
        
        # SQL operators mapping
        self.sql_operators = {
            'equals': '=',
            'contains': 'LIKE',
            'startswith': 'LIKE',
            'endswith': 'LIKE',
            'regex': 'REGEXP',
            'gt': '>',
            'gte': '>=',
            'lt': '<',
            'lte': '<=',
            'in': 'IN'
        }
    
    def convert_to_sql(self, rule_content: str, target_table: Optional[str] = None,
                      log_source_type: str = 'windows', custom_field_mappings: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Convert SIGMA rule to SQL query"""
        try:
            # Parse SIGMA rule
            rule_data = yaml.safe_load(rule_content)
            
            if not rule_data or 'detection' not in rule_data:
                return {
                    'success': False,
                    'error': 'Invalid SIGMA rule: missing detection section'
                }
            
            # Extract metadata
            title = rule_data.get('title', 'Converted SIGMA Rule')
            description = rule_data.get('description', '')
            logsource = rule_data.get('logsource', {})
            detection = rule_data['detection']
            
            # Determine table name
            if not target_table:
                target_table = self._get_default_table_name(logsource, log_source_type)
            
            # Convert detection logic to SQL WHERE clause
            where_clause = self._convert_detection_to_sql(detection, log_source_type, custom_field_mappings)

            if not where_clause:
                return {
                    'success': False,
                    'error': 'Could not convert detection logic to SQL'
                }
            
            # Build complete SQL query
            sql_query = self._build_sql_query(target_table, where_clause, rule_data)
            
            return {
                'success': True,
                'sql_query': sql_query,
                'table_name': target_table,
                'metadata': {
                    'title': title,
                    'description': description,
                    'logsource': logsource,
                    'generated_at': datetime.now().isoformat()
                }
            }
            
        except yaml.YAMLError as e:
            return {
                'success': False,
                'error': f'Invalid YAML format: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Error converting to SQL: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def convert_to_python_dac(self, rule_content: str, function_name: Optional[str] = None) -> Dict[str, Any]:
        """Convert SIGMA rule to Python Detection as Code function"""
        try:
            # Parse SIGMA rule
            rule_data = yaml.safe_load(rule_content)
            
            if not rule_data or 'detection' not in rule_data:
                return {
                    'success': False,
                    'error': 'Invalid SIGMA rule: missing detection section'
                }
            
            # Extract metadata
            title = rule_data.get('title', 'Converted SIGMA Rule')
            description = rule_data.get('description', '')
            detection = rule_data['detection']
            
            # Generate function name if not provided
            if not function_name:
                function_name = self._generate_function_name(title)
            
            # Convert detection logic to Python
            python_logic = self._convert_detection_to_python(detection)
            
            if not python_logic:
                return {
                    'success': False,
                    'error': 'Could not convert detection logic to Python'
                }
            
            # Build complete Python function
            python_function = self._build_python_function(
                function_name, python_logic, rule_data
            )
            
            return {
                'success': True,
                'python_function': python_function,
                'function_name': function_name,
                'metadata': {
                    'title': title,
                    'description': description,
                    'generated_at': datetime.now().isoformat()
                }
            }
            
        except yaml.YAMLError as e:
            return {
                'success': False,
                'error': f'Invalid YAML format: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Error converting to Python DAC: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def convert_with_llm(self, rule_content: str, target_format: str,
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Use LLM for advanced conversion of complex SIGMA rules"""
        if not self.llm_integration:
            return {
                'success': False,
                'error': 'LLM integration not available'
            }

        try:
            # Prepare context for LLM
            context = context or {}

            # Create conversion prompt
            prompt = self._create_conversion_prompt(rule_content, target_format, context)

            # Call LLM
            response = self.llm_integration._call_ollama(prompt)

            if response['success']:
                # Parse LLM response
                converted_code = self._extract_converted_code(response['content'], target_format)

                return {
                    'success': True,
                    'converted_code': converted_code,
                    'raw_response': response['content'],
                    'target_format': target_format
                }
            else:
                return response

        except Exception as e:
            self.logger.error(f"Error in LLM conversion: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _get_default_table_name(self, logsource: Dict[str, Any], log_source_type: str) -> str:
        """Generate default table name based on log source"""
        category = logsource.get('category', '')
        product = logsource.get('product', '')
        service = logsource.get('service', '')

        if category == 'process_creation':
            return 'process_events'
        elif category == 'network_connection':
            return 'network_events'
        elif category == 'file_event':
            return 'file_events'
        elif product == 'windows':
            if service == 'security':
                return 'winlog_security'
            elif service == 'system':
                return 'winlog_system'
            else:
                return 'windows_events'
        elif product == 'linux':
            return 'linux_events'
        else:
            return f'{log_source_type}_events'

    def _convert_detection_to_sql(self, detection: Dict[str, Any], log_source_type: str, custom_field_mappings: Optional[Dict[str, str]] = None) -> str:
        """Convert SIGMA detection logic to SQL WHERE clause"""
        try:
            condition = detection.get('condition', 'selection')
            where_parts = []

            # Process each selection/filter in detection
            for key, value in detection.items():
                if key == 'condition':
                    continue

                if isinstance(value, dict):
                    # Convert selection criteria to SQL
                    sql_part = self._convert_selection_to_sql(value, log_source_type, custom_field_mappings)
                    if sql_part:
                        where_parts.append(f"({sql_part})")

            if not where_parts:
                return ""

            # Process condition logic
            where_clause = self._process_condition_logic(condition, where_parts)

            return where_clause

        except Exception as e:
            self.logger.error(f"Error converting detection to SQL: {e}")
            return ""

    def _convert_selection_to_sql(self, selection: Dict[str, Any], log_source_type: str, custom_field_mappings: Optional[Dict[str, str]] = None) -> str:
        """Convert a single selection to SQL conditions"""
        conditions = []

        # Use custom field mappings if provided, otherwise use predefined mappings
        if custom_field_mappings:
            field_mapping = custom_field_mappings
        else:
            field_mapping = self.field_mappings.get(log_source_type, {})

        for field, value in selection.items():
            # Handle SIGMA field modifiers (e.g., field|contains, field|endswith)
            base_field = field
            modifier = None

            if '|' in field:
                base_field, modifier = field.split('|', 1)

            # Map field name
            sql_field = field_mapping.get(base_field, base_field.lower())

            # Handle different value types with modifiers
            if isinstance(value, str):
                sql_condition = self._convert_string_value_to_sql_with_modifier(sql_field, value, modifier)
            elif isinstance(value, list):
                sql_condition = self._convert_list_value_to_sql(sql_field, value)
            elif isinstance(value, (int, float)):
                sql_condition = f"{sql_field} = {value}"
            else:
                sql_condition = f"{sql_field} = '{value}'"

            if sql_condition:
                conditions.append(sql_condition)

        return " AND ".join(conditions)

    def _convert_string_value_to_sql(self, field: str, value: str) -> str:
        """Convert string value to SQL condition"""
        # Handle SIGMA wildcards and modifiers
        if value.startswith('*') and value.endswith('*'):
            # Contains
            clean_value = value.strip('*')
            return f"{field} LIKE '%{clean_value}%'"
        elif value.startswith('*'):
            # Ends with
            clean_value = value[1:]
            return f"{field} LIKE '%{clean_value}'"
        elif value.endswith('*'):
            # Starts with
            clean_value = value[:-1]
            return f"{field} LIKE '{clean_value}%'"
        elif value.startswith('re:'):
            # Regex
            regex_pattern = value[3:]
            return f"{field} REGEXP '{regex_pattern}'"
        else:
            # Exact match
            return f"{field} = '{value}'"

    def _convert_string_value_to_sql_with_modifier(self, field: str, value: str, modifier: Optional[str]) -> str:
        """Convert string value to SQL condition with SIGMA modifier"""
        if modifier == 'contains':
            return f"{field} LIKE '%{value}%'"
        elif modifier == 'startswith':
            return f"{field} LIKE '{value}%'"
        elif modifier == 'endswith':
            return f"{field} LIKE '%{value}'"
        elif modifier == 'regex':
            return f"{field} REGEXP '{value}'"
        elif modifier in ['gt', 'gte', 'lt', 'lte']:
            operator = self.sql_operators.get(modifier, '=')
            return f"{field} {operator} '{value}'"
        else:
            # No modifier or unknown modifier, use default logic
            return self._convert_string_value_to_sql(field, value)

    def _convert_list_value_to_sql(self, field: str, values: List[Any]) -> str:
        """Convert list of values to SQL IN clause"""
        if not values:
            return ""

        # Handle different value types in list
        sql_values = []
        for value in values:
            if isinstance(value, str):
                if '*' in value or value.startswith('re:'):
                    # For wildcards/regex in lists, use OR conditions
                    return " OR ".join([
                        self._convert_string_value_to_sql(field, v) for v in values
                    ])
                else:
                    sql_values.append(f"'{value}'")
            else:
                sql_values.append(str(value))

        if sql_values:
            return f"{field} IN ({', '.join(sql_values)})"
        return ""

    def _process_condition_logic(self, condition: str, where_parts: List[str]) -> str:
        """Process SIGMA condition logic and convert to SQL"""
        if not where_parts:
            return ""

        # Simple condition processing
        if condition == 'selection':
            return where_parts[0] if where_parts else ""
        elif 'and not' in condition.lower():
            # Handle "selection and not filter" pattern
            if len(where_parts) >= 2:
                return f"{where_parts[0]} AND NOT ({where_parts[1]})"
            else:
                return where_parts[0] if where_parts else ""
        elif 'and' in condition.lower():
            return " AND ".join(where_parts)
        elif 'or' in condition.lower():
            return " OR ".join(where_parts)
        elif 'not' in condition.lower():
            # Handle NOT logic
            if len(where_parts) >= 1:
                return f"NOT ({where_parts[0]})"
            else:
                return ""
        else:
            # Default to AND for complex conditions
            return " AND ".join(where_parts)

    def _build_sql_query(self, table_name: str, where_clause: str, rule_data: Dict[str, Any]) -> str:
        """Build complete SQL query"""
        title = rule_data.get('title', 'SIGMA Rule')
        description = rule_data.get('description', '')

        query = f"""-- SIGMA Rule: {title}
-- Description: {description}
-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SELECT *
FROM {table_name}
WHERE {where_clause}
ORDER BY timestamp DESC;"""

        return query

    def _convert_detection_to_python(self, detection: Dict[str, Any]) -> str:
        """Convert SIGMA detection logic to Python code"""
        try:
            condition = detection.get('condition', 'selection')
            python_parts = []

            # Process each selection/filter in detection
            for key, value in detection.items():
                if key == 'condition':
                    continue

                if isinstance(value, dict):
                    # Convert selection criteria to Python
                    python_part = self._convert_selection_to_python(key, value)
                    if python_part:
                        python_parts.append(python_part)

            if not python_parts:
                return ""

            # Process condition logic for Python
            python_logic = self._process_python_condition_logic(condition, python_parts)

            return python_logic

        except Exception as e:
            self.logger.error(f"Error converting detection to Python: {e}")
            return ""

    def _convert_selection_to_python(self, selection_name: str, selection: Dict[str, Any]) -> str:
        """Convert a single selection to Python conditions"""
        conditions = []

        for field, value in selection.items():
            # Handle SIGMA field modifiers
            base_field = field
            modifier = None

            if '|' in field:
                base_field, modifier = field.split('|', 1)

            # Handle different value types
            if isinstance(value, str):
                python_condition = self._convert_string_value_to_python_with_modifier(base_field, value, modifier)
            elif isinstance(value, list):
                python_condition = self._convert_list_value_to_python(base_field, value)
            elif isinstance(value, (int, float)):
                python_condition = f"event.get('{base_field}') == {value}"
            else:
                python_condition = f"event.get('{base_field}') == '{value}'"

            if python_condition:
                conditions.append(python_condition)

        if conditions:
            return " and ".join(conditions)
        return ""

    def _convert_string_value_to_python(self, field: str, value: str) -> str:
        """Convert string value to Python condition"""
        # Handle SIGMA wildcards and modifiers
        if value.startswith('*') and value.endswith('*'):
            # Contains
            clean_value = value.strip('*')
            return f"'{clean_value}' in str(event.get('{field}', ''))"
        elif value.startswith('*'):
            # Ends with
            clean_value = value[1:]
            return f"str(event.get('{field}', '')).endswith('{clean_value}')"
        elif value.endswith('*'):
            # Starts with
            clean_value = value[:-1]
            return f"str(event.get('{field}', '')).startswith('{clean_value}')"
        elif value.startswith('re:'):
            # Regex
            regex_pattern = value[3:]
            return f"re.search(r'{regex_pattern}', str(event.get('{field}', '')))"
        else:
            # Exact match
            return f"event.get('{field}') == '{value}'"

    def _convert_string_value_to_python_with_modifier(self, field: str, value: str, modifier: Optional[str]) -> str:
        """Convert string value to Python condition with SIGMA modifier"""
        if modifier == 'contains':
            return f"'{value}' in str(event.get('{field}', ''))"
        elif modifier == 'startswith':
            return f"str(event.get('{field}', '')).startswith('{value}')"
        elif modifier == 'endswith':
            return f"str(event.get('{field}', '')).endswith('{value}')"
        elif modifier == 'regex':
            return f"re.search(r'{value}', str(event.get('{field}', '')))"
        elif modifier in ['gt', 'gte', 'lt', 'lte']:
            if modifier == 'gt':
                return f"event.get('{field}', 0) > {value}"
            elif modifier == 'gte':
                return f"event.get('{field}', 0) >= {value}"
            elif modifier == 'lt':
                return f"event.get('{field}', 0) < {value}"
            elif modifier == 'lte':
                return f"event.get('{field}', 0) <= {value}"
            else:
                return f"event.get('{field}', 0) > {value}"  # Default fallback
        else:
            # No modifier or unknown modifier, use default logic
            return self._convert_string_value_to_python(field, value)

    def _convert_list_value_to_python(self, field: str, values: List[Any]) -> str:
        """Convert list of values to Python condition"""
        if not values:
            return ""

        # Handle different value types in list
        python_conditions = []
        for value in values:
            if isinstance(value, str):
                if '*' in value or value.startswith('re:'):
                    # For wildcards/regex in lists, use OR conditions
                    python_conditions.append(self._convert_string_value_to_python(field, value))
                else:
                    python_conditions.append(f"event.get('{field}') == '{value}'")
            else:
                python_conditions.append(f"event.get('{field}') == {value}")

        if python_conditions:
            return f"({' or '.join(python_conditions)})"
        return ""

    def _process_python_condition_logic(self, condition: str, python_parts: List[str]) -> str:
        """Process SIGMA condition logic for Python"""
        if not python_parts:
            return ""

        # Simple condition processing for Python
        if condition == 'selection':
            return python_parts[0] if python_parts else ""
        elif 'and not' in condition.lower():
            # Handle "selection and not filter" pattern
            if len(python_parts) >= 2:
                return f"({python_parts[0]}) and not ({python_parts[1]})"
            else:
                return python_parts[0] if python_parts else ""
        elif 'and' in condition.lower():
            return " and ".join([f"({part})" for part in python_parts])
        elif 'or' in condition.lower():
            return " or ".join([f"({part})" for part in python_parts])
        elif 'not' in condition.lower():
            # Handle NOT logic
            if len(python_parts) >= 1:
                return f"not ({python_parts[0]})"
            else:
                return ""
        else:
            # Default to AND for complex conditions
            return " and ".join([f"({part})" for part in python_parts])

    def _generate_function_name(self, title: str) -> str:
        """Generate Python function name from rule title"""
        # Clean title and convert to snake_case
        clean_title = re.sub(r'[^\w\s]', '', title)
        words = clean_title.lower().split()
        function_name = '_'.join(words[:5])  # Limit to 5 words

        # Ensure it starts with letter and is valid Python identifier
        if not function_name or not function_name[0].isalpha():
            function_name = f"detect_{function_name}"

        return function_name

    def _build_python_function(self, function_name: str, python_logic: str, rule_data: Dict[str, Any]) -> str:
        """Build complete Python function"""
        title = rule_data.get('title', 'SIGMA Rule')
        description = rule_data.get('description', '')
        author = rule_data.get('author', 'Unknown')
        level = rule_data.get('level', 'medium')

        function_code = f'''import re
from typing import Dict, Any, Bool

def {function_name}(event: Dict[str, Any]) -> bool:
    """
    {title}

    Description: {description}
    Author: {author}
    Level: {level}
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    Args:
        event: Dictionary containing log event data

    Returns:
        bool: True if event matches detection criteria, False otherwise
    """
    try:
        # Detection logic converted from SIGMA rule
        return {python_logic}
    except Exception as e:
        # Log error and return False for safety
        import logging
        logging.getLogger(__name__).error(f"Error in {function_name}: {{e}}")
        return False

# Example usage:
# if {function_name}(log_event):
#     # Handle detection match
'''

        return function_code

    def _create_conversion_prompt(self, rule_content: str, target_format: str, context: Dict[str, Any]) -> str:
        """Create prompt for LLM conversion"""
        base_prompt = f"""Convert the following SIGMA detection rule to {target_format.upper()} format.

SIGMA Rule:
```yaml
{rule_content}
```

Requirements:
- Generate clean, production-ready {target_format.upper()} code
- Include proper comments and documentation
- Handle edge cases and errors gracefully
- Follow best practices for {target_format.upper()}
"""

        if target_format.lower() == 'sql':
            table_name = context.get('target_table', 'events') if context else 'events'
            log_source = context.get('log_source_type', 'windows') if context else 'windows'
            base_prompt += f"""
- Generate production-ready SQL query for threat hunting and detection
- Use table name '{table_name}' or derive appropriate table from log source
- Target log source type: {log_source}
- Use standard SQL syntax compatible with most SIEM databases (Splunk, Elastic, ClickHouse, etc.)
- Include comprehensive WHERE clauses for all detection criteria
- Handle SIGMA field modifiers correctly (contains -> LIKE '%value%', startswith -> LIKE 'value%', etc.)
- Add detailed comments explaining the detection logic and MITRE ATT&CK mapping
- Include proper field mappings for common log sources (Windows Event Logs, Sysmon, etc.)
- Use appropriate SQL functions for string matching, regex, and case-insensitive searches
- Handle multiple values in selections with proper OR conditions
- Implement complex condition logic (AND, OR, NOT operations) correctly
- Add ORDER BY timestamp DESC for chronological analysis
- Include rule metadata as SQL comments (title, description, level, author)
- Make the query optimized for performance in large datasets
- Handle edge cases and null values gracefully
- Use proper SQL escaping for special characters
- Include example usage and execution context in comments
"""
        elif target_format.lower() == 'python':
            function_name = context.get('function_name', 'detect_sigma_rule') if context else 'detect_sigma_rule'
            base_prompt += f"""
- Create a Detection as Code (DAC) function named '{function_name}' that takes an event dictionary as input
- Return boolean True/False for detection match
- Include proper type hints (Dict[str, Any] -> bool)
- Include comprehensive docstring with rule description, MITRE ATT&CK mapping, and usage examples
- Handle missing fields gracefully using .get() method with appropriate defaults
- Use appropriate Python patterns for string matching (in, startswith, endswith, regex)
- Handle SIGMA field modifiers (contains, startswith, endswith, regex) correctly
- Include proper error handling with try/except blocks
- Add logging for debugging purposes
- Follow PEP 8 style guidelines
- Make the function production-ready for security operations centers (SOCs)
- Include example usage in comments
- Handle case-insensitive matching where appropriate
- Support both single values and lists in SIGMA selections
- Implement proper condition logic (AND, OR, NOT operations)
"""

        # Add context if provided
        if context:
            context_str = ""
            for key, value in context.items():
                if key != 'function_name':  # Already handled above
                    context_str += f"- {key}: {value}\n"
            if context_str:
                base_prompt += f"\nAdditional Context:\n{context_str}"

        base_prompt += f"\nProvide only the {target_format.upper()} code without additional explanation."

        return base_prompt

    def _extract_converted_code(self, llm_response: str, target_format: str) -> str:
        """Extract converted code from LLM response"""
        # Look for code blocks
        if target_format.lower() == 'sql':
            # Extract SQL code blocks
            sql_pattern = r'```sql\n(.*?)\n```'
            matches = re.findall(sql_pattern, llm_response, re.DOTALL)
            if matches:
                return matches[0].strip()
        elif target_format.lower() == 'python':
            # Extract Python code blocks
            python_pattern = r'```python\n(.*?)\n```'
            matches = re.findall(python_pattern, llm_response, re.DOTALL)
            if matches:
                return matches[0].strip()

        # If no code blocks found, return the whole response
        return llm_response.strip()
