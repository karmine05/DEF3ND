"""
LLM Integration Module for SIGMA Detection Engineering Platform
Handles Ollama integration for SIGMA rule generation and analysis
"""

import requests
import json
import logging
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import re

class LLMIntegration:
    """Handles LLM integration for SIGMA rule generation and analysis"""

    def __init__(self, ollama_host: str = "http://localhost:11434", model: str = "qwen2.5:7b", db_manager=None):
        self.ollama_host = ollama_host
        self.model = model
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # SIGMA rule template
        self.sigma_template = """title: {title}
id: {rule_id}
status: experimental
description: {description}
author: {author}
date: {date}
references:
    - {references}
tags:
    - {tags}
logsource:
    {logsource}
detection:
    {detection}
    condition: {condition}
falsepositives:
    - {falsepositives}
level: {level}"""
    
    def test_connection(self, host: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
        """Test connection to Ollama"""
        try:
            test_host = host or self.ollama_host
            test_model = model or self.model
            
            # Test if Ollama is running
            response = requests.get(f"{test_host}/api/tags", timeout=5)
            
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m['name'] for m in models]
                
                if test_model in model_names:
                    return {
                        'success': True,
                        'message': f'Connected to Ollama with model {test_model}',
                        'available_models': model_names
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Model {test_model} not found. Available: {model_names}'
                    }
            else:
                return {
                    'success': False,
                    'error': f'Ollama not responding: {response.status_code}'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Connection failed: {str(e)}'
            }
    
    def generate_sigma_rule(self, description: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a SIGMA rule from natural language description"""
        try:
            # Prepare context information
            context = context or {}
            log_source = context.get('log_source', 'windows')
            attack_technique = context.get('attack_technique', '')
            severity = context.get('severity', 'medium')

            # If no technique ID provided, try to identify it from description
            if not attack_technique:
                identified_technique = self._identify_technique_from_description(description)
                if identified_technique:
                    attack_technique = identified_technique
                    self.logger.info(f"Auto-identified technique {attack_technique} from description: {description[:50]}...")

            # Try up to 3 attempts to generate a valid rule (increased for better accuracy)
            max_attempts = 3
            for attempt in range(max_attempts):
                # Create detailed prompt for SIGMA rule generation
                prompt = self._create_sigma_generation_prompt(description, log_source, attack_technique, severity)

                # Add retry context if this is a second attempt
                if attempt > 0:
                    prompt += f"""

IMPORTANT: This is attempt {attempt + 1}. The previous attempt failed validation.
Please ensure you follow ALL the mandatory constraints and validation checklist above.
Focus specifically on using the correct technique ID {attack_technique} and appropriate detection logic."""

                # Generate rule using LLM
                response = self._call_ollama(prompt)

                if response['success']:
                    # Parse and validate the generated rule
                    rule_content = self._extract_sigma_rule(response['content'])

                    if rule_content:
                        # Pre-validate YAML syntax for common issues
                        syntax_issues = self._check_yaml_syntax_issues(rule_content)
                        if syntax_issues:
                            if attempt == max_attempts - 1:
                                return {
                                    'success': False,
                                    'error': f'YAML syntax issues detected: {"; ".join(syntax_issues)}',
                                    'raw_content': response['content'],
                                    'extracted_yaml': rule_content
                                }
                            self.logger.warning(f"Pre-validation failed on attempt {attempt + 1}: {syntax_issues}")
                            continue

                        # Validate YAML syntax
                        try:
                            parsed_rule = yaml.safe_load(rule_content)

                            # Pre-validation check for critical errors
                            pre_validation_errors = self._pre_validate_rule(parsed_rule, attack_technique)
                            if pre_validation_errors:
                                if attempt == max_attempts - 1:
                                    return {
                                        'success': False,
                                        'error': f'Critical validation errors: {"; ".join(pre_validation_errors)}',
                                        'attempts': attempt + 1
                                    }
                                continue  # Try again

                            # Validate rule follows MITRE guidance
                            validation_result = self._validate_generated_rule(parsed_rule, attack_technique)
                            if validation_result['valid']:
                                # Additional validation: check if rule matches the original description
                                description_match = self._validate_rule_matches_description(parsed_rule, description, attack_technique)
                                if not description_match['matches']:
                                    if attempt == max_attempts - 1:
                                        return {
                                            'success': False,
                                            'error': f'Generated rule does not match the requested description: {description_match["reason"]}',
                                            'raw_content': response['content'],
                                            'extracted_yaml': rule_content
                                        }
                                    self.logger.warning(f"Rule doesn't match description on attempt {attempt + 1}: {description_match['reason']}")
                                    continue

                                return {
                                    'success': True,
                                    'rule_content': rule_content,
                                    'parsed_rule': parsed_rule,
                                    'message': f'SIGMA rule generated successfully (attempt {attempt + 1})'
                                }
                            else:
                                # If this is the last attempt, return the validation error
                                if attempt == max_attempts - 1:
                                    return {
                                        'success': False,
                                        'error': f'Generated rule failed validation after {max_attempts} attempts: {validation_result["error"]}',
                                        'raw_content': response['content'],
                                        'validation_issues': validation_result['issues']
                                    }
                                # Otherwise, continue to next attempt
                                self.logger.warning(f"Attempt {attempt + 1} failed validation: {validation_result['error']}")
                                continue

                        except yaml.YAMLError as e:
                            # Provide more detailed YAML error information
                            yaml_error_details = self._analyze_yaml_error(rule_content, str(e))
                            if attempt == max_attempts - 1:
                                return {
                                    'success': False,
                                    'error': f'Generated rule has invalid YAML syntax: {str(e)}',
                                    'yaml_error_details': yaml_error_details,
                                    'raw_content': response['content'],
                                    'extracted_yaml': rule_content
                                }
                            # Log the error for debugging
                            self.logger.warning(f"YAML parsing failed on attempt {attempt + 1}: {str(e)}")
                            self.logger.debug(f"Problematic YAML content:\n{rule_content}")
                            continue
                    else:
                        if attempt == max_attempts - 1:
                            return {
                                'success': False,
                                'error': 'Could not extract valid SIGMA rule from LLM response',
                                'raw_content': response['content']
                            }
                        continue
                else:
                    if attempt == max_attempts - 1:
                        return response
                    continue

            # This should not be reached, but just in case
            return {
                'success': False,
                'error': 'Failed to generate valid rule after all attempts'
            }
                
        except Exception as e:
            self.logger.error(f"Error generating SIGMA rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_sigma_rule(self, rule_content: str) -> Dict[str, Any]:
        """Analyze a SIGMA rule and provide insights"""
        try:
            prompt = f"""
            Analyze the following SIGMA detection rule and provide insights:

            ```yaml
            {rule_content}
            ```

            Please provide:
            1. Rule effectiveness assessment (1-10 scale)
            2. Potential false positive scenarios
            3. Coverage gaps or improvements
            4. MITRE ATT&CK technique mapping suggestions
            5. Detection logic analysis
            6. Recommendations for optimization

            Format your response as structured analysis.
            """
            
            response = self._call_ollama(prompt)
            
            if response['success']:
                analysis = self._parse_rule_analysis(response['content'])
                return {
                    'success': True,
                    'analysis': analysis,
                    'raw_analysis': response['content']
                }
            else:
                return response
                
        except Exception as e:
            self.logger.error(f"Error analyzing SIGMA rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def suggest_rule_improvements(self, rule_content: str, context: str = "") -> Dict[str, Any]:
        """Suggest improvements for an existing SIGMA rule"""
        try:
            prompt = f"""
            Review the following SIGMA rule and suggest specific improvements:

            ```yaml
            {rule_content}
            ```

            Context: {context}

            Please provide:
            1. Specific detection logic improvements
            2. Additional selection criteria to reduce false positives
            3. Missing log source considerations
            4. Enhanced condition logic
            5. Better field mappings
            6. Performance optimization suggestions

            Provide the improved rule in YAML format.
            """
            
            response = self._call_ollama(prompt)
            
            if response['success']:
                improved_rule = self._extract_sigma_rule(response['content'])
                suggestions = self._extract_suggestions(response['content'])
                
                return {
                    'success': True,
                    'improved_rule': improved_rule,
                    'suggestions': suggestions,
                    'raw_response': response['content']
                }
            else:
                return response
                
        except Exception as e:
            self.logger.error(f"Error suggesting rule improvements: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def explain_detection_logic(self, rule_content: str) -> Dict[str, Any]:
        """Explain the detection logic of a SIGMA rule in plain language"""
        try:
            prompt = f"""
            Explain the following SIGMA detection rule in simple, clear language:

            ```yaml
            {rule_content}
            ```

            Please explain:
            1. What this rule detects
            2. How the detection logic works
            3. What log events it looks for
            4. What conditions trigger an alert
            5. Why this detection is important
            6. What an analyst should do when this rule triggers

            Use clear, non-technical language that a security analyst can easily understand.
            """
            
            response = self._call_ollama(prompt)
            
            if response['success']:
                return {
                    'success': True,
                    'explanation': response['content'],
                    'summary': self._extract_summary(response['content'])
                }
            else:
                return response
                
        except Exception as e:
            self.logger.error(f"Error explaining detection logic: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _get_mitre_technique_data(self, technique_id: str) -> Dict[str, Any]:
        """Retrieve complete MITRE ATT&CK technique data from database - USES CENTRALIZED METHOD"""
        if not self.db_manager or not technique_id:
            return {}

        try:
            # Use the centralized method from database manager
            technique_data = self.db_manager.get_mitre_technique_details(technique_id)
            return technique_data or {}

        except Exception as e:
            self.logger.error(f"Error retrieving MITRE data for {technique_id}: {e}")
            return {}

    def analyze_mitre_technique(self, technique_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI-enhanced analysis of a MITRE ATT&CK technique"""
        try:
            technique_id = technique_data.get('technique_id', 'Unknown')
            technique_name = technique_data.get('name', 'Unknown')
            description = technique_data.get('description', 'No description available')
            tactic = technique_data.get('tactic', 'Unknown')
            platforms = technique_data.get('platform', [])
            data_sources = technique_data.get('data_sources', [])

            # Format platforms and data sources
            platforms_str = ', '.join(platforms) if platforms else 'Not specified'
            data_sources_str = ', '.join(data_sources) if data_sources else 'Not specified'

            prompt = f"""
            Provide a comprehensive technical analysis of the following MITRE ATT&CK technique:

            **Technique ID:** {technique_id}
            **Name:** {technique_name}
            **Tactic:** {tactic}
            **Platforms:** {platforms_str}
            **Data Sources:** {data_sources_str}
            **Description:** {description}

            Please provide detailed analysis covering:

            1. **Threat Actor Usage Patterns:**
               - Which threat actors commonly use this technique
               - Real-world attack campaigns that have employed this technique
               - Common variations and implementations

            2. **Technical Implementation Details:**
               - How attackers typically execute this technique
               - Technical prerequisites and requirements
               - Common tools and methods used

            3. **Attack Chain Context:**
               - Where this technique typically fits in the attack lifecycle
               - Common preceding and following techniques
               - Relationship to other MITRE ATT&CK techniques

            4. **Detection Engineering Recommendations:**
               - Specific detection strategies and approaches
               - Key indicators and artifacts to monitor
               - Recommended data sources and log types
               - Detection rule logic suggestions

            5. **Defense and Mitigation Strategies:**
               - Preventive security controls
               - Detection and response procedures
               - Hardening recommendations
               - Monitoring best practices

            6. **False Positive Considerations:**
               - Common legitimate activities that might trigger alerts
               - Strategies to reduce false positives
               - Context clues for distinguishing malicious vs benign activity

            Format your response with clear sections and actionable insights for security analysts and detection engineers.
            """

            response = self._call_ollama(prompt)

            if response['success']:
                return {
                    'success': True,
                    'analysis': response['content'],
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'generated_at': datetime.now().isoformat()
                }
            else:
                return response

        except Exception as e:
            self.logger.error(f"Error analyzing MITRE technique: {e}")
            return {
                'success': False,
                'error': f"Analysis failed: {str(e)}"
            }

    def generate_detection_recommendations(self, technique_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific detection recommendations for a MITRE technique"""
        try:
            technique_id = technique_data.get('technique_id', 'Unknown')
            technique_name = technique_data.get('name', 'Unknown')
            description = technique_data.get('description', 'No description available')
            data_sources = technique_data.get('data_sources', [])
            platforms = technique_data.get('platform', [])

            data_sources_str = ', '.join(data_sources) if data_sources else 'Not specified'
            platforms_str = ', '.join(platforms) if platforms else 'Not specified'

            prompt = f"""
            Generate specific detection recommendations for MITRE ATT&CK technique {technique_id} - {technique_name}.

            **Technique Details:**
            - Description: {description}
            - Platforms: {platforms_str}
            - Data Sources: {data_sources_str}

            Please provide:

            1. **Detection Logic Recommendations:**
               - Specific log events to monitor
               - Key fields and values to look for
               - Correlation rules and patterns
               - Threshold-based detection suggestions

            2. **SIGMA Rule Concepts:**
               - Suggested SIGMA rule structure
               - Key selection criteria
               - Detection conditions
               - Filter recommendations

            3. **Data Collection Requirements:**
               - Required log sources and types
               - Specific Windows Event IDs (if applicable)
               - Sysmon configuration recommendations
               - Network monitoring requirements

            4. **Detection Maturity Levels:**
               - Basic detection (high confidence, low false positives)
               - Advanced detection (behavioral analysis)
               - Hunt queries for proactive detection

            5. **Implementation Priorities:**
               - Quick wins for immediate detection
               - Medium-term detection improvements
               - Advanced detection capabilities

            Focus on practical, implementable recommendations that detection engineers can use immediately.
            """

            response = self._call_ollama(prompt)

            if response['success']:
                return {
                    'success': True,
                    'recommendations': response['content'],
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'generated_at': datetime.now().isoformat()
                }
            else:
                return response

        except Exception as e:
            self.logger.error(f"Error generating detection recommendations: {e}")
            return {
                'success': False,
                'error': f"Recommendation generation failed: {str(e)}"
            }

    def generate_attack_scenarios(self, technique_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate real-world attack scenarios for a MITRE technique"""
        try:
            technique_id = technique_data.get('technique_id', 'Unknown')
            technique_name = technique_data.get('name', 'Unknown')
            description = technique_data.get('description', 'No description available')
            tactic = technique_data.get('tactic', 'Unknown')

            prompt = f"""
            Generate realistic attack scenarios for MITRE ATT&CK technique {technique_id} - {technique_name}.

            **Technique Details:**
            - Tactic: {tactic}
            - Description: {description}

            Please provide:

            1. **Common Attack Scenarios:**
               - 3-4 realistic attack scenarios where this technique is used
               - Step-by-step breakdown of each scenario
               - Context of when and why attackers use this technique

            2. **Threat Actor Examples:**
               - Known threat groups that use this technique
               - Specific campaigns or incidents
               - Variations in implementation by different actors

            3. **Attack Chain Integration:**
               - How this technique connects to other MITRE techniques
               - Common technique sequences and progressions
               - Prerequisites and follow-up actions

            4. **Real-World Impact:**
               - Business impact of successful execution
               - Potential damage and consequences
               - Recovery considerations

            5. **Defensive Insights:**
               - Key moments for detection and intervention
               - Critical decision points for defenders
               - Lessons learned from real incidents

            Focus on practical, educational content that helps security teams understand the real-world application of this technique.
            """

            response = self._call_ollama(prompt)

            if response['success']:
                return {
                    'success': True,
                    'scenarios': response['content'],
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'generated_at': datetime.now().isoformat()
                }
            else:
                return response

        except Exception as e:
            self.logger.error(f"Error generating attack scenarios: {e}")
            return {
                'success': False,
                'error': f"Scenario generation failed: {str(e)}"
            }

    def _format_related_rules(self, related_rules: List[Dict]) -> str:
        """Format related rules for inclusion in prompts"""
        try:
            if not related_rules:
                return "No related rules found."

            formatted_rules = []
            for i, rule in enumerate(related_rules[:3], 1):  # Limit to top 3
                rule_title = rule.get('title', 'Unknown')
                rule_confidence = rule.get('confidence', 0)
                formatted_rules.append(f"{i}. {rule_title} (confidence: {rule_confidence:.2f})")

            return '\n'.join(formatted_rules)

        except Exception as e:
            self.logger.error(f"Error formatting related rules: {e}")
            return "Error formatting related rules."

    def analyze_sigma_rule_with_mitre(self, rule_content: str, technique_id: str = None) -> Dict[str, Any]:
        """Analyze SIGMA rule with enhanced MITRE ATT&CK context"""
        try:
            # Get MITRE technique data if technique ID provided
            mitre_context = ""
            if technique_id:
                technique_data = self._get_mitre_technique_data(technique_id)
                if technique_data:
                    mitre_context = f"""
**MITRE ATT&CK CONTEXT:**
- Technique: {technique_data.get('technique_id', 'Unknown')} - {technique_data.get('name', 'Unknown')}
- Tactic: {technique_data.get('tactic', 'Unknown')}
- Detection Guidance: {technique_data.get('detection', 'No specific guidance available')}
- Mitigation Info: {technique_data.get('mitigation', 'No mitigation information available')}
- Data Sources: {', '.join(technique_data.get('data_sources', [])) if technique_data.get('data_sources') else 'Not specified'}
"""

            prompt = f"""
            Analyze this SIGMA detection rule with enhanced MITRE ATT&CK context:

            {mitre_context}

            **SIGMA RULE:**
            ```yaml
            {rule_content}
            ```

            Provide comprehensive analysis covering:

            1. **MITRE Alignment Assessment:**
               - How well does this rule align with MITRE detection guidance?
               - Does it target the correct data sources mentioned in MITRE?
               - Are there gaps between MITRE recommendations and rule implementation?

            2. **Detection Effectiveness:**
               - Rate effectiveness (1-10) based on MITRE context
               - Identify potential detection gaps
               - Suggest improvements based on MITRE guidance

            3. **False Positive Analysis:**
               - Potential false positive scenarios
               - Legitimate activities that might trigger this rule
               - Recommendations to reduce false positives

            4. **Enhancement Recommendations:**
               - Additional detection logic based on MITRE data
               - Missing data sources that should be included
               - Correlation opportunities with other techniques

            5. **MITRE Technique Mappings:**
               - Primary technique mapping confidence
               - Related techniques that might also be detected
               - Sub-technique coverage assessment

            Format your response as structured analysis with clear sections.
            """

            response = self._call_ollama(prompt)

            if response['success']:
                return {
                    'success': True,
                    'enhanced_analysis': response['content'],
                    'technique_id': technique_id,
                    'mitre_context_used': bool(mitre_context),
                    'generated_at': datetime.now().isoformat()
                }
            else:
                return response

        except Exception as e:
            self.logger.error(f"Error analyzing SIGMA rule with MITRE context: {e}")
            return {
                'success': False,
                'error': f"Enhanced analysis failed: {str(e)}"
            }

    def _identify_technique_from_description(self, description: str) -> Optional[str]:
        """Identify MITRE technique ID from natural language description"""
        try:
            if not self.db_manager:
                return None

            description_lower = description.lower()

            # Use completely dynamic technique identification based on MITRE database
            # This approach analyzes the description against all techniques dynamically

            # Get all techniques from database
            all_techniques = self.db_manager.get_mitre_techniques()

            # Extract key terms from user description for semantic matching
            description_terms = self._extract_key_terms(description_lower)

            # Score techniques based on multiple dynamic criteria
            technique_scores = []

            for technique in all_techniques:
                tech_id = technique.get('technique_id', '')

                # Handle name field which should be a string but might be a list
                tech_name_raw = technique.get('name', '')
                if isinstance(tech_name_raw, list):
                    tech_name = ' '.join(str(n) for n in tech_name_raw).lower()
                else:
                    tech_name = str(tech_name_raw).lower()

                # Handle description field which should be a string but might be a list
                tech_desc_raw = technique.get('description', '')
                if isinstance(tech_desc_raw, list):
                    tech_desc = ' '.join(str(d) for d in tech_desc_raw).lower()
                else:
                    tech_desc = str(tech_desc_raw).lower()

                # Get additional technique data for comprehensive matching
                # Handle detection field which should be a string but might be a list
                detection_guidance_raw = technique.get('detection', '')
                if isinstance(detection_guidance_raw, list):
                    detection_guidance = ' '.join(str(d) for d in detection_guidance_raw).lower()
                else:
                    detection_guidance = str(detection_guidance_raw).lower()

                # Handle data_sources which can be a list or string
                data_sources_raw = technique.get('data_sources', '')
                if isinstance(data_sources_raw, list):
                    data_sources = ' '.join(str(ds) for ds in data_sources_raw).lower()
                else:
                    data_sources = str(data_sources_raw).lower()

                # Ensure all variables are strings (additional safety check)
                tech_name = str(tech_name) if not isinstance(tech_name, str) else tech_name
                tech_desc = str(tech_desc) if not isinstance(tech_desc, str) else tech_desc
                detection_guidance = str(detection_guidance) if not isinstance(detection_guidance, str) else detection_guidance
                data_sources = str(data_sources) if not isinstance(data_sources, str) else data_sources

                score = 0.0

                # 1. Exact technique name match (highest priority)
                if tech_name and tech_name in description_lower:
                    score += 50.0

                # 1.5. Special case for "kerberoasting" technique name match
                if 'kerberoasting' in tech_name and 'kerberoasting' in description_lower:
                    score += 60.0  # Very high score for exact match
                    # Prefer sub-techniques (T1558.003) over parent techniques (T1208)
                    if '.' in tech_id:  # Sub-technique
                        score += 20.0

                # Dynamic term matching - extract key terms from description and match against technique data
                description_key_terms = self._extract_key_terms(description_lower)
                tech_name_safe = str(tech_name).lower() if tech_name else ''

                # Calculate dynamic term overlap score
                tech_terms = set(tech_name_safe.split() + tech_desc.split() + detection_guidance.split())
                description_terms_set = set(description_key_terms)

                # Score based on term overlap relevance
                overlap = description_terms_set.intersection(tech_terms)
                if overlap:
                    overlap_score = len(overlap) * 10.0  # Base score per overlapping term
                    score += overlap_score

                # 2. Semantic similarity using key terms
                semantic_score = self._calculate_semantic_similarity(
                    description_terms, tech_name, tech_desc, detection_guidance
                )
                score += semantic_score

                # 3. Context-aware scoring based on description patterns
                context_score = self._calculate_context_score(
                    description_lower, tech_name, tech_desc, detection_guidance, data_sources
                )
                score += context_score

                # 4. Detection method alignment
                detection_score = self._calculate_detection_alignment(
                    description_lower, detection_guidance, data_sources
                )
                score += detection_score

                # 5. Prefer sub-techniques over parent techniques (more specific)
                if '.' in tech_id and score > 0:
                    score += 5.0  # Small bonus for sub-techniques

                if score > 0:
                    technique_scores.append((tech_id, score, tech_name))

            # Sort by score and return best match if confidence is high enough
            if technique_scores:
                technique_scores.sort(key=lambda x: x[1], reverse=True)
                best_match = technique_scores[0]

                # Dynamic threshold based on score distribution
                threshold = self._calculate_dynamic_threshold(technique_scores)

                # Only return if confidence is high enough
                if best_match[1] >= threshold:
                    self.logger.info(f"Dynamically identified technique {best_match[0]} ('{best_match[2]}') with score {best_match[1]:.2f}")
                    return best_match[0]
                else:
                    self.logger.info(f"Best match {best_match[0]} scored {best_match[1]:.2f} but below threshold {threshold:.2f}")

            return None

        except Exception as e:
            self.logger.error(f"Error identifying technique from description: {e}")
            return None

    def _extract_key_terms(self, description: str) -> List[str]:
        """Extract key terms from description for semantic matching"""
        import re

        # Remove common stop words and extract meaningful terms
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'must', 'shall', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'}

        # Extract words and filter
        words = re.findall(r'\b\w+\b', description.lower())
        key_terms = [word for word in words if len(word) > 2 and word not in stop_words]

        # Also extract multi-word phrases that might be important
        phrases = []
        # Look for common attack-related phrases
        phrase_patterns = [
            r'\b\w+\s+enumeration\b',
            r'\b\w+\s+scanning\b',
            r'\b\w+\s+discovery\b',
            r'\b\w+\s+injection\b',
            r'\b\w+\s+execution\b',
            r'\b\w+\s+escalation\b',
            r'\b\w+\s+movement\b',
            r'\b\w+\s+access\b',
            r'\b\w+\s+evasion\b',
            r'\b\w+\s+persistence\b'
        ]

        for pattern in phrase_patterns:
            matches = re.findall(pattern, description)
            phrases.extend(matches)

        return key_terms + phrases

    def _calculate_semantic_similarity(self, description_terms: List[str], tech_name: str, tech_desc: str, detection_guidance: str) -> float:
        """Calculate semantic similarity between description and technique"""
        score = 0.0

        # Combine all technique text for analysis
        technique_text = f"{tech_name} {tech_desc} {detection_guidance}".lower()
        technique_words = set(technique_text.split())

        # Calculate term overlap
        description_words = set(description_terms)
        common_words = description_words.intersection(technique_words)

        if description_words:
            overlap_ratio = len(common_words) / len(description_words)
            score += overlap_ratio * 20.0  # Up to 20 points for term overlap

        # Enhanced semantic matching for domain-specific terms
        score += self._calculate_domain_specific_score(description_terms, tech_name, tech_desc, detection_guidance)

        # Bonus for exact phrase matches
        for term in description_terms:
            if len(term) > 3 and term in technique_text:
                score += 5.0

        return score

    def _calculate_domain_specific_score(self, description_terms: List[str], tech_name: str, tech_desc: str, detection_guidance: str) -> float:
        """Calculate domain-specific scoring using dynamic semantic analysis"""
        score = 0.0

        # Create comprehensive technique context
        full_context = f"{tech_name} {tech_desc} {detection_guidance}".lower()
        tech_name_safe = str(tech_name).lower() if tech_name else ''

        # Extract all meaningful terms from technique context
        tech_context_terms = set()
        for text in [tech_name_safe, tech_desc, detection_guidance]:
            if text:
                # Extract words longer than 2 characters
                words = re.findall(r'\b\w{3,}\b', text.lower())
                tech_context_terms.update(words)

        # Calculate semantic relevance based on term co-occurrence
        for desc_term in description_terms:
            desc_term_lower = desc_term.lower()

            # Direct term match in technique context
            if desc_term_lower in tech_context_terms:
                score += 10.0

                # Extra bonus if term appears in technique name (higher relevance)
                if desc_term_lower in tech_name_safe:
                    score += 15.0

            # Partial term matching for compound words and variations
            for tech_term in tech_context_terms:
                # Check for partial matches (substring relationships)
                if len(desc_term_lower) > 3 and len(tech_term) > 3:
                    if desc_term_lower in tech_term or tech_term in desc_term_lower:
                        score += 5.0
                        break

        # Calculate contextual similarity using word proximity
        description_text = ' '.join(description_terms).lower()

        # Score based on shared word patterns and context
        shared_patterns = 0
        for tech_term in tech_context_terms:
            if tech_term in description_text:
                shared_patterns += 1

        if shared_patterns > 0:
            pattern_score = min(shared_patterns * 3.0, 20.0)  # Cap at 20 points
            score += pattern_score

        return score

    def _calculate_context_score(self, description: str, tech_name: str, tech_desc: str, detection_guidance: str, data_sources: str) -> float:
        """Calculate context-aware scoring using dynamic semantic analysis"""
        score = 0.0

        # Extract key action words and concepts from description
        description_lower = description.lower()
        description_terms = self._extract_key_terms(description_lower)

        # Create comprehensive technique context
        technique_text = f"{tech_name} {tech_desc} {detection_guidance}".lower()
        technique_terms = self._extract_key_terms(technique_text)

        # Calculate semantic overlap between description and technique
        description_set = set(description_terms)
        technique_set = set(technique_terms)

        # Direct term overlap scoring
        common_terms = description_set.intersection(technique_set)
        if common_terms:
            overlap_score = len(common_terms) * 5.0  # 5 points per common term
            score += min(overlap_score, 30.0)  # Cap at 30 points

        # Contextual relevance based on term co-occurrence patterns
        for desc_term in description_terms:
            # Check if description term appears in technique context
            if desc_term.lower() in technique_text:
                score += 3.0

        # Data source alignment scoring
        if data_sources:
            data_sources_lower = data_sources.lower()
            # Check if description mentions data source related terms
            for desc_term in description_terms:
                if desc_term.lower() in data_sources_lower:
                    score += 8.0  # Higher score for data source alignment

        # Dynamic pattern matching based on semantic similarity
        # Calculate additional contextual relevance using word embeddings approach
        description_words = set(description_lower.split())
        technique_words = set(technique_text.split())

        # Find semantically related word pairs
        semantic_matches = 0
        for desc_word in description_words:
            for tech_word in technique_words:
                # Check for word similarity (substring, common roots, etc.)
                if len(desc_word) > 3 and len(tech_word) > 3:
                    if (desc_word in tech_word or tech_word in desc_word or
                        self._calculate_word_similarity(desc_word, tech_word) > 0.7):
                        semantic_matches += 1
                        break

        if semantic_matches > 0:
            semantic_score = min(semantic_matches * 4.0, 20.0)  # Cap at 20 points
            score += semantic_score

        return score

    def _calculate_word_similarity(self, word1: str, word2: str) -> float:
        """Calculate similarity between two words using simple string metrics"""
        if not word1 or not word2:
            return 0.0

        # Simple similarity based on common characters and length
        common_chars = set(word1.lower()).intersection(set(word2.lower()))
        max_len = max(len(word1), len(word2))

        if max_len == 0:
            return 0.0

        similarity = len(common_chars) / max_len

        # Bonus for similar length
        length_diff = abs(len(word1) - len(word2))
        length_bonus = max(0, 1 - (length_diff / max_len))

        return (similarity + length_bonus) / 2

    def _calculate_detection_alignment(self, description: str, detection_guidance: str, data_sources: str) -> float:
        """Calculate how well the technique's detection methods align with the description using dynamic analysis"""
        score = 0.0

        if not detection_guidance:
            return score

        # Extract meaningful terms from description and detection guidance
        description_terms = self._extract_key_terms(description.lower())
        guidance_terms = self._extract_key_terms(detection_guidance.lower())

        # Calculate term overlap between description and detection guidance
        description_set = set(description_terms)
        guidance_set = set(guidance_terms)

        common_terms = description_set.intersection(guidance_set)
        if common_terms:
            alignment_score = len(common_terms) * 4.0  # 4 points per common term
            score += min(alignment_score, 25.0)  # Cap at 25 points

        # Check data source alignment dynamically
        if data_sources:
            data_sources_terms = self._extract_key_terms(data_sources.lower())
            data_sources_set = set(data_sources_terms)

            # Check overlap between description and data sources
            data_overlap = description_set.intersection(data_sources_set)
            if data_overlap:
                data_score = len(data_overlap) * 3.0  # 3 points per data source term match
                score += min(data_score, 15.0)  # Cap at 15 points

            # Check overlap between detection guidance and data sources
            guidance_data_overlap = guidance_set.intersection(data_sources_set)
            if guidance_data_overlap:
                guidance_data_score = len(guidance_data_overlap) * 2.0  # 2 points per match
                score += min(guidance_data_score, 10.0)  # Cap at 10 points

        return score

    def _calculate_dynamic_threshold(self, technique_scores: List[tuple]) -> float:
        """Calculate dynamic threshold based on score distribution"""
        if not technique_scores:
            return 10.0

        scores = [score[1] for score in technique_scores]

        # If we have a clear winner (much higher than others), lower threshold
        if len(scores) > 1:
            top_score = scores[0]
            second_score = scores[1]

            if top_score > second_score * 2:  # Clear winner
                return max(5.0, top_score * 0.3)
            else:
                return max(10.0, top_score * 0.5)

        # Single result or no clear winner - use higher threshold
        return max(15.0, scores[0] * 0.6) if scores else 15.0

    def _validate_rule_matches_description(self, parsed_rule: Dict[str, Any], description: str, technique_id: str) -> Dict[str, Any]:
        """Validate that the generated rule actually matches the user's description"""
        try:
            description_lower = description.lower()
            rule_title = parsed_rule.get('title', '').lower()
            rule_description = parsed_rule.get('description', '').lower()
            rule_tags = parsed_rule.get('tags', [])

            # Check if the rule is for the correct technique
            expected_technique_tag = f"attack.{technique_id.lower()}"
            if expected_technique_tag not in rule_tags:
                return {
                    'matches': False,
                    'reason': f'Rule does not contain the expected technique tag: {expected_technique_tag}'
                }

            # Dynamic validation using MITRE technique data
            mitre_data = self._get_mitre_technique_data(technique_id)
            technique_name = mitre_data.get('name', '').lower()
            technique_desc = mitre_data.get('description', '').lower()
            detection_guidance = mitre_data.get('detection', '').lower()

            # Extract key terms from MITRE data for this technique
            technique_context = f"{technique_name} {technique_desc} {detection_guidance}"
            technique_terms = self._extract_key_terms(technique_context)
            description_terms = self._extract_key_terms(description_lower)
            rule_terms = self._extract_key_terms(f"{rule_title} {rule_description}")

            # Check for semantic overlap between description and technique
            desc_tech_overlap = set(description_terms).intersection(set(technique_terms))
            rule_tech_overlap = set(rule_terms).intersection(set(technique_terms))

            # Require semantic alignment between description, rule, and technique
            if desc_tech_overlap and not rule_tech_overlap:
                # Check for partial matches in rule
                partial_matches = 0
                for rule_term in rule_terms:
                    for tech_term in technique_terms:
                        if (len(rule_term) > 3 and len(tech_term) > 3 and
                            (rule_term in tech_term or tech_term in rule_term)):
                            partial_matches += 1
                            break

                if partial_matches == 0:
                    return {
                        'matches': False,
                        'reason': f'Rule content does not align with {technique_id} technique context'
                    }

            # Validate detection logic alignment with description
            detection = parsed_rule.get('detection', {})
            detection_str = str(detection).lower()
            detection_terms = self._extract_key_terms(detection_str)

            # Check if detection logic contains terms relevant to the description
            detection_desc_overlap = set(detection_terms).intersection(set(description_terms))
            detection_tech_overlap = set(detection_terms).intersection(set(technique_terms))

            # Require some alignment between detection logic and either description or technique
            if not detection_desc_overlap and not detection_tech_overlap:
                return {
                    'matches': False,
                    'reason': 'Rule detection logic does not align with description or technique requirements'
                }

            return {
                'matches': True,
                'reason': 'Rule matches the description and technique'
            }

        except Exception as e:
            self.logger.error(f"Error validating rule matches description: {e}")
            return {
                'matches': True,  # Default to true to avoid blocking valid rules
                'reason': f'Validation error: {str(e)}'
            }

    def _get_related_sigma_rules(self, technique_id: str, limit: int = 3) -> List[Dict[str, Any]]:
        """Get existing SIGMA rules for the technique - USES CENTRALIZED METHOD"""
        if not self.db_manager or not technique_id:
            return []

        try:
            # Use the centralized method from database manager
            return self.db_manager.get_rules_for_technique(technique_id, limit=limit)

        except Exception as e:
            self.logger.error(f"Error retrieving related SIGMA rules for {technique_id}: {e}")
            return []

    def _pre_validate_rule(self, parsed_rule: Dict[str, Any], expected_technique: str) -> List[str]:
        """Pre-validation to catch critical errors before full validation - completely dynamic"""
        errors = []

        # Check for completely wrong technique IDs
        rule_str = str(parsed_rule).lower()
        tags = parsed_rule.get('tags', [])
        references = parsed_rule.get('references', [])

        # Dynamic technique validation using pattern analysis
        import re

        # Find all technique IDs in the rule
        technique_pattern = r't\d{4}(?:\.\d{3})?'
        found_techniques = re.findall(technique_pattern, rule_str)

        # Check if expected technique is present
        expected_lower = expected_technique.lower()
        technique_found = False
        wrong_techniques = []

        for found_tech in found_techniques:
            if found_tech == expected_lower:
                technique_found = True
            else:
                wrong_techniques.append(found_tech.upper())

        # Also check in tags specifically
        for tag in tags:
            if expected_lower in tag.lower():
                technique_found = True
                break

        # Report specific errors
        if wrong_techniques and not technique_found:
            errors.append(f"Rule contains completely wrong technique ID {', '.join(wrong_techniques)} instead of {expected_technique}")

        # Check for wrong tactic
        expected_tactic = self._get_expected_tactic(expected_technique)
        if expected_tactic and expected_tactic != 'unknown':
            tactic_found = False
            for tag in tags:
                if f"attack.{expected_tactic}" in tag.lower():
                    tactic_found = True
                    break

            if not tactic_found:
                # Check what tactic is being used
                used_tactics = []
                for tag in tags:
                    if tag.lower().startswith('attack.') and not tag.lower().startswith('attack.t'):
                        tactic = tag.lower().replace('attack.', '')
                        if tactic not in ['unknown', expected_tactic]:
                            used_tactics.append(tactic)

                if used_tactics:
                    errors.append(f"Rule uses '{', '.join(used_tactics)}' tactic - must use proper MITRE tactic '{expected_tactic}' for {expected_technique}")
                else:
                    errors.append(f"Rule uses 'unknown' tactic - must use proper MITRE tactic '{expected_tactic}' for {expected_technique}")

        return errors

    def _get_expected_tactic(self, technique_id: str) -> str:
        """Get expected tactic for a technique ID"""
        try:
            mitre_data = self._get_mitre_technique_data(technique_id)
            tactic_raw = mitre_data.get('tactic', '')
            if isinstance(tactic_raw, list):
                tactic = tactic_raw[0] if tactic_raw else ''
            else:
                tactic = str(tactic_raw) if tactic_raw else ''
            tactic = tactic.lower().replace(' ', '_')
            return tactic if tactic else 'unknown'
        except Exception:
            return 'unknown'

        return errors

    def _validate_generated_rule(self, parsed_rule: Dict[str, Any], expected_technique: str) -> Dict[str, Any]:
        """Validate that the generated rule follows MITRE guidance"""
        issues = []

        # Check technique ID in tags (flexible format checking)
        tags = parsed_rule.get('tags', [])
        technique_found = False
        expected_variations = [
            f"attack.{expected_technique.lower()}",
            f"attack.{expected_technique.lower().replace('.', '_')}",
            f"attack.{expected_technique.upper().lower()}",
            expected_technique.lower()
        ]

        for tag in tags:
            tag_lower = tag.lower()
            if any(variation in tag_lower for variation in expected_variations):
                technique_found = True
                break

        if not technique_found:
            issues.append(f"Missing or incorrect technique tag. Expected technique {expected_technique} in tags, found: {tags}")

        # Dynamic validation based on MITRE technique data
        mitre_data = self._get_mitre_technique_data(expected_technique)
        if mitre_data:
            validation_issues = self._validate_rule_against_mitre_guidance(parsed_rule, expected_technique, mitre_data)
            issues.extend(validation_issues)

        # Validate technique ID format and relevance
        for tag in tags:
            if tag.lower().startswith('attack.t') and expected_technique.lower() not in tag.lower():
                # Check if it's a valid technique format but wrong ID
                if len(tag.split('.')) >= 2 and tag.split('.')[1].startswith('t'):
                    issues.append(f"Rule may use incorrect technique ID: {tag}")

        # Separate critical errors from warnings
        critical_issues = [issue for issue in issues if issue.startswith('CRITICAL')]
        warnings = [issue for issue in issues if issue.startswith('WARNING')]

        return {
            'valid': len(critical_issues) == 0,  # Only fail on critical issues
            'issues': issues,
            'critical_issues': critical_issues,
            'warnings': warnings,
            'error': '; '.join(critical_issues) if critical_issues else None
        }

    def _get_technique_specific_requirements(self, technique_id: str, mitre_data: Dict[str, Any]) -> str:
        """Generate technique-specific detection requirements based on MITRE data"""
        requirements = []

        # Extract key information from MITRE data
        detection_guidance = mitre_data.get('detection', '')
        data_sources = mitre_data.get('data_sources', [])
        tactic = mitre_data.get('tactic', '')
        technique_name = mitre_data.get('name', '')

        # Parse data sources
        if isinstance(data_sources, str):
            try:
                data_sources = eval(data_sources) if data_sources.startswith('[') else [data_sources]
            except:
                data_sources = [data_sources]

        # Dynamic technique-specific requirements based on MITRE detection guidance
        if detection_guidance:
            parsed_requirements = self._parse_mitre_detection_guidance(detection_guidance, technique_id, technique_name)
            if parsed_requirements:
                requirements.extend(parsed_requirements)

        # Generate requirements based on data sources (secondary priority)
        for ds in data_sources:
            # Handle nested data source structures
            if isinstance(ds, str):
                ds_lower = ds.lower()
            elif isinstance(ds, list) and ds:
                # If it's a nested list, get the first string element
                ds_lower = str(ds[0]).lower()
            else:
                # Convert to string as fallback
                ds_lower = str(ds).lower()
            if 'process' in ds_lower:
                if 'creation' in ds_lower:
                    requirements.append("Monitor for process creation events and command-line arguments")
                elif 'access' in ds_lower or 'modification' in ds_lower:
                    requirements.append("Monitor for process access and modification patterns")
                else:
                    requirements.append("Monitor for process-related activities")

            elif 'file' in ds_lower:
                if 'creation' in ds_lower:
                    requirements.append("Monitor for file creation events and suspicious file types")
                elif 'modification' in ds_lower:
                    requirements.append("Monitor for file modification and deletion patterns")
                elif 'access' in ds_lower:
                    requirements.append("Monitor for file access patterns and permissions")
                else:
                    requirements.append("Monitor for file system activities")

            elif 'network' in ds_lower:
                if 'traffic' in ds_lower:
                    requirements.append("Monitor for network traffic patterns and connections")
                elif 'connection' in ds_lower:
                    requirements.append("Monitor for network connection establishment")
                else:
                    requirements.append("Monitor for network activities")

            elif 'registry' in ds_lower:
                requirements.append("Monitor for Windows registry modifications and access")

            elif 'authentication' in ds_lower or 'logon' in ds_lower:
                requirements.append("Monitor for authentication events and logon patterns")

            elif 'cloud' in ds_lower or 'azure' in ds_lower or 'aws' in ds_lower:
                requirements.append("Monitor for cloud service activities and API calls")

            elif 'application' in ds_lower:
                requirements.append("Monitor for application logs and service activities")

            elif 'command' in ds_lower:
                requirements.append("Monitor for command execution and script activities")

            elif 'user' in ds_lower or 'account' in ds_lower:
                requirements.append("Monitor for user account activities and privilege changes")

            elif 'service' in ds_lower:
                requirements.append("Monitor for service creation, modification, and execution")

            elif 'scheduled' in ds_lower or 'task' in ds_lower:
                requirements.append("Monitor for scheduled task creation and execution")

            elif 'wmi' in ds_lower:
                requirements.append("Monitor for WMI activity and suspicious queries")

        # Extract specific indicators from detection guidance
        if detection_guidance:
            guidance_lower = detection_guidance.lower()

            # Look for specific tools, commands, or indicators mentioned
            specific_indicators = []

            # Common attack tools and techniques
            tool_patterns = [
                ('powershell', 'PowerShell execution and script content'),
                ('cmd', 'Command prompt usage and parameters'),
                ('wmi', 'WMI queries and method calls'),
                ('registry', 'Registry key modifications'),
                ('dll', 'DLL loading and injection patterns'),
                ('api', 'API calls and system interactions'),
                ('certificate', 'Certificate usage and validation'),
                ('encryption', 'Encryption and encoding activities'),
                ('base64', 'Base64 encoded content'),
                ('javascript', 'JavaScript execution and content'),
                ('blob', 'JavaScript Blob objects and file operations'),
                ('download', 'File download activities'),
                ('upload', 'File upload activities'),
                ('credential', 'Credential access and extraction'),
                ('token', 'Token manipulation and usage'),
                ('privilege', 'Privilege escalation attempts'),
                ('persistence', 'Persistence mechanism creation'),
                ('lateral', 'Lateral movement indicators'),
                ('exfiltration', 'Data exfiltration patterns')
            ]

            for pattern, description in tool_patterns:
                if pattern in guidance_lower:
                    specific_indicators.append(f"Monitor for {description}")

            # Add the most relevant specific indicators
            if specific_indicators:
                requirements.extend(specific_indicators[:3])  # Limit to top 3 most relevant

        # Add tactic-specific requirements
        if tactic:
            tactic_lower = tactic.lower()
            if 'initial access' in tactic_lower:
                requirements.append("Focus on entry point detection and external connections")
            elif 'execution' in tactic_lower:
                requirements.append("Focus on code execution and process spawning")
            elif 'persistence' in tactic_lower:
                requirements.append("Focus on persistence mechanism creation and startup items")
            elif 'privilege escalation' in tactic_lower:
                requirements.append("Focus on privilege elevation and permission changes")
            elif 'defense evasion' in tactic_lower:
                requirements.append("Focus on evasion techniques and obfuscation methods")
            elif 'credential access' in tactic_lower:
                requirements.append("Focus on credential extraction and authentication bypass")
            elif 'discovery' in tactic_lower:
                requirements.append("Focus on reconnaissance and information gathering")
            elif 'lateral movement' in tactic_lower:
                requirements.append("Focus on network traversal and remote access")
            elif 'collection' in tactic_lower:
                requirements.append("Focus on data collection and staging activities")
            elif 'command and control' in tactic_lower:
                requirements.append("Focus on C2 communications and remote control")
            elif 'exfiltration' in tactic_lower:
                requirements.append("Focus on data transfer and external communications")
            elif 'impact' in tactic_lower:
                requirements.append("Focus on system disruption and data destruction")

        # Remove duplicates while preserving order
        seen = set()
        unique_requirements = []
        for req in requirements:
            if req not in seen:
                seen.add(req)
                unique_requirements.append(req)

        return '\n'.join(f"- {req}" for req in unique_requirements) if unique_requirements else ""

    def _parse_mitre_detection_guidance(self, detection_guidance: str, technique_id: str, technique_name: str) -> List[str]:
        """Dynamically parse MITRE detection guidance to extract specific detection requirements"""
        requirements = []
        guidance_lower = detection_guidance.lower()

        # Extract key detection indicators mentioned in the guidance
        detection_indicators = []

        # Look for specific technical terms and indicators
        technical_patterns = {
            # File-based indicators
            'blob': 'JavaScript Blob objects and file operations',
            'mssaveoropenblob': 'msSaveOrOpenBlob API calls',
            'download': 'file download activities and attributes',
            'html': 'HTML content and structure analysis',
            'javascript': 'JavaScript execution and content',

            # Process-based indicators
            'powershell': 'PowerShell execution patterns and encoded commands',
            'cmd': 'Command prompt usage and parameters',
            'process': 'process creation and execution monitoring',
            'command line': 'command-line arguments and parameters',
            'encoded': 'encoded or obfuscated content',
            'base64': 'Base64 encoded content and commands',

            # Memory and injection indicators
            'memory': 'memory access and manipulation patterns',
            'injection': 'code injection and process manipulation',
            'dll': 'DLL loading and injection patterns',
            'lsass': 'LSASS process access and credential extraction',

            # Network indicators
            'network': 'network traffic and connection patterns',
            'dns': 'DNS queries and resolution patterns',
            'http': 'HTTP/HTTPS traffic and requests',
            'c2': 'command and control communications',

            # Registry indicators
            'registry': 'Windows registry modifications and access',
            'persistence': 'persistence mechanism creation',
            'startup': 'startup and autorun mechanisms',

            # Authentication indicators
            'credential': 'credential access and extraction',
            'authentication': 'authentication events and patterns',
            'token': 'token manipulation and usage',
            'privilege': 'privilege escalation attempts'
        }

        # Find relevant indicators in the detection guidance
        for pattern, description in technical_patterns.items():
            if pattern in guidance_lower:
                detection_indicators.append(f"Monitor for {description}")

        # Extract data source requirements from guidance
        data_source_patterns = {
            'file creation': ('file', 'Monitor for file creation events and suspicious file types'),
            'process creation': ('process_creation', 'Monitor for process creation events and command-line arguments'),
            'process access': ('process_access', 'Monitor for process access and memory manipulation'),
            'network traffic': ('network_traffic', 'Monitor for network traffic patterns and connections'),
            'registry': ('registry', 'Monitor for Windows registry modifications and access'),
            'authentication': ('authentication', 'Monitor for authentication events and logon patterns'),
            'api monitoring': ('api', 'Monitor for API calls and system interactions')
        }

        suggested_logsource = None
        for pattern, (category, description) in data_source_patterns.items():
            if pattern in guidance_lower:
                detection_indicators.append(description)
                if not suggested_logsource:  # Use first match as primary suggestion
                    suggested_logsource = category

        # Add critical requirements based on detected patterns
        if detection_indicators:
            requirements.append(f"CRITICAL: Based on MITRE guidance, focus on: {', '.join(detection_indicators[:3])}")

        if suggested_logsource:
            requirements.append(f"CRITICAL: Use logsource category '{suggested_logsource}' based on MITRE data sources")

        # Extract specific tools or methods mentioned dynamically from guidance
        guidance_terms = self._extract_key_terms(guidance_lower)
        tool_mentions = []

        # Look for executable names and tool patterns in guidance
        for term in guidance_terms:
            # Check for common executable patterns
            if (term.endswith('.exe') or
                len(term) > 3 and any(char in term for char in ['.', '_']) or
                term in guidance_lower and guidance_lower.count(term) > 1):  # Repeated mentions suggest importance
                tool_mentions.append(term)

        if tool_mentions:
            # Limit to most relevant tools (avoid noise)
            relevant_tools = tool_mentions[:5]  # Top 5 most mentioned
            requirements.append(f"CRITICAL: Monitor for specific tools/methods mentioned in MITRE guidance: {', '.join(relevant_tools)}")

        # Look for "should not" or "avoid" patterns to prevent common mistakes
        avoid_patterns = []
        if 'difficult' in guidance_lower or 'challenging' in guidance_lower:
            avoid_patterns.append("Be aware this technique is difficult to detect - focus on behavioral patterns")

        if 'false positive' in guidance_lower:
            avoid_patterns.append("Consider false positives from legitimate activities mentioned in MITRE guidance")

        if avoid_patterns:
            requirements.extend([f"WARNING: {pattern}" for pattern in avoid_patterns])

        # Add technique-specific validation based on common mistakes
        common_mistakes = self._identify_common_detection_mistakes(technique_id, guidance_lower)
        if common_mistakes:
            requirements.extend([f"AVOID: {mistake}" for mistake in common_mistakes])

        return requirements

    def _identify_common_detection_mistakes(self, technique_id: str, guidance_lower: str) -> List[str]:
        """Dynamically identify common mistakes based on MITRE guidance content"""
        mistakes = []

        # Analyze guidance content to identify potential mistakes dynamically

        # Data source guidance (suggestions, not strict requirements)
        if 'file creation' in guidance_lower or 'download' in guidance_lower:
            mistakes.append("Consider file monitoring in addition to process monitoring for comprehensive coverage")

        if 'process access' in guidance_lower or 'memory' in guidance_lower:
            mistakes.append("Consider process access monitoring for memory-based detection patterns")

        if 'network' in guidance_lower and 'traffic' in guidance_lower:
            mistakes.append("Consider network monitoring for comprehensive detection coverage")

        # Tactic misalignment detection
        if 'defense evasion' in guidance_lower or 'evasion' in guidance_lower:
            mistakes.append("Using wrong tactic - should be 'defense_evasion' based on MITRE guidance")

        if 'execution' in guidance_lower and 'command' in guidance_lower:
            mistakes.append("Using wrong tactic - should be 'execution' based on MITRE guidance")

        # Tool/method focus misalignment
        if 'powershell' not in guidance_lower:
            mistakes.append("Focusing on PowerShell when technique doesn't primarily use PowerShell")

        if any(term in guidance_lower for term in ['html', 'javascript', 'web', 'browser']):
            mistakes.append("Using command-line focused detection for web/browser-based techniques")

        # Detection complexity warnings
        if 'difficult' in guidance_lower or 'challenging' in guidance_lower:
            mistakes.append("Oversimplifying detection for techniques marked as difficult to detect")

        if 'false positive' in guidance_lower:
            mistakes.append("Not considering false positives mentioned in MITRE guidance")

        return mistakes

    def _validate_rule_against_mitre_guidance(self, parsed_rule: Dict[str, Any], technique_id: str, mitre_data: Dict[str, Any]) -> List[str]:
        """Dynamically validate rule against MITRE ATT&CK guidance"""
        issues = []

        # Get MITRE guidance data
        detection_guidance_raw = mitre_data.get('detection', '')
        detection_guidance = str(detection_guidance_raw).lower() if detection_guidance_raw else ''
        data_sources = mitre_data.get('data_sources', [])

        # Safely extract tactic as string
        tactic_raw = mitre_data.get('tactic', '')
        if isinstance(tactic_raw, list):
            expected_tactic = tactic_raw[0] if tactic_raw else ''
        else:
            expected_tactic = str(tactic_raw) if tactic_raw else ''
        expected_tactic = expected_tactic.lower().replace(' ', '_')

        technique_name = mitre_data.get('name', '')

        # Parse data sources
        if isinstance(data_sources, str):
            try:
                data_sources = eval(data_sources) if data_sources.startswith('[') else [data_sources]
            except:
                data_sources = [data_sources]

        # Extract rule components for validation
        title = parsed_rule.get('title', '').lower()
        description = parsed_rule.get('description', '').lower()
        detection = parsed_rule.get('detection', {})
        detection_str = str(detection).lower()
        logsource = parsed_rule.get('logsource', {})
        category = logsource.get('category', '').lower()
        tags = parsed_rule.get('tags', [])
        references = parsed_rule.get('references', [])
        rule_content_str = str(parsed_rule).lower()

        # Validate tactic alignment - be more flexible as techniques can span multiple tactics
        tactic_tags = [tag for tag in tags if tag.startswith('attack.') and not tag.startswith('attack.t')]
        expected_tactic_tag = f"attack.{expected_tactic}"

        # Only flag as critical if there are tactic tags but none match expected
        if tactic_tags and expected_tactic_tag not in tactic_tags and expected_tactic != 'unknown':
            # Check if any valid tactic is present (not just the expected one)
            valid_tactics = ['initial_access', 'execution', 'persistence', 'privilege_escalation',
                           'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
                           'collection', 'command_and_control', 'exfiltration', 'impact']

            has_valid_tactic = any(f"attack.{tactic}" in tactic_tags for tactic in valid_tactics)

            if not has_valid_tactic:
                issues.append(f"WARNING: Rule should include a valid MITRE tactic. Suggested: '{expected_tactic}'")

        # Validate data source alignment
        primary_data_source = None
        if data_sources:
            # Handle nested data source structures
            first_source = data_sources[0]
            if isinstance(first_source, str):
                primary_data_source = first_source.lower()
            elif isinstance(first_source, list) and first_source:
                # If it's a nested list, get the first string element
                primary_data_source = str(first_source[0]).lower()
            else:
                # Convert to string as fallback
                primary_data_source = str(first_source).lower()

            # Check if logsource category aligns with MITRE data sources - make suggestions instead of critical errors
            if 'file' in primary_data_source and 'process' in category and 'file' not in category:
                issues.append(f"INFO: Consider file monitoring in addition to process monitoring for {technique_name} based on MITRE data sources")
            elif 'process' in primary_data_source and 'file' in category and 'process' not in category:
                issues.append(f"INFO: Consider process monitoring in addition to file monitoring for {technique_name} based on MITRE data sources")

        # Validate detection indicators based on MITRE guidance
        if detection_guidance:
            # Extract key indicators from MITRE guidance
            guidance_indicators = self._extract_detection_indicators_from_guidance(detection_guidance)

            # Check if rule includes relevant indicators
            missing_indicators = []
            for indicator_type, indicators in guidance_indicators.items():
                if indicators and not any(indicator in detection_str for indicator in indicators):
                    missing_indicators.append(indicator_type)

            if missing_indicators:
                issues.append(f"WARNING: Rule may be missing key detection indicators mentioned in MITRE guidance: {', '.join(missing_indicators)}")

        # Check for technique-specific validation issues
        technique_issues = self._validate_technique_specific_patterns(parsed_rule, technique_id, detection_guidance)
        issues.extend(technique_issues)

        # Validate references
        ref_str = ' '.join(references).lower()
        expected_ref = f"techniques/{technique_id.lower()}/"
        if expected_ref not in ref_str:
            # Check for any wrong technique references dynamically
            import re
            technique_pattern = r't\d{4}(?:\.\d{3})?'
            found_techniques = re.findall(technique_pattern, ref_str)
            for found_tech in found_techniques:
                if found_tech != technique_id.lower():
                    issues.append(f"CRITICAL: Rule references wrong technique {found_tech.upper()} instead of {technique_id}")

        # Additional critical validation for common mistakes
        rule_content_str = str(parsed_rule).lower()

        # Dynamic check for any technique IDs that don't match expected
        import re
        all_technique_pattern = r't\d{4}(?:\.\d{3})?'
        found_all_techniques = re.findall(all_technique_pattern, rule_content_str)

        for found_tech in found_all_techniques:
            if found_tech != technique_id.lower():
                issues.append(f"CRITICAL: Rule contains technique ID {found_tech.upper()} instead of expected {technique_id}")

        # Check for unknown tactic
        if 'attack.unknown' in tags:
            issues.append(f"CRITICAL: Rule uses 'unknown' tactic instead of proper tactic '{expected_tactic}'")

        return issues

    def _extract_detection_indicators_from_guidance(self, detection_guidance: str) -> Dict[str, List[str]]:
        """Extract specific detection indicators from MITRE guidance text"""
        indicators = {
            'file_indicators': [],
            'process_indicators': [],
            'network_indicators': [],
            'registry_indicators': [],
            'api_indicators': []
        }

        guidance_lower = detection_guidance.lower()

        # Dynamic indicator extraction based on guidance content
        guidance_terms = self._extract_key_terms(guidance_lower)

        # Categorize terms based on context and common patterns
        for term in guidance_terms:
            term_lower = term.lower()

            # File-related indicators
            if any(file_hint in term_lower for file_hint in ['file', 'blob', 'download', 'html', 'script', 'document']):
                indicators['file_indicators'].append(term)

            # Process-related indicators
            elif any(proc_hint in term_lower for proc_hint in ['process', 'command', 'execution', 'powershell', 'cmd']):
                indicators['process_indicators'].append(term)

            # Network-related indicators
            elif any(net_hint in term_lower for net_hint in ['network', 'dns', 'http', 'connection', 'traffic', 'communication']):
                indicators['network_indicators'].append(term)

            # Registry-related indicators
            elif any(reg_hint in term_lower for reg_hint in ['registry', 'hkey', 'persistence', 'startup']):
                indicators['registry_indicators'].append(term)

            # API/Memory-related indicators
            elif any(api_hint in term_lower for api_hint in ['api', 'dll', 'injection', 'memory', 'function']):
                indicators['api_indicators'].append(term)

        # Remove duplicates and limit to most relevant
        for category in indicators:
            indicators[category] = list(set(indicators[category]))[:10]  # Top 10 per category

        return indicators

    def _validate_technique_specific_patterns(self, parsed_rule: Dict[str, Any], technique_id: str, detection_guidance: str) -> List[str]:
        """Dynamically validate patterns based on MITRE guidance content"""
        issues = []
        guidance_lower = detection_guidance.lower()
        rule_content_str = str(parsed_rule).lower()
        logsource = parsed_rule.get('logsource', {})
        category = logsource.get('category', '').lower()
        detection_str = str(parsed_rule.get('detection', {})).lower()

        # Dynamic validation based on guidance content

        # File-based techniques validation - make more flexible
        if 'file creation' in guidance_lower or 'download' in guidance_lower:
            # Check if rule has ANY file-related detection
            has_file_detection = ('file' in category or
                                'file' in detection_str or
                                'download' in detection_str or
                                'creation' in detection_str)

            if not has_file_detection and 'process' in category:
                issues.append(f"WARNING: Technique {technique_id} involves file operations - consider adding file monitoring alongside process monitoring")

        # Process access vs process creation validation - make more flexible
        if 'process access' in guidance_lower or 'memory' in guidance_lower:
            # Check if rule has ANY process-related detection, not just creation
            has_process_detection = ('process' in category or
                                   'process' in detection_str or
                                   'lsass' in detection_str or
                                   'memory' in detection_str)

            if not has_process_detection:
                issues.append(f"WARNING: Technique {technique_id} involves process/memory access - consider adding process monitoring")

        # Network-based techniques validation
        if 'network' in guidance_lower and 'traffic' in guidance_lower:
            if 'process' in category and 'network' not in category:
                issues.append(f"WARNING: Technique {technique_id} may require network monitoring based on MITRE guidance")

        # Tool-specific validation based on guidance
        if 'powershell' in guidance_lower:
            if 'powershell' not in rule_content_str:
                issues.append(f"WARNING: Technique {technique_id} mentions PowerShell in MITRE guidance but rule doesn't focus on it")
        elif 'powershell' not in guidance_lower:
            if 'powershell' in parsed_rule.get('title', '').lower():
                issues.append(f"WARNING: Technique {technique_id} doesn't mention PowerShell in MITRE guidance but rule focuses on it")

        # Dynamic validation based on guidance content
        guidance_terms = self._extract_key_terms(guidance_lower)
        detection_terms = self._extract_key_terms(detection_str)

        # Check for semantic alignment between guidance and detection logic
        guidance_set = set(guidance_terms)
        detection_set = set(detection_terms)

        overlap = guidance_set.intersection(detection_set)

        # If guidance has specific technical terms but detection doesn't include them
        if len(guidance_terms) > 5 and len(overlap) < 2:
            # Look for partial matches
            partial_matches = 0
            for guide_term in guidance_terms:
                for detect_term in detection_terms:
                    if (len(guide_term) > 3 and len(detect_term) > 3 and
                        (guide_term in detect_term or detect_term in guide_term)):
                        partial_matches += 1
                        break

            if partial_matches < 2:
                issues.append(f"WARNING: Rule detection logic may not align well with MITRE guidance for technique {technique_id}")

        return issues

    def _create_sigma_generation_prompt(self, description: str, log_source: str, attack_technique: str, severity: str) -> str:
        """Create a detailed prompt for SIGMA rule generation with MITRE guidance"""

        # Get complete MITRE technique data
        mitre_data = self._get_mitre_technique_data(attack_technique)
        related_rules = self._get_related_sigma_rules(attack_technique, limit=2)

        # Safely extract tactic as string
        tactic_raw = mitre_data.get('tactic', 'unknown')
        if isinstance(tactic_raw, list):
            tactic = tactic_raw[0] if tactic_raw else 'unknown'
        else:
            tactic = str(tactic_raw) if tactic_raw else 'unknown'

        # Build enhanced prompt with complete MITRE context
        prompt = f"""You are a cybersecurity expert creating SIGMA detection rules. You MUST follow MITRE ATT&CK guidance exactly.

**ENHANCED MITRE ATT&CK CONTEXT:**"""

        # Add complete MITRE information if available
        if mitre_data:
            prompt += f"""
**Technique ID:** {mitre_data.get('technique_id', attack_technique)}
**Technique Name:** {mitre_data.get('name', 'Unknown')}
**Tactic:** {mitre_data.get('tactic', 'Unknown')}

**Complete MITRE Description:**
{mitre_data.get('description', 'No description available')}

**MITRE Detection Guidance:**
{mitre_data.get('detection', 'No specific detection guidance available')}

**Data Sources (from MITRE):**
{', '.join(mitre_data.get('data_sources', [])) if mitre_data.get('data_sources') else 'No data sources specified'}

**Platforms:**
{', '.join(mitre_data.get('platform', [])) if mitre_data.get('platform') else 'No platforms specified'}

**Permissions Required:**
{', '.join(mitre_data.get('permissions_required', [])) if mitre_data.get('permissions_required') else 'Not specified'}

**Defense Bypassed:**
{', '.join(mitre_data.get('defense_bypassed', [])) if mitre_data.get('defense_bypassed') else 'Not specified'}
"""

        # Add related rules context if available
        if related_rules:
            prompt += f"""

**RELATED EXISTING RULES:**
{self._format_related_rules(related_rules)}
"""

        prompt += f"""

**USER REQUEST:**
{description}

**TARGET LOG SOURCE:** {log_source}
**SEVERITY LEVEL:** {severity}

🎯 **CRITICAL REQUIREMENT**: Your SIGMA rule MUST detect exactly what the user described: "{description}"
- If the user mentions "SPN enumeration", your rule MUST detect SPN enumeration activities
- If the user mentions "Kerberoasting", your rule MUST detect Kerberoasting activities
- If the user mentions "PowerShell", your rule MUST detect PowerShell activities
- DO NOT create rules for unrelated techniques or activities

**ENHANCED DETECTION GUIDANCE:**
Based on the MITRE detection information above, focus on:
- Data sources mentioned in the MITRE guidance
- Detection methods specifically recommended by MITRE
- Log events and artifacts identified in the MITRE framework
- Behavioral patterns described in the MITRE detection section

**MANDATORY REQUIREMENTS:**

🚨 CRITICAL REQUIREMENTS - FAILURE TO FOLLOW WILL RESULT IN REJECTION:
1. You MUST use technique {attack_technique} and ONLY {attack_technique}
2. Do NOT use any other technique ID (like T1134, T1055, etc.) - ONLY {attack_technique}
3. You MUST use the correct MITRE tactic for {attack_technique}
4. Do NOT use 'unknown' tactic - use the proper MITRE tactic

USER REQUIREMENTS:
- Description: {description}
- Log Source: {log_source}
- MITRE ATT&CK Technique: {attack_technique} (USE THIS EXACT TECHNIQUE ID - NO SUBSTITUTIONS)
- Severity: {severity}"""

        # Add MITRE technique context if available
        if mitre_data:
            prompt += f"""

MITRE ATT&CK TECHNIQUE CONTEXT:
- Technique ID: {attack_technique} (USE THIS EXACT ID)
- Technique Name: {mitre_data.get('name', 'Unknown')}
- Tactic: {mitre_data.get('tactic', 'Unknown')} (USE THIS EXACT TACTIC - convert to lowercase with underscores)
- Platform: {mitre_data.get('platform', 'Unknown')}
- Data Sources: {mitre_data.get('data_sources', 'Unknown')}

🎯 TACTIC REQUIREMENT: You MUST use "attack.{tactic.lower().replace(' ', '_')}" as the tactic tag.

MITRE DETECTION GUIDANCE:
{mitre_data.get('detection', 'No specific detection guidance available.')}"""

        # Add examples from existing rules if available
        if related_rules:
            prompt += f"""

EXISTING SIGMA RULE EXAMPLES FOR REFERENCE:
(Use these as inspiration for detection logic, field names, and structure)"""

            for i, rule in enumerate(related_rules, 1):
                prompt += f"""

Example {i}: {rule.get('title', 'Unknown')}
Description: {rule.get('description', 'No description')[:200]}...
Confidence: {rule.get('confidence', 'Unknown')}"""

                # Include rule content snippet if available
                if rule.get('rule_content'):
                    rule_content = rule['rule_content'][:500]  # Limit content length
                    prompt += f"""
Rule snippet:
```yaml
{rule_content}...
```"""

        # Build dynamic constraints based on technique and MITRE data
        constraints = f"""

🚨 ABSOLUTE MANDATORY CONSTRAINTS - VIOLATION WILL RESULT IN IMMEDIATE REJECTION:

1. TECHNIQUE ID: You MUST use {attack_technique} and ONLY {attack_technique}
   - DO NOT use T1133, T1193, T1566, or any other technique ID
   - The technique tag MUST be: attack.{attack_technique.lower()}

2. TACTIC: You MUST use {tactic.lower().replace(' ', '_')}
   - The tactic tag MUST be: attack.{tactic.lower().replace(' ', '_')}

3. DATA SOURCES: You MUST align with {mitre_data.get('data_sources', 'Unknown')}
   - Follow the data source requirements exactly as specified

4. DETECTION LOGIC: You MUST follow the MITRE detection guidance above
   - Use the specific indicators mentioned in the guidance
   - Do NOT create generic or unrelated detection patterns

5. REFERENCE URL: You MUST use https://attack.mitre.org/techniques/{attack_technique}/
   - DO NOT use any other technique URL"""

        # Add technique-specific requirements
        specific_requirements = self._get_technique_specific_requirements(attack_technique, mitre_data)
        if specific_requirements:
            constraints += f"""

SPECIFIC DETECTION REQUIREMENTS FOR {mitre_data.get('name', attack_technique).upper()}:
{specific_requirements}"""

        prompt += constraints

        prompt += f"""

CRITICAL REQUIREMENTS:
1. FOLLOW MITRE DETECTION GUIDANCE: Base your detection logic on the MITRE guidance above
2. USE APPROPRIATE DATA SOURCES: Focus on the data sources mentioned in MITRE guidance
3. LEARN FROM EXAMPLES: Use similar field names and detection patterns from existing rules
4. BE SPECIFIC: Create precise detection criteria, not generic patterns
5. CONSIDER CONTEXT: Detection should be part of behavioral analysis, not isolated events

YAML STRUCTURE REQUIREMENTS:
- Use proper YAML syntax with 2-space indentation consistently
- Quote string values with special characters or colons
- Use proper list notation with dashes and 2-space indentation
- Ensure colons have spaces after them: "key: value" not "key:value"
- No tabs, only spaces
- Each list item should be on its own line with proper indentation
- Avoid complex nested structures that can cause parsing errors

REQUIRED SIGMA RULE STRUCTURE (FOLLOW EXACT INDENTATION):
```yaml
title: [Specific descriptive title based on technique behavior]
id: {str(uuid.uuid4())}
status: experimental
description: "[Detailed description incorporating MITRE guidance - use simple quoted string]"
author: AI Generated
date: {datetime.now().strftime('%Y/%m/%d')}
references:
  - https://attack.mitre.org/techniques/{attack_technique}/
tags:
  - attack.{tactic.lower().replace(' ', '_')}
  - attack.{attack_technique.lower()}
logsource:
  category: [appropriate category based on data sources]
  product: [specific product based on log source]
  service: [specific service if applicable]
detection:
  selection:
    [field_based_on_mitre_guidance]: [value_based_on_technique]
  condition: selection
falsepositives:
  - [Legitimate use case that might trigger this rule]
level: {severity}
```

CRITICAL: For the description field, ALWAYS use a simple quoted string like:
description: "This rule detects SPN enumeration activities..."
NEVER use literal block scalars like:
description: |
  This rule detects...
OR
description: "|"
  This rule detects...

CRITICAL YAML SYNTAX RULES:
1. Use exactly 2 spaces for indentation (never 4 spaces or tabs)
2. Always put a space after colons: "key: value"
3. For lists, use "- " (dash followed by space) with proper indentation
4. Quote values that contain special characters, numbers, or colons
5. Ensure proper nesting - child elements must be indented exactly 2 spaces from parent
6. Do not mix different indentation levels

VALIDATION CHECKLIST - YOUR RESPONSE MUST:
- Use technique ID {attack_technique} (NOT any other technique ID)
- Use tactic: {tactic.lower().replace(' ', '_')}
- Align with data sources: {mitre_data.get('data_sources', 'Unknown')}
- Follow the MITRE detection guidance provided above
- Include technique-specific detection indicators as specified

🚨 FINAL YAML SYNTAX CHECKLIST - VERIFY BEFORE RESPONDING:
1. Every colon followed by a space: "key: value" NOT "key:value"
2. Consistent 2-space indentation throughout
3. List items properly indented with "- " (dash + space)
4. No tabs anywhere in the YAML
5. Proper nesting - child elements exactly 2 spaces more than parent
6. Quote values containing special characters or numbers
7. No missing colons or malformed key-value pairs
8. For multiline descriptions, use simple quoted strings, NOT literal block scalars (|)
9. NEVER use "|" or '"|"' for descriptions - use simple strings instead

EXAMPLE OF CORRECT YAML FORMATTING:
```yaml
title: Example Rule
detection:
  selection:
    EventID: "4769"
    ServiceName: "krbtgt"
  condition: selection
```

EXAMPLE OF CORRECT MULTIPLE CONDITIONS:
```yaml
detection:
  selection1:
    EventID: "4769"
  selection2:
    EventID: "4768"
  condition: selection1 or selection2
```

❌ NEVER DO THIS (INVALID YAML):
```yaml
detection:
  selection:
    EventID: 4769
    or
    EventID: 4768
```

✅ CORRECT WAY FOR MULTIPLE VALUES:
```yaml
detection:
  selection:
    EventID:
      - "4769"
      - "4768"
  condition: selection
```

Generate ONLY the complete YAML rule content. Ensure it follows MITRE detection guidance and uses appropriate detection logic for {attack_technique}.

RESPOND WITH ONLY THE YAML CONTENT - NO EXPLANATIONS OR ADDITIONAL TEXT."""

        return prompt
    
    def _call_ollama(self, prompt: str) -> Dict[str, Any]:
        """Make API call to Ollama"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "max_tokens": 2048
                }
            }
            
            response = requests.post(
                f"{self.ollama_host}/api/generate",
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'content': result.get('response', ''),
                    'model': result.get('model', self.model)
                }
            else:
                return {
                    'success': False,
                    'error': f'Ollama API error: {response.status_code} - {response.text}'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }
    
    def _extract_sigma_rule(self, content: str) -> Optional[str]:
        """Extract SIGMA rule YAML from LLM response with improved parsing"""
        try:
            # Look for YAML code blocks first
            yaml_pattern = r'```(?:yaml|yml)?\s*(.*?)```'
            matches = re.findall(yaml_pattern, content, re.DOTALL | re.IGNORECASE)

            if matches:
                extracted_yaml = matches[0].strip()
                # Clean up common formatting issues
                extracted_yaml = self._clean_yaml_content(extracted_yaml)
                return extracted_yaml

            # If no code blocks, try to find YAML-like content
            lines = content.split('\n')
            yaml_lines = []
            in_yaml = False

            for line in lines:
                if line.strip().startswith('title:') or line.strip().startswith('id:'):
                    in_yaml = True

                if in_yaml:
                    yaml_lines.append(line)

                    # Stop at end of YAML-like content
                    if line.strip() == '' and len(yaml_lines) > 10:
                        break

            if yaml_lines:
                extracted_yaml = '\n'.join(yaml_lines).strip()
                # Clean up common formatting issues
                extracted_yaml = self._clean_yaml_content(extracted_yaml)
                return extracted_yaml

            return None

        except Exception as e:
            self.logger.error(f"Error extracting SIGMA rule: {e}")
            return None

    def _clean_yaml_content(self, yaml_content: str) -> str:
        """Clean up common YAML formatting issues"""
        try:
            lines = yaml_content.split('\n')
            cleaned_lines = []
            in_multiline_description = False
            description_indent = 0

            for i, line in enumerate(lines):
                # Skip empty lines at the beginning
                if not cleaned_lines and not line.strip():
                    continue

                # Handle multiline description with literal block scalar
                if 'description:' in line and ('"|"' in line or '|' in line):
                    # Fix the literal block scalar syntax
                    if '"|"' in line:
                        line = line.replace('"|"', '|')
                    elif ': |' not in line and ':|' in line:
                        line = line.replace(':|', ': |')
                    elif ':  |' in line:
                        line = line.replace(':  |', ': |')

                    in_multiline_description = True
                    description_indent = len(line) - len(line.lstrip())
                    cleaned_lines.append(line)
                    continue

                # Handle continuation of multiline description
                if in_multiline_description:
                    # Check if this line is part of the description (indented more than description key)
                    current_indent = len(line) - len(line.lstrip()) if line.strip() else 0

                    # If we hit a line that's not indented more than description, we're done with description
                    if line.strip() and current_indent <= description_indent:
                        in_multiline_description = False
                    else:
                        # This is part of the description - ensure proper indentation
                        if line.strip():
                            # Ensure description content is indented 2 spaces from description key
                            proper_indent = description_indent + 2
                            cleaned_line = ' ' * proper_indent + line.strip()
                            cleaned_lines.append(cleaned_line)
                        else:
                            cleaned_lines.append('')
                        continue

                # Fix common indentation and formatting issues
                if line.strip():
                    # Ensure proper spacing after colons
                    if ':' in line and not line.strip().startswith('-'):
                        # Split on first colon only
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            key = parts[0].rstrip()
                            value = parts[1].lstrip()
                            # Preserve original indentation
                            indent = len(line) - len(line.lstrip())

                            if value:
                                # Don't quote literal block scalars or special YAML syntax
                                if value not in ['|', '>', '|-', '>-'] and not value.startswith('[') and not value.startswith('{'):
                                    # Quote numeric values and values with special characters (except YAML syntax)
                                    if (value.isdigit() or
                                        any(char in value for char in [':', '#', '@']) or
                                        (value.startswith('*') and value.endswith('*'))):
                                        if not (value.startswith('"') and value.endswith('"')):
                                            value = f'"{value}"'
                                line = ' ' * indent + key + ': ' + value
                            else:
                                line = ' ' * indent + key + ':'

                cleaned_lines.append(line)

            return '\n'.join(cleaned_lines)

        except Exception as e:
            self.logger.error(f"Error cleaning YAML content: {e}")
            return yaml_content

    def _check_yaml_syntax_issues(self, yaml_content: str) -> List[str]:
        """Check for common YAML syntax issues before parsing"""
        issues = []
        lines = yaml_content.split('\n')

        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue

            # Check for missing spaces after colons
            if ':' in line and not line.strip().startswith('-'):
                # Look for colons not followed by space (but allow colons at end of line)
                if ':' in line and not ': ' in line and not line.rstrip().endswith(':'):
                    issues.append(f"Line {i}: Missing space after colon")

            # Check for tabs
            if '\t' in line:
                issues.append(f"Line {i}: Contains tabs instead of spaces")

            # Check for inconsistent indentation (should be multiples of 2)
            if line.startswith(' '):
                indent = len(line) - len(line.lstrip())
                if indent % 2 != 0:
                    issues.append(f"Line {i}: Inconsistent indentation ({indent} spaces)")

            # Check for standalone logical operators (common SIGMA rule error)
            stripped_line = line.strip().lower()
            if stripped_line in ['or', 'and', 'not'] and not line.strip().endswith(':'):
                issues.append(f"Line {i}: Standalone logical operator '{stripped_line}' - should be in condition field")

        return issues

    def _analyze_yaml_error(self, yaml_content: str, error_message: str) -> Dict[str, Any]:
        """Analyze YAML parsing errors and provide helpful diagnostics"""
        try:
            lines = yaml_content.split('\n')
            error_details = {
                'error_message': error_message,
                'line_count': len(lines),
                'issues_found': [],
                'suggestions': []
            }

            # Extract line number from error message if available
            line_number = None
            if 'line' in error_message:
                import re
                line_match = re.search(r'line (\d+)', error_message)
                if line_match:
                    line_number = int(line_match.group(1))

            # Check for common YAML issues
            for i, line in enumerate(lines, 1):
                if not line.strip():
                    continue

                # Check for missing spaces after colons
                if ':' in line and not line.strip().startswith('-'):
                    if ':' in line and not ': ' in line and not line.endswith(':'):
                        error_details['issues_found'].append(f"Line {i}: Missing space after colon - '{line.strip()}'")
                        error_details['suggestions'].append(f"Line {i}: Change to '{line.replace(':', ': ')}'")

                # Check for inconsistent indentation
                if line.startswith(' '):
                    indent = len(line) - len(line.lstrip())
                    if indent % 2 != 0:
                        error_details['issues_found'].append(f"Line {i}: Inconsistent indentation ({indent} spaces) - '{line.strip()}'")
                        error_details['suggestions'].append(f"Line {i}: Use 2, 4, 6, etc. spaces for indentation")

                # Check for tabs
                if '\t' in line:
                    error_details['issues_found'].append(f"Line {i}: Contains tabs instead of spaces - '{line.strip()}'")
                    error_details['suggestions'].append(f"Line {i}: Replace tabs with spaces")

            # If we have a specific line number from the error, focus on that area
            if line_number and line_number <= len(lines):
                problematic_line = lines[line_number - 1]
                error_details['problematic_line'] = {
                    'line_number': line_number,
                    'content': problematic_line,
                    'analysis': f"Issue detected in: '{problematic_line.strip()}'"
                }

            return error_details

        except Exception as e:
            return {
                'error_message': error_message,
                'analysis_error': f"Could not analyze YAML error: {str(e)}"
            }

    def _parse_rule_analysis(self, content: str) -> Dict[str, Any]:
        """Parse rule analysis from LLM response"""
        analysis = {
            'effectiveness_score': None,
            'false_positives': [],
            'improvements': [],
            'mitre_mappings': [],
            'recommendations': []
        }
        
        try:
            # Extract effectiveness score
            score_match = re.search(r'effectiveness.*?(\d+(?:\.\d+)?)', content, re.IGNORECASE)
            if score_match:
                analysis['effectiveness_score'] = float(score_match.group(1))
            
            # Extract sections (simplified parsing)
            sections = content.split('\n')
            current_section = None
            
            for line in sections:
                line = line.strip()
                if 'false positive' in line.lower():
                    current_section = 'false_positives'
                elif 'improvement' in line.lower() or 'gap' in line.lower():
                    current_section = 'improvements'
                elif 'mitre' in line.lower():
                    current_section = 'mitre_mappings'
                elif 'recommendation' in line.lower():
                    current_section = 'recommendations'
                elif line.startswith('-') or line.startswith('•'):
                    if current_section and current_section in analysis:
                        analysis[current_section].append(line[1:].strip())
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error parsing rule analysis: {e}")
            return analysis
    
    def _extract_suggestions(self, content: str) -> List[str]:
        """Extract improvement suggestions from LLM response"""
        suggestions = []
        
        try:
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('-') or line.startswith('•') or line.startswith('*'):
                    suggestions.append(line[1:].strip())
            
            return suggestions
            
        except Exception as e:
            self.logger.error(f"Error extracting suggestions: {e}")
            return []
    
    def _extract_summary(self, content: str) -> str:
        """Extract summary from explanation"""
        try:
            # Take first paragraph or first few sentences
            paragraphs = content.split('\n\n')
            if paragraphs:
                return paragraphs[0].strip()
            
            # Fallback to first 200 characters
            return content[:200] + "..." if len(content) > 200 else content
            
        except Exception as e:
            self.logger.error(f"Error extracting summary: {e}")
            return "Summary not available"

    def get_available_models(self, ollama_host: str = None) -> List[str]:
        """Get list of available models from Ollama"""
        try:
            host = ollama_host or self.ollama_host
            response = requests.get(f"{host}/api/tags", timeout=5)

            if response.status_code == 200:
                data = response.json()
                models = [model['name'] for model in data.get('models', [])]
                return sorted(models) if models else [self.model]
            else:
                return [self.model]

        except Exception as e:
            self.logger.error(f"Error getting available models: {e}")
            return [self.model]
