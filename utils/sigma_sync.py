"""
SIGMA Rules Synchronization Module
Handles downloading and syncing SIGMA rules from GitHub repositories
"""

import os
import yaml
import requests
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from git import Repo
import tempfile
import shutil

class SigmaSync:
    """Handles synchronization of SIGMA rules from GitHub repositories"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # SIGMA repositories to sync
        self.repositories = {
            'main': {
                'url': 'https://github.com/SigmaHQ/sigma.git',
                'rules_path': 'rules',
                'name': 'SigmaHQ Main Rules'
            },
            'threat-hunting': {
                'url': 'https://github.com/SigmaHQ/sigma.git',
                'rules_path': 'rules-threat-hunting',
                'name': 'SigmaHQ Threat Hunting Rules'
            },
            'emerging-threats': {
                'url': 'https://github.com/SigmaHQ/sigma.git',
                'rules_path': 'rules-emerging-threats',
                'name': 'SigmaHQ Emerging Threats'
            }
        }
        
        self.local_cache_dir = Path("data/sigma_rules")
        self.local_cache_dir.mkdir(parents=True, exist_ok=True)
    
    def sync_all_rules(self) -> Dict[str, Any]:
        """Sync all SIGMA rules from configured repositories"""
        try:
            total_synced = 0
            sync_results = {}
            
            self.logger.info("Starting SIGMA rules synchronization")
            
            for repo_key, repo_config in self.repositories.items():
                self.logger.info(f"Syncing repository: {repo_config['name']}")
                
                result = self._sync_repository(repo_key, repo_config)
                sync_results[repo_key] = result
                
                if result['success']:
                    total_synced += result['rules_synced']
                else:
                    self.logger.error(f"Failed to sync {repo_config['name']}: {result['error']}")
            
            # Log sync activity
            self.db_manager.log_activity(
                "SIGMA Rules Sync",
                f"Synced {total_synced} rules from {len(self.repositories)} repositories"
            )
            
            # Record sync history
            self._record_sync_history('sigma_rules', 'success', f"Synced {total_synced} rules", total_synced)
            
            return {
                'success': True,
                'count': total_synced,
                'details': sync_results
            }
            
        except Exception as e:
            self.logger.error(f"Error during SIGMA rules sync: {e}")
            self._record_sync_history('sigma_rules', 'error', str(e), 0)
            return {
                'success': False,
                'error': str(e)
            }
    
    def _sync_repository(self, repo_key: str, repo_config: Dict) -> Dict[str, Any]:
        """Sync rules from a specific repository"""
        try:
            # Create temporary directory for cloning
            with tempfile.TemporaryDirectory() as temp_dir:
                repo_path = Path(temp_dir) / repo_key
                
                # Clone repository
                self.logger.info(f"Cloning repository: {repo_config['url']}")
                repo = Repo.clone_from(repo_config['url'], repo_path, depth=1)
                
                # Find and process SIGMA rule files
                rules_path = repo_path / repo_config['rules_path']
                
                if not rules_path.exists():
                    return {
                        'success': False,
                        'error': f"Rules path not found: {repo_config['rules_path']}"
                    }
                
                rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
                rules_synced = 0
                
                for rule_file in rule_files:
                    try:
                        if self._process_rule_file(rule_file, repo_config['name']):
                            rules_synced += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to process rule file {rule_file}: {e}")
                        continue
                
                return {
                    'success': True,
                    'rules_synced': rules_synced,
                    'total_files': len(rule_files)
                }
                
        except Exception as e:
            self.logger.error(f"Error syncing repository {repo_key}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _process_rule_file(self, rule_file: Path, source_repo: str) -> bool:
        """Process a single SIGMA rule file"""
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            
            # Parse YAML content
            rule_data = yaml.safe_load(rule_content)
            
            if not rule_data or not isinstance(rule_data, dict):
                return False
            
            # Generate rule ID if not present
            rule_id = rule_data.get('id')
            if not rule_id:
                # Generate ID from file path and content hash
                content_hash = hashlib.md5(rule_content.encode()).hexdigest()[:8]
                rule_id = f"{rule_file.stem}_{content_hash}"
            
            # Extract rule metadata
            processed_rule = {
                'rule_id': rule_id,
                'title': rule_data.get('title', ''),
                'description': rule_data.get('description', ''),
                'author': rule_data.get('author', ''),
                'date': rule_data.get('date', ''),
                'status': rule_data.get('status', ''),
                'level': rule_data.get('level', ''),
                'logsource': rule_data.get('logsource', {}),
                'detection': rule_data.get('detection', {}),
                'falsepositives': rule_data.get('falsepositives', []),
                'tags': rule_data.get('tags', []),
                'references': rule_data.get('references', []),
                'rule_content': rule_content,
                'file_path': str(rule_file.relative_to(rule_file.parents[2])),  # Relative to repo root
                'source_repo': source_repo,
                'is_custom': False
            }
            
            # Insert into database
            success = self.db_manager.insert_sigma_rule(processed_rule)
            
            if success:
                # Extract and store MITRE ATT&CK mappings if present
                self._extract_mitre_mappings(rule_id, rule_data.get('tags', []))
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error processing rule file {rule_file}: {e}")
            return False
    
    def _extract_mitre_mappings(self, rule_id: str, tags: List[str]):
        """Extract MITRE ATT&CK technique mappings from rule tags with enhanced accuracy"""
        try:
            mitre_tags = [tag for tag in tags if tag.startswith('attack.t') or tag.startswith('attack.T')]

            for tag in mitre_tags:
                # Extract technique ID (e.g., 'attack.t1055' -> 'T1055')
                if '.' in tag:
                    technique_id = tag.split('.')[1].upper()
                    if technique_id.startswith('T'):
                        # Calculate confidence based on enhanced MITRE data
                        confidence = self._calculate_mapping_confidence(rule_id, technique_id)

                        # Store mapping with calculated confidence
                        self._store_rule_technique_mapping(rule_id, technique_id, confidence)

        except Exception as e:
            self.logger.error(f"Error extracting MITRE mappings for rule {rule_id}: {e}")

    def _calculate_mapping_confidence(self, rule_id: str, technique_id: str) -> float:
        """Calculate mapping confidence using enhanced MITRE data"""
        try:
            # Get rule details
            rule_data = self._get_rule_data(rule_id)
            if not rule_data:
                return 1.0  # Default confidence for explicit tag mappings

            # Get enhanced technique data
            technique_data = self.db_manager.get_mitre_technique_details(technique_id)
            if not technique_data:
                return 1.0  # Default confidence if technique data not available

            confidence = 1.0  # Start with base confidence for explicit mapping

            # Enhance confidence based on content analysis
            rule_title = rule_data.get('title', '').lower()
            rule_description = rule_data.get('description', '').lower()
            rule_content = f"{rule_title} {rule_description}"

            technique_name = technique_data.get('name', '').lower()
            technique_description = technique_data.get('description', '').lower()
            technique_detection = technique_data.get('detection', '').lower()

            # Check for keyword overlap
            rule_words = set(word.strip() for word in rule_content.split() if len(word.strip()) > 3)
            technique_words = set(word.strip() for word in f"{technique_name} {technique_description} {technique_detection}".split() if len(word.strip()) > 3)

            # Calculate word overlap ratio
            if rule_words and technique_words:
                overlap = len(rule_words.intersection(technique_words))
                overlap_ratio = overlap / len(rule_words)

                # Adjust confidence based on overlap
                if overlap_ratio > 0.3:
                    confidence += 0.2  # High overlap
                elif overlap_ratio > 0.1:
                    confidence += 0.1  # Moderate overlap

            # Check for data source alignment
            technique_data_sources = technique_data.get('data_sources', [])
            if isinstance(technique_data_sources, str):
                try:
                    technique_data_sources = json.loads(technique_data_sources)
                except:
                    technique_data_sources = []

            # Check if rule mentions relevant data sources
            for data_source in technique_data_sources:
                if data_source.lower() in rule_content:
                    confidence += 0.1
                    break

            # Cap confidence at reasonable maximum
            return min(confidence, 1.5)

        except Exception as e:
            self.logger.error(f"Error calculating mapping confidence: {e}")
            return 1.0

    def _get_rule_data(self, rule_id: str) -> Optional[Dict]:
        """Get rule data from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT rule_id, title, description, level, tags
                    FROM sigma_rules
                    WHERE rule_id = ?
                """, (rule_id,))

                row = cursor.fetchone()
                if row:
                    columns = [description[0] for description in cursor.description]
                    return dict(zip(columns, row))

                return None

        except Exception as e:
            self.logger.error(f"Error getting rule data: {e}")
            return None
    
    def _store_rule_technique_mapping(self, rule_id: str, technique_id: str, confidence: float = 1.0):
        """Store rule-technique mapping (prevents duplicates)"""
        try:
            # Use the database manager's method which handles the updated_at column properly
            success = self.db_manager.store_rule_technique_mapping(rule_id, technique_id, confidence)
            if not success:
                self.logger.warning(f"Failed to store mapping {rule_id} -> {technique_id}")

        except Exception as e:
            self.logger.error(f"Error storing rule-technique mapping: {e}")

    def enhance_rule_mappings(self):
        """Enhance existing rule mappings using enhanced MITRE data"""
        try:
            self.logger.info("Starting enhanced rule mapping analysis...")

            # Get all rules without explicit MITRE mappings
            unmapped_rules = self._get_unmapped_rules()

            if not unmapped_rules:
                self.logger.info("No unmapped rules found")
                return

            self.logger.info(f"Analyzing {len(unmapped_rules)} unmapped rules for potential MITRE mappings")

            # Get all techniques for comparison
            all_techniques = self.db_manager.get_mitre_techniques()

            mapping_count = 0

            for rule in unmapped_rules:
                rule_id = rule.get('rule_id')
                if not rule_id:
                    continue

                # Find potential technique matches
                potential_mappings = self._find_potential_mappings(rule, all_techniques)

                # Store high-confidence mappings
                for technique_id, confidence in potential_mappings:
                    if confidence >= 0.7:  # Only store high-confidence mappings
                        self._store_rule_technique_mapping(rule_id, technique_id, confidence)
                        mapping_count += 1

            self.logger.info(f"Enhanced mapping analysis complete. Added {mapping_count} new mappings.")

        except Exception as e:
            self.logger.error(f"Error enhancing rule mappings: {e}")

    def _get_unmapped_rules(self) -> List[Dict]:
        """Get rules that don't have explicit MITRE mappings"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get rules that don't have any technique mappings
                cursor.execute("""
                    SELECT sr.rule_id, sr.title, sr.description, sr.tags
                    FROM sigma_rules sr
                    LEFT JOIN rule_technique_mappings rtm ON sr.rule_id = rtm.rule_id
                    WHERE rtm.rule_id IS NULL
                    AND sr.tags NOT LIKE '%attack.t%'
                    LIMIT 100
                """)

                rows = cursor.fetchall()
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting unmapped rules: {e}")
            return []

    def _find_potential_mappings(self, rule: Dict, techniques: List[Dict]) -> List[tuple]:
        """Find potential technique mappings for a rule using enhanced analysis"""
        try:
            rule_title = rule.get('title', '').lower()
            rule_description = rule.get('description', '').lower()
            rule_content = f"{rule_title} {rule_description}"
            rule_words = set(word.strip() for word in rule_content.split() if len(word.strip()) > 3)

            potential_mappings = []

            for technique in techniques:
                technique_id = technique.get('technique_id', '')
                if not technique_id:
                    continue

                confidence = self._calculate_content_similarity(rule, technique)

                if confidence > 0.5:  # Minimum threshold for consideration
                    potential_mappings.append((technique_id, confidence))

            # Sort by confidence and return top matches
            potential_mappings.sort(key=lambda x: x[1], reverse=True)
            return potential_mappings[:3]  # Return top 3 matches

        except Exception as e:
            self.logger.error(f"Error finding potential mappings: {e}")
            return []

    def _calculate_content_similarity(self, rule: Dict, technique: Dict) -> float:
        """Calculate similarity between rule and technique content"""
        try:
            # Rule content
            rule_title = rule.get('title', '').lower()
            rule_description = rule.get('description', '').lower()
            rule_content = f"{rule_title} {rule_description}"
            rule_words = set(word.strip() for word in rule_content.split() if len(word.strip()) > 3)

            # Technique content (enhanced)
            technique_name = technique.get('name', '').lower()
            technique_description = technique.get('description', '').lower()
            technique_detection = technique.get('detection', '').lower()
            technique_content = f"{technique_name} {technique_description} {technique_detection}"
            technique_words = set(word.strip() for word in technique_content.split() if len(word.strip()) > 3)

            if not rule_words or not technique_words:
                return 0.0

            # Calculate Jaccard similarity
            intersection = len(rule_words.intersection(technique_words))
            union = len(rule_words.union(technique_words))

            if union == 0:
                return 0.0

            jaccard_similarity = intersection / union

            # Boost score for technique name matches
            if any(word in technique_name for word in rule_words if len(word) > 4):
                jaccard_similarity += 0.3

            # Boost score for detection method matches
            if technique_detection and any(word in technique_detection for word in rule_words if len(word) > 4):
                jaccard_similarity += 0.2

            return min(jaccard_similarity, 1.0)

        except Exception as e:
            self.logger.error(f"Error calculating content similarity: {e}")
            return 0.0
    
    def _record_sync_history(self, sync_type: str, status: str, message: str, rules_synced: int):
        """Record sync operation in history"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sync_history (sync_type, status, message, rules_synced)
                    VALUES (?, ?, ?, ?)
                """, (sync_type, status, message, rules_synced))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error recording sync history: {e}")
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status and history"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get latest sync for each type
                cursor.execute("""
                    SELECT sync_type, status, message, rules_synced, sync_timestamp
                    FROM sync_history 
                    WHERE id IN (
                        SELECT MAX(id) FROM sync_history GROUP BY sync_type
                    )
                    ORDER BY sync_timestamp DESC
                """)
                
                latest_syncs = [dict(row) for row in cursor.fetchall()]
                
                # Get sync history (last 10)
                cursor.execute("""
                    SELECT * FROM sync_history 
                    ORDER BY sync_timestamp DESC 
                    LIMIT 10
                """)
                
                sync_history = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'latest_syncs': latest_syncs,
                    'sync_history': sync_history
                }
                
        except Exception as e:
            self.logger.error(f"Error getting sync status: {e}")
            return {}
    
    def force_sync_repository(self, repo_key: str) -> Dict[str, Any]:
        """Force sync a specific repository"""
        if repo_key not in self.repositories:
            return {
                'success': False,
                'error': f"Unknown repository: {repo_key}"
            }
        
        repo_config = self.repositories[repo_key]
        return self._sync_repository(repo_key, repo_config)
    
    def add_custom_rule(self, rule_content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Add a custom SIGMA rule"""
        try:
            # Parse rule content
            rule_data = yaml.safe_load(rule_content)
            
            if not rule_data or not isinstance(rule_data, dict):
                return {
                    'success': False,
                    'error': 'Invalid YAML content'
                }
            
            # Generate custom rule ID
            rule_id = metadata.get('rule_id')
            if not rule_id:
                content_hash = hashlib.md5(rule_content.encode()).hexdigest()[:8]
                rule_id = f"custom_{content_hash}"
            
            # Prepare rule data
            processed_rule = {
                'rule_id': rule_id,
                'title': rule_data.get('title', metadata.get('title', '')),
                'description': rule_data.get('description', metadata.get('description', '')),
                'author': rule_data.get('author', metadata.get('author', 'Custom')),
                'date': rule_data.get('date', datetime.now().strftime('%Y/%m/%d')),
                'status': rule_data.get('status', 'experimental'),
                'level': rule_data.get('level', metadata.get('level', 'medium')),
                'logsource': rule_data.get('logsource', {}),
                'detection': rule_data.get('detection', {}),
                'falsepositives': rule_data.get('falsepositives', []),
                'tags': rule_data.get('tags', []) + ['custom'],
                'references': rule_data.get('references', []),
                'rule_content': rule_content,
                'file_path': f"custom/{rule_id}.yml",
                'source_repo': 'Custom Rules',
                'is_custom': True
            }
            
            # Insert into database
            success = self.db_manager.insert_sigma_rule(processed_rule)
            
            if success:
                # Extract MITRE mappings
                self._extract_mitre_mappings(rule_id, processed_rule['tags'])
                
                # Log activity
                self.db_manager.log_activity(
                    "Custom Rule Added",
                    f"Added custom rule: {processed_rule['title']}"
                )
                
                return {
                    'success': True,
                    'rule_id': rule_id,
                    'message': 'Custom rule added successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to save rule to database'
                }
                
        except Exception as e:
            self.logger.error(f"Error adding custom rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }
