"""
Database Manager for SIGMA Detection Engineering Platform
Handles SQLite database operations for SIGMA rules, MITRE data, and user configurations
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import threading
from contextlib import contextmanager

class DatabaseManager:
    """Manages SQLite database operations for the detection platform"""

    def __init__(self, db_path: str = "data/database/sigma_platform.db"):
        self.db_path = db_path
        self.ensure_db_directory()
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()
        self._connection_cache = threading.local()
        
    def ensure_db_directory(self):
        """Ensure database directory exists"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """Get database connection with proper resource management"""
        conn = None
        try:
            # Use thread-local connection caching for better performance
            if not hasattr(self._connection_cache, 'conn') or self._connection_cache.conn is None:
                conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA cache_size=10000")
                conn.execute("PRAGMA temp_store=MEMORY")
                conn.execute("PRAGMA foreign_keys=ON")
                self._connection_cache.conn = conn
            else:
                conn = self._connection_cache.conn

            yield conn

        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            # Don't close connection here - let it be reused
            pass

    def close_connections(self):
        """Close all cached connections"""
        if hasattr(self._connection_cache, 'conn') and self._connection_cache.conn:
            self._connection_cache.conn.close()
            self._connection_cache.conn = None
    
    def initialize_database(self):
        """Initialize database with required tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Enable foreign keys
                cursor.execute("PRAGMA foreign_keys = ON")

                # SIGMA Rules table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sigma_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT UNIQUE,
                        title TEXT NOT NULL,
                        description TEXT,
                        author TEXT,
                        date TEXT,
                        status TEXT,
                        level TEXT,
                        logsource TEXT,
                        detection TEXT,
                        falsepositives TEXT,
                        tags TEXT,
                        rule_references TEXT,
                        rule_content TEXT NOT NULL,
                        file_path TEXT,
                        source_repo TEXT,
                        is_custom BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # MITRE ATT&CK Techniques table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitre_techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    tactic TEXT,
                    platform TEXT,
                    data_sources TEXT,
                    detection TEXT,
                    mitigation TEXT,
                    technique_references TEXT,
                    permissions_required TEXT,
                    sub_techniques TEXT,
                    procedure_examples TEXT,
                    kill_chain_phases TEXT,
                    system_requirements TEXT,
                    network_requirements TEXT,
                    remote_support TEXT,
                    impact_type TEXT,
                    effective_permissions TEXT,
                    defense_bypassed TEXT,
                    framework TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # MITRE ATT&CK Tactics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitre_tactics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tactic_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Check if rule_technique_mappings table exists and has updated_at column
            cursor.execute("PRAGMA table_info(rule_technique_mappings)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'rule_technique_mappings' not in [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
                # Table doesn't exist, create it with all columns
                cursor.execute("""
                    CREATE TABLE rule_technique_mappings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT NOT NULL,
                        technique_id TEXT NOT NULL,
                        confidence REAL DEFAULT 1.0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(rule_id, technique_id),
                        FOREIGN KEY (rule_id) REFERENCES sigma_rules (rule_id),
                        FOREIGN KEY (technique_id) REFERENCES mitre_techniques (technique_id)
                    )
                """)
            elif 'updated_at' not in columns:
                # Table exists but missing updated_at column, add it
                self.logger.info("Adding updated_at column to rule_technique_mappings table")
                cursor.execute("""
                    ALTER TABLE rule_technique_mappings
                    ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """)
                # Update existing rows to have updated_at value
                cursor.execute("""
                    UPDATE rule_technique_mappings
                    SET updated_at = created_at
                    WHERE updated_at IS NULL
                """)
            
            # Search embeddings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE,
                    embedding BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rule_id) REFERENCES sigma_rules (rule_id)
                )
            """)

            # Pending rule-technique mappings table (for mappings where technique doesn't exist yet)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pending_rule_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(rule_id, technique_id)
                )
            """)
            
            # Sync history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sync_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sync_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    rules_synced INTEGER DEFAULT 0,
                    sync_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # User activity log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Custom attack scenarios table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_scenarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scenario_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT NOT NULL,
                    tactics TEXT NOT NULL,
                    techniques TEXT NOT NULL,
                    platforms TEXT,
                    author TEXT,
                    tags TEXT,
                    is_public BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Add new columns to existing mitre_techniques table if they don't exist
            try:
                # Check if new columns exist and add them if they don't
                cursor.execute("PRAGMA table_info(mitre_techniques)")
                columns = [column[1] for column in cursor.fetchall()]

                new_columns = [
                    ("permissions_required", "TEXT"),
                    ("sub_techniques", "TEXT"),
                    ("procedure_examples", "TEXT"),
                    ("kill_chain_phases", "TEXT"),
                    ("system_requirements", "TEXT"),
                    ("network_requirements", "TEXT"),
                    ("remote_support", "TEXT"),
                    ("impact_type", "TEXT"),
                    ("effective_permissions", "TEXT"),
                    ("defense_bypassed", "TEXT"),
                    ("framework", "TEXT")
                ]

                for column_name, column_type in new_columns:
                    if column_name not in columns:
                        cursor.execute(f"ALTER TABLE mitre_techniques ADD COLUMN {column_name} {column_type}")
                        self.logger.info(f"Added column {column_name} to mitre_techniques table")

            except Exception as e:
                self.logger.warning(f"Error adding new columns to mitre_techniques: {e}")

            # Migrate framework data for existing techniques
            try:
                cursor.execute("SELECT technique_id FROM mitre_techniques WHERE framework IS NULL OR framework = ''")
                techniques_to_update = cursor.fetchall()

                if techniques_to_update:
                    self.logger.info(f"Migrating framework data for {len(techniques_to_update)} techniques")
                    for (technique_id,) in techniques_to_update:
                        framework = 'ics' if technique_id.startswith('T0') else 'enterprise'
                        cursor.execute(
                            "UPDATE mitre_techniques SET framework = ? WHERE technique_id = ?",
                            (framework, technique_id)
                        )
                    conn.commit()
                    self.logger.info("Framework migration completed")
            except Exception as e:
                self.logger.warning(f"Error migrating framework data: {e}")

            # Create indexes for better performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_sigma_rules_tags ON sigma_rules(tags)",
                "CREATE INDEX IF NOT EXISTS idx_sigma_rules_level ON sigma_rules(level)",
                "CREATE INDEX IF NOT EXISTS idx_sigma_rules_source ON sigma_rules(source_repo)",
                "CREATE INDEX IF NOT EXISTS idx_sigma_rules_title ON sigma_rules(title)",
                "CREATE INDEX IF NOT EXISTS idx_sigma_rules_custom ON sigma_rules(is_custom)",
                "CREATE INDEX IF NOT EXISTS idx_mitre_techniques_tactic ON mitre_techniques(tactic)",
                "CREATE INDEX IF NOT EXISTS idx_mitre_techniques_platform ON mitre_techniques(platform)",
                "CREATE INDEX IF NOT EXISTS idx_rule_mappings_rule ON rule_technique_mappings(rule_id)",
                "CREATE INDEX IF NOT EXISTS idx_rule_mappings_technique ON rule_technique_mappings(technique_id)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_mappings_unique ON rule_technique_mappings(rule_id, technique_id)",
                "CREATE INDEX IF NOT EXISTS idx_custom_scenarios_category ON custom_scenarios(category)",
                "CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_sync_history_type ON sync_history(sync_type)",
                "CREATE INDEX IF NOT EXISTS idx_sync_history_timestamp ON sync_history(sync_timestamp)"
            ]

            for index_sql in indexes:
                cursor.execute(index_sql)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_custom_scenarios_author ON custom_scenarios(author)")

            conn.commit()
            self.logger.info("Database initialized successfully")

        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def insert_sigma_rule(self, rule_data: Dict[str, Any]) -> bool:
        """Insert or update a SIGMA rule"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO sigma_rules
                    (rule_id, title, description, author, date, status, level,
                     logsource, detection, falsepositives, tags, rule_references,
                     rule_content, file_path, source_repo, is_custom, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule_data.get('rule_id'),
                    rule_data.get('title'),
                    rule_data.get('description'),
                    rule_data.get('author'),
                    rule_data.get('date'),
                    rule_data.get('status'),
                    rule_data.get('level'),
                    json.dumps(rule_data.get('logsource', {})),
                    json.dumps(rule_data.get('detection', {})),
                    json.dumps(rule_data.get('falsepositives', [])),
                    json.dumps(rule_data.get('tags', [])),
                    json.dumps(rule_data.get('references', [])),
                    rule_data.get('rule_content'),
                    rule_data.get('file_path'),
                    rule_data.get('source_repo'),
                    rule_data.get('is_custom', False),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error inserting SIGMA rule: {e}")
            return False
    
    def get_sigma_rules(self, filters: Optional[Dict] = None, limit: Optional[int] = None,
                       offset: int = 0) -> List[Dict]:
        """Get SIGMA rules with optional filters and pagination"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Use optimized query with proper indexing
                query = """
                    SELECT id, rule_id, title, description, author, date, status, level,
                           logsource, detection, falsepositives, tags, rule_references,
                           rule_content, file_path, source_repo, is_custom,
                           created_at, updated_at
                    FROM sigma_rules WHERE 1=1
                """
                params = []

                if filters:
                    # Handle level filter (can be single value or list)
                    if 'level' in filters:
                        level_filter = filters['level']
                        if isinstance(level_filter, list) and level_filter:
                            placeholders = ','.join(['?' for _ in level_filter])
                            query += f" AND level IN ({placeholders})"
                            params.extend(level_filter)
                        elif isinstance(level_filter, str):
                            query += " AND level = ?"
                            params.append(level_filter)

                    # Handle status filter (can be single value or list)
                    if 'status' in filters:
                        status_filter = filters['status']
                        if isinstance(status_filter, list) and status_filter:
                            placeholders = ','.join(['?' for _ in status_filter])
                            query += f" AND status IN ({placeholders})"
                            params.extend(status_filter)
                        elif isinstance(status_filter, str):
                            query += " AND status = ?"
                            params.append(status_filter)

                    # Handle source_repo filter (can be single value or list)
                    if 'source_repo' in filters:
                        source_filter = filters['source_repo']
                        if isinstance(source_filter, list) and source_filter:
                            placeholders = ','.join(['?' for _ in source_filter])
                            query += f" AND source_repo IN ({placeholders})"
                            params.extend(source_filter)
                        elif isinstance(source_filter, str):
                            query += " AND source_repo = ?"
                            params.append(source_filter)

                    # Handle is_custom filter
                    if 'is_custom' in filters:
                        query += " AND is_custom = ?"
                        params.append(filters['is_custom'])

                    # Handle search_term filter
                    if 'search_term' in filters:
                        query += " AND (title LIKE ? OR description LIKE ? OR tags LIKE ?)"
                        search_term = f"%{filters['search_term']}%"
                        params.extend([search_term, search_term, search_term])

                # Add ordering and pagination
                query += " ORDER BY updated_at DESC"

                if limit:
                    query += " LIMIT ? OFFSET ?"
                    params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting SIGMA rules: {e}")
            return []

    def get_sigma_rules_count(self, filters: Optional[Dict] = None) -> int:
        """Get count of SIGMA rules with optional filters"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT COUNT(*) FROM sigma_rules WHERE 1=1"
                params = []

                if filters:
                    # Apply same filters as get_sigma_rules
                    if 'level' in filters:
                        level_filter = filters['level']
                        if isinstance(level_filter, list) and level_filter:
                            placeholders = ','.join(['?' for _ in level_filter])
                            query += f" AND level IN ({placeholders})"
                            params.extend(level_filter)
                        elif isinstance(level_filter, str):
                            query += " AND level = ?"
                            params.append(level_filter)

                    if 'status' in filters:
                        status_filter = filters['status']
                        if isinstance(status_filter, list) and status_filter:
                            placeholders = ','.join(['?' for _ in status_filter])
                            query += f" AND status IN ({placeholders})"
                            params.extend(status_filter)
                        elif isinstance(status_filter, str):
                            query += " AND status = ?"
                            params.append(status_filter)

                    if 'source_repo' in filters:
                        query += " AND source_repo = ?"
                        params.append(filters['source_repo'])

                    if 'is_custom' in filters:
                        query += " AND is_custom = ?"
                        params.append(filters['is_custom'])

                    if 'search_term' in filters:
                        query += " AND (title LIKE ? OR description LIKE ? OR tags LIKE ?)"
                        search_term = f"%{filters['search_term']}%"
                        params.extend([search_term, search_term, search_term])

                cursor.execute(query, params)
                return cursor.fetchone()[0]

        except Exception as e:
            self.logger.error(f"Error getting SIGMA rules count: {e}")
            return 0

    def get_rules_for_technique(self, technique_id: str, include_parent: bool = True, limit: int = 50) -> List[Dict]:
        """Get SIGMA rules that detect a specific technique - CENTRALIZED METHOD"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Check if this is a sub-technique (contains a dot)
                is_sub_technique = '.' in technique_id
                parent_technique = technique_id.split('.')[0] if is_sub_technique else None

                if is_sub_technique and include_parent and parent_technique:
                    # For sub-techniques, get rules for both the sub-technique and parent technique
                    query = """
                        SELECT DISTINCT sr.rule_id, sr.title, sr.description, sr.level,
                               sr.author, sr.tags, rtm.confidence
                        FROM sigma_rules sr
                        JOIN rule_technique_mappings rtm ON sr.rule_id = rtm.rule_id
                        WHERE rtm.technique_id IN (?, ?)
                        GROUP BY sr.rule_id, sr.title, sr.description
                        ORDER BY MAX(rtm.confidence) DESC, sr.level DESC
                        LIMIT ?
                    """
                    cursor.execute(query, (technique_id, parent_technique, limit))
                else:
                    # For regular techniques or when not including parent
                    query = """
                        SELECT DISTINCT sr.rule_id, sr.title, sr.description, sr.level,
                               sr.author, sr.tags, rtm.confidence
                        FROM sigma_rules sr
                        JOIN rule_technique_mappings rtm ON sr.rule_id = rtm.rule_id
                        WHERE rtm.technique_id = ?
                        GROUP BY sr.rule_id, sr.title, sr.description
                        ORDER BY MAX(rtm.confidence) DESC, sr.level DESC
                        LIMIT ?
                    """
                    cursor.execute(query, (technique_id, limit))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting rules for technique {technique_id}: {e}")
            return []

    def get_coverage_metrics(self) -> Dict[str, Any]:
        """Get overall coverage metrics from database - CENTRALIZED METHOD"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get total SIGMA rules count
                cursor.execute("SELECT COUNT(*) FROM sigma_rules")
                total_rules = cursor.fetchone()[0]

                # Get total MITRE techniques count
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                total_techniques = cursor.fetchone()[0]

                # Get techniques with rule coverage
                cursor.execute("""
                    SELECT COUNT(DISTINCT mt.technique_id)
                    FROM mitre_techniques mt
                    JOIN rule_technique_mappings rtm ON mt.technique_id = rtm.technique_id
                """)
                covered_techniques = cursor.fetchone()[0]

                # Calculate overall coverage percentage
                overall_coverage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0

                # Get techniques without any rules (coverage gaps)
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM mitre_techniques mt
                    LEFT JOIN rule_technique_mappings rtm ON mt.technique_id = rtm.technique_id
                    WHERE rtm.technique_id IS NULL
                """)
                coverage_gaps = cursor.fetchone()[0]

                # Get high-quality mappings (confidence > 0.8)
                cursor.execute("""
                    SELECT COUNT(DISTINCT rtm.technique_id)
                    FROM rule_technique_mappings rtm
                    WHERE rtm.confidence > 0.8
                """)
                high_confidence_mappings = cursor.fetchone()[0]

                # Calculate average rules per technique
                avg_rules_per_technique = (total_rules / covered_techniques) if covered_techniques > 0 else 0

                return {
                    'overall_coverage': round(overall_coverage, 1),
                    'covered_techniques': covered_techniques,
                    'total_rules': total_rules,
                    'total_techniques': total_techniques,
                    'coverage_gaps': coverage_gaps,
                    'high_confidence_mappings': high_confidence_mappings,
                    'high_confidence_percentage': round((high_confidence_mappings / total_techniques * 100), 1) if total_techniques > 0 else 0,
                    'avg_rules_per_technique': round(avg_rules_per_technique, 1)
                }

        except Exception as e:
            self.logger.error(f"Error getting coverage metrics: {e}")
            return {
                'overall_coverage': 0,
                'covered_techniques': 0,
                'total_rules': 0,
                'total_techniques': 0,
                'coverage_gaps': 0,
                'high_confidence_mappings': 0,
                'high_confidence_percentage': 0,
                'avg_rules_per_technique': 0
            }

    def calculate_scenario_coverage(self, techniques: List[str]) -> float:
        """Calculate coverage percentage for a scenario based on its techniques - CENTRALIZED METHOD"""
        try:
            if not techniques:
                return 0.0

            total_rules = 0
            for technique_id in techniques:
                rules = self.get_rules_for_technique(technique_id)
                total_rules += len(rules)

            # Calculate coverage as average rules per technique
            avg_rules_per_technique = total_rules / len(techniques)

            # Convert to percentage (assuming 3+ rules per technique = 100% coverage)
            coverage_percentage = min(100.0, (avg_rules_per_technique / 3.0) * 100.0)
            return round(coverage_percentage, 1)

        except Exception as e:
            self.logger.error(f"Error calculating scenario coverage: {e}")
            return 0.0

    def calculate_path_coverage_score(self, path: List[str], tactic_order: List[str]) -> float:
        """Calculate coverage score for a path - CENTRALIZED METHOD"""
        try:
            total_score = 0
            technique_count = 0

            for step in path:
                if step not in tactic_order:  # It's a technique
                    technique_count += 1
                    # Get rule count for this technique
                    rules = self.get_rules_for_technique(step)
                    rule_count = len(rules)

                    # Score based on rule coverage
                    if rule_count >= 3:
                        total_score += 3
                    elif rule_count >= 1:
                        total_score += 2
                    else:
                        total_score += 0

            return total_score / max(technique_count, 1)

        except Exception as e:
            self.logger.error(f"Error calculating path coverage score: {e}")
            return 0

    def calculate_detailed_coverage_stats(self, matrix_data: Dict) -> Dict:
        """Calculate detailed coverage statistics - CENTRALIZED METHOD"""
        try:
            total_techniques = 0
            high_coverage = 0  # 10+ rules
            medium_coverage = 0  # 1-9 rules
            no_coverage = 0  # 0 rules

            for techniques in matrix_data.values():
                for technique in techniques:
                    total_techniques += 1
                    rule_count = technique.get('rule_count', 0)

                    if rule_count >= 10:
                        high_coverage += 1
                    elif rule_count >= 1:
                        medium_coverage += 1
                    else:
                        no_coverage += 1

            covered_techniques = high_coverage + medium_coverage
            coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0

            return {
                'total_techniques': total_techniques,
                'high_coverage': high_coverage,
                'medium_coverage': medium_coverage,
                'no_coverage': no_coverage,
                'coverage_percentage': coverage_percentage,
                'high_coverage_pct': (high_coverage / total_techniques * 100) if total_techniques > 0 else 0,
                'medium_coverage_pct': (medium_coverage / total_techniques * 100) if total_techniques > 0 else 0,
                'no_coverage_pct': (no_coverage / total_techniques * 100) if total_techniques > 0 else 0
            }

        except Exception as e:
            self.logger.error(f"Error calculating detailed coverage stats: {e}")
            return {}

    def validate_technique_id(self, technique_id: str) -> bool:
        """Validate MITRE ATT&CK technique ID format and existence - CENTRALIZED METHOD"""
        import re

        if not technique_id:
            return False

        # MITRE technique ID pattern: T followed by 4 digits, optionally followed by .001-.999
        pattern = r'^T\d{4}(\.\d{3})?$'

        if not re.match(pattern, technique_id.upper()):
            return False

        # Check if technique exists in database
        technique_info = self.get_mitre_technique_details(technique_id.upper())
        return bool(technique_info and technique_info.get('technique_id'))

    def validate_sigma_rule_syntax(self, rule_content: str) -> Dict[str, Any]:
        """Validate SIGMA rule syntax - CENTRALIZED METHOD"""
        import yaml

        try:
            # Parse YAML
            rule_data = yaml.safe_load(rule_content)

            if not rule_data or not isinstance(rule_data, dict):
                return {
                    'valid': False,
                    'error': 'Invalid YAML structure'
                }

            # Check required fields
            required_fields = ['title', 'detection']
            missing_fields = []

            for field in required_fields:
                if field not in rule_data:
                    missing_fields.append(field)

            if missing_fields:
                return {
                    'valid': False,
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }

            # Validate detection section
            detection = rule_data.get('detection', {})
            if not isinstance(detection, dict):
                return {
                    'valid': False,
                    'error': 'Detection section must be a dictionary'
                }

            # Check for condition field in detection
            if 'condition' not in detection:
                return {
                    'valid': False,
                    'error': 'Detection section must contain a condition field'
                }

            return {
                'valid': True,
                'rule_data': rule_data,
                'warnings': []
            }

        except yaml.YAMLError as e:
            return {
                'valid': False,
                'error': f'YAML parsing error: {str(e)}'
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation error: {str(e)}'
            }
    
    def insert_mitre_technique(self, technique_data: Dict[str, Any]) -> bool:
        """Insert or update a MITRE ATT&CK technique"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Determine framework based on technique ID
                technique_id = technique_data.get('technique_id', '')
                framework = 'ics' if technique_id.startswith('T0') else 'enterprise'

                cursor.execute("""
                    INSERT OR REPLACE INTO mitre_techniques
                    (technique_id, name, description, tactic, platform,
                     data_sources, detection, mitigation, technique_references,
                     permissions_required, sub_techniques, procedure_examples,
                     kill_chain_phases, system_requirements, network_requirements,
                     remote_support, impact_type, effective_permissions, defense_bypassed,
                     framework, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    technique_data.get('technique_id'),
                    technique_data.get('name'),
                    technique_data.get('description'),
                    technique_data.get('tactic'),
                    json.dumps(technique_data.get('platform', [])),
                    json.dumps(technique_data.get('data_sources', [])),
                    technique_data.get('detection'),
                    technique_data.get('mitigation'),
                    json.dumps(technique_data.get('references', [])),
                    json.dumps(technique_data.get('permissions_required', [])),
                    json.dumps(technique_data.get('sub_techniques', [])),
                    json.dumps(technique_data.get('procedure_examples', [])),
                    json.dumps(technique_data.get('kill_chain_phases', [])),
                    json.dumps(technique_data.get('system_requirements', [])),
                    technique_data.get('network_requirements'),
                    technique_data.get('remote_support'),
                    technique_data.get('impact_type'),
                    json.dumps(technique_data.get('effective_permissions', [])),
                    json.dumps(technique_data.get('defense_bypassed', [])),
                    framework,
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error inserting MITRE technique: {e}")
            return False

    def store_rule_technique_mapping(self, rule_id: str, technique_id: str, confidence: float = 1.0) -> bool:
        """Store rule-technique mapping with proper error handling and foreign key validation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # First check if the rule exists
                cursor.execute("SELECT 1 FROM sigma_rules WHERE rule_id = ?", (rule_id,))
                if not cursor.fetchone():
                    self.logger.warning(f"Rule {rule_id} not found in database, skipping mapping")
                    return False

                # Check if the technique exists
                cursor.execute("SELECT 1 FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
                if not cursor.fetchone():
                    # Store in pending mappings table for later processing
                    self._store_pending_mapping(rule_id, technique_id, confidence)
                    return True

                # Both rule and technique exist, create the mapping
                # Use INSERT OR IGNORE to prevent duplicates, then UPDATE if needed
                cursor.execute("""
                    INSERT OR IGNORE INTO rule_technique_mappings
                    (rule_id, technique_id, confidence, created_at, updated_at)
                    VALUES (?, ?, ?, datetime('now'), datetime('now'))
                """, (rule_id, technique_id, confidence))

                # Update if it already exists and confidence is higher
                cursor.execute("""
                    UPDATE rule_technique_mappings
                    SET confidence = ?, updated_at = datetime('now')
                    WHERE rule_id = ? AND technique_id = ? AND confidence < ?
                """, (confidence, rule_id, technique_id, confidence))

                conn.commit()
                return True

        except Exception as e:
            self.logger.error(f"Error storing rule-technique mapping: {e}")
            return False

    def _store_pending_mapping(self, rule_id: str, technique_id: str, confidence: float = 1.0):
        """Store pending rule-technique mapping for later processing"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO pending_rule_mappings
                    (rule_id, technique_id, confidence, created_at)
                    VALUES (?, ?, ?, datetime('now'))
                """, (rule_id, technique_id, confidence))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing pending mapping: {e}")

    def process_pending_mappings(self) -> Dict[str, int]:
        """Process pending rule-technique mappings after MITRE data is loaded"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get all pending mappings
                cursor.execute("""
                    SELECT rule_id, technique_id, confidence
                    FROM pending_rule_mappings
                """)
                pending_mappings = cursor.fetchall()

                processed = 0
                failed = 0

                for rule_id, technique_id, confidence in pending_mappings:
                    # Check if technique now exists
                    cursor.execute("SELECT 1 FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
                    if cursor.fetchone():
                        # Create the mapping
                        cursor.execute("""
                            INSERT OR IGNORE INTO rule_technique_mappings
                            (rule_id, technique_id, confidence, created_at, updated_at)
                            VALUES (?, ?, ?, datetime('now'), datetime('now'))
                        """, (rule_id, technique_id, confidence))

                        # Remove from pending
                        cursor.execute("""
                            DELETE FROM pending_rule_mappings
                            WHERE rule_id = ? AND technique_id = ?
                        """, (rule_id, technique_id))

                        processed += 1
                    else:
                        failed += 1

                conn.commit()

                self.logger.info(f"Processed {processed} pending mappings, {failed} still pending")
                return {'processed': processed, 'failed': failed, 'total': len(pending_mappings)}

        except Exception as e:
            self.logger.error(f"Error processing pending mappings: {e}")
            return {'processed': 0, 'failed': 0, 'total': 0}
    
    def get_mitre_techniques(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Get MITRE ATT&CK techniques with optional filters"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM mitre_techniques WHERE 1=1"
                params = []

                if filters:
                    if 'framework' in filters and filters['framework']:
                        framework_filter = filters['framework']
                        if isinstance(framework_filter, list) and framework_filter:
                            # Handle multiple frameworks
                            placeholders = ','.join(['?' for _ in framework_filter])
                            query += f" AND framework IN ({placeholders})"
                            params.extend(framework_filter)
                        elif isinstance(framework_filter, str):
                            # Handle single framework
                            query += " AND framework = ?"
                            params.append(framework_filter)

                    if 'tactic' in filters and filters['tactic']:
                        tactic_filter = filters['tactic']
                        if isinstance(tactic_filter, list) and tactic_filter:
                            # Handle multiple tactics
                            placeholders = ','.join(['?' for _ in tactic_filter])
                            query += f" AND tactic IN ({placeholders})"
                            params.extend(tactic_filter)
                        elif isinstance(tactic_filter, str):
                            # Handle single tactic
                            query += " AND tactic = ?"
                            params.append(tactic_filter)

                    if 'search_term' in filters and filters['search_term']:
                        query += " AND (name LIKE ? OR description LIKE ? OR technique_id LIKE ?)"
                        search_term = f"%{filters['search_term']}%"
                        params.extend([search_term, search_term, search_term])

                query += " ORDER BY technique_id"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to list of dicts and parse JSON fields
                techniques = []
                for row in rows:
                    technique_data = dict(row)

                    # Parse JSON fields to ensure consistency with get_mitre_technique_details
                    json_fields = [
                        'platform', 'data_sources', 'technique_references',
                        'permissions_required', 'sub_techniques', 'procedure_examples',
                        'kill_chain_phases', 'system_requirements', 'effective_permissions',
                        'defense_bypassed'
                    ]

                    for field in json_fields:
                        if technique_data.get(field):
                            try:
                                technique_data[field] = json.loads(technique_data[field])
                            except (json.JSONDecodeError, TypeError):
                                technique_data[field] = []
                        else:
                            technique_data[field] = []

                    techniques.append(technique_data)

                # Apply platform and data source filters (JSON fields are now parsed)
                if filters:
                    if 'platforms' in filters and filters['platforms']:
                        filtered_techniques = []
                        for technique in techniques:
                            technique_platforms = technique.get('platform', [])
                            if isinstance(technique_platforms, list):
                                # Check if any of the selected platforms match the technique's platforms
                                if any(platform in technique_platforms for platform in filters['platforms']):
                                    filtered_techniques.append(technique)
                            elif isinstance(technique_platforms, str):
                                # Handle single platform string
                                if technique_platforms in filters['platforms']:
                                    filtered_techniques.append(technique)
                        techniques = filtered_techniques

                    if 'data_sources' in filters and filters['data_sources']:
                        filtered_techniques = []
                        for technique in techniques:
                            technique_data_sources = technique.get('data_sources', [])
                            if isinstance(technique_data_sources, list):
                                # Check if any of the selected data sources match the technique's data sources
                                if any(ds in technique_data_sources for ds in filters['data_sources']):
                                    filtered_techniques.append(technique)
                            elif isinstance(technique_data_sources, str):
                                # Handle single data source string
                                if technique_data_sources in filters['data_sources']:
                                    filtered_techniques.append(technique)
                        techniques = filtered_techniques

                return techniques

        except Exception as e:
            self.logger.error(f"Error getting MITRE techniques: {e}")
            return []

    def get_mitre_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get complete details for a specific MITRE ATT&CK technique - CENTRALIZED METHOD"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT * FROM mitre_techniques
                    WHERE technique_id = ?
                """, (technique_id,))

                row = cursor.fetchone()
                if row:
                    # Convert row to dictionary
                    columns = [description[0] for description in cursor.description]
                    technique_data = dict(zip(columns, row))

                    # Parse JSON fields
                    json_fields = [
                        'platform', 'data_sources', 'technique_references',
                        'permissions_required', 'sub_techniques', 'procedure_examples',
                        'kill_chain_phases', 'system_requirements', 'effective_permissions',
                        'defense_bypassed'
                    ]

                    for field in json_fields:
                        if technique_data.get(field):
                            try:
                                technique_data[field] = json.loads(technique_data[field])
                            except (json.JSONDecodeError, TypeError):
                                technique_data[field] = []
                        else:
                            technique_data[field] = []

                    return technique_data

                # If not found, return fallback data structure
                return {
                    'technique_id': technique_id,
                    'name': technique_id,
                    'description': 'No description available',
                    'tactic': 'Unknown',
                    'platform': [],
                    'data_sources': [],
                    'detection': '',
                    'mitigation': '',
                    'technique_references': [],
                    'permissions_required': [],
                    'sub_techniques': [],
                    'procedure_examples': [],
                    'kill_chain_phases': [],
                    'system_requirements': [],
                    'effective_permissions': [],
                    'defense_bypassed': []
                }

        except Exception as e:
            self.logger.error(f"Error getting technique details for {technique_id}: {e}")
            # Return fallback data structure on error
            return {
                'technique_id': technique_id,
                'name': technique_id,
                'description': 'Error loading description',
                'tactic': 'Unknown',
                'platform': [],
                'data_sources': [],
                'detection': '',
                'mitigation': '',
                'technique_references': [],
                'permissions_required': [],
                'sub_techniques': [],
                'procedure_examples': [],
                'kill_chain_phases': [],
                'system_requirements': [],
                'effective_permissions': [],
                'defense_bypassed': []
            }
    
    def log_activity(self, action: str, details: Optional[str] = None):
        """Log user activity"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO activity_log (action, details)
                    VALUES (?, ?)
                """, (action, details))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error logging activity: {e}")
    
    def get_quick_stats(self) -> Dict[str, int]:
        """Get quick statistics for dashboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Count SIGMA rules
                cursor.execute("SELECT COUNT(*) FROM sigma_rules")
                stats['sigma_rules'] = cursor.fetchone()[0]
                
                # Count MITRE techniques
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                stats['mitre_techniques'] = cursor.fetchone()[0]
                
                # Count custom rules
                cursor.execute("SELECT COUNT(*) FROM sigma_rules WHERE is_custom = 1")
                stats['custom_rules'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting quick stats: {e}")
            return {}


    
    def get_detailed_stats(self) -> Dict[str, Any]:
        """Get enhanced detailed statistics for dashboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                stats = self.get_quick_stats()

                # Enhanced MITRE data metrics
                cursor.execute("""
                    SELECT COUNT(*) FROM mitre_techniques
                    WHERE detection IS NOT NULL AND detection != ''
                """)
                stats['techniques_with_detection'] = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT COUNT(*) FROM mitre_techniques
                    WHERE mitigation IS NOT NULL AND mitigation != ''
                """)
                stats['techniques_with_mitigation'] = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT COUNT(*) FROM mitre_techniques
                    WHERE (detection IS NOT NULL AND detection != '')
                    AND (mitigation IS NOT NULL AND mitigation != '')
                """)
                stats['techniques_with_complete_data'] = cursor.fetchone()[0]

                # Enhanced coverage metrics
                cursor.execute("""
                    SELECT COUNT(DISTINCT rtm.technique_id)
                    FROM rule_technique_mappings rtm
                    WHERE rtm.confidence >= 1.0
                """)
                stats['high_confidence_mappings'] = cursor.fetchone()[0]

                # Calculate enhanced percentages
                total_techniques = stats.get('mitre_techniques', 0)
                if total_techniques > 0:
                    stats['detection_data_percentage'] = (stats['techniques_with_detection'] / total_techniques * 100)
                    stats['mitigation_data_percentage'] = (stats['techniques_with_mitigation'] / total_techniques * 100)
                    stats['complete_data_percentage'] = (stats['techniques_with_complete_data'] / total_techniques * 100)
                else:
                    stats['detection_data_percentage'] = 0
                    stats['mitigation_data_percentage'] = 0
                    stats['complete_data_percentage'] = 0

                # Get new rules this week
                week_ago = (datetime.now() - timedelta(days=7)).isoformat()
                cursor.execute("SELECT COUNT(*) FROM sigma_rules WHERE created_at > ?", (week_ago,))
                stats['new_rules_this_week'] = cursor.fetchone()[0]

                # Get last sync time
                cursor.execute("SELECT sync_timestamp FROM sync_history ORDER BY sync_timestamp DESC LIMIT 1")
                last_sync = cursor.fetchone()
                stats['last_sync'] = last_sync[0] if last_sync else 'Never'

                return stats

        except Exception as e:
            self.logger.error(f"Error getting detailed stats: {e}")
            return {}

    # Custom Scenarios CRUD Operations
    def insert_custom_scenario(self, scenario_data: Dict[str, Any]) -> bool:
        """Insert a custom attack scenario"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT OR REPLACE INTO custom_scenarios
                    (scenario_id, name, description, category, tactics, techniques,
                     platforms, author, tags, is_public, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scenario_data.get('scenario_id'),
                    scenario_data.get('name'),
                    scenario_data.get('description'),
                    scenario_data.get('category'),
                    json.dumps(scenario_data.get('tactics', [])),
                    json.dumps(scenario_data.get('techniques', [])),
                    json.dumps(scenario_data.get('platforms', [])),
                    scenario_data.get('author'),
                    json.dumps(scenario_data.get('tags', [])),
                    scenario_data.get('is_public', False),
                    datetime.now().isoformat()
                ))

                conn.commit()
                return True

        except Exception as e:
            self.logger.error(f"Error inserting custom scenario: {e}")
            return False

    def get_custom_scenarios(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Get custom scenarios with optional filters"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM custom_scenarios WHERE 1=1"
                params = []

                if filters:
                    if 'category' in filters:
                        query += " AND category = ?"
                        params.append(filters['category'])

                    if 'author' in filters:
                        query += " AND author = ?"
                        params.append(filters['author'])

                    if 'is_public' in filters:
                        query += " AND is_public = ?"
                        params.append(filters['is_public'])

                query += " ORDER BY updated_at DESC"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                scenarios = []
                for row in rows:
                    scenario = dict(row)
                    # Parse JSON fields with type checking
                    json_fields = ['tactics', 'techniques', 'platforms', 'tags']
                    for field in json_fields:
                        field_data = scenario.get(field, '[]')
                        if isinstance(field_data, str):
                            try:
                                scenario[field] = json.loads(field_data) if field_data else []
                            except (json.JSONDecodeError, TypeError):
                                scenario[field] = []
                        elif isinstance(field_data, list):
                            scenario[field] = field_data
                        else:
                            scenario[field] = []
                    scenarios.append(scenario)

                return scenarios

        except Exception as e:
            self.logger.error(f"Error getting custom scenarios: {e}")
            return []

    def get_custom_scenario_by_id(self, scenario_id: str) -> Optional[Dict]:
        """Get a specific custom scenario by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT * FROM custom_scenarios WHERE scenario_id = ?", (scenario_id,))
                row = cursor.fetchone()

                if row:
                    scenario = dict(row)
                    # Parse JSON fields with type checking
                    json_fields = ['tactics', 'techniques', 'platforms', 'tags']
                    for field in json_fields:
                        field_data = scenario.get(field, '[]')
                        if isinstance(field_data, str):
                            try:
                                scenario[field] = json.loads(field_data) if field_data else []
                            except (json.JSONDecodeError, TypeError):
                                scenario[field] = []
                        elif isinstance(field_data, list):
                            scenario[field] = field_data
                        else:
                            scenario[field] = []
                    return scenario

                return None

        except Exception as e:
            self.logger.error(f"Error getting custom scenario {scenario_id}: {e}")
            return None

    def update_custom_scenario(self, scenario_id: str, scenario_data: Dict[str, Any]) -> bool:
        """Update an existing custom scenario"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE custom_scenarios
                    SET name = ?, description = ?, category = ?, tactics = ?,
                        techniques = ?, platforms = ?, author = ?, tags = ?,
                        is_public = ?, updated_at = ?
                    WHERE scenario_id = ?
                """, (
                    scenario_data.get('name'),
                    scenario_data.get('description'),
                    scenario_data.get('category'),
                    json.dumps(scenario_data.get('tactics', [])),
                    json.dumps(scenario_data.get('techniques', [])),
                    json.dumps(scenario_data.get('platforms', [])),
                    scenario_data.get('author'),
                    json.dumps(scenario_data.get('tags', [])),
                    scenario_data.get('is_public', False),
                    datetime.now().isoformat(),
                    scenario_id
                ))

                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            self.logger.error(f"Error updating custom scenario {scenario_id}: {e}")
            return False

    def delete_custom_scenario(self, scenario_id: str) -> bool:
        """Delete a custom scenario"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("DELETE FROM custom_scenarios WHERE scenario_id = ?", (scenario_id,))
                conn.commit()

                return cursor.rowcount > 0

        except Exception as e:
            self.logger.error(f"Error deleting custom scenario {scenario_id}: {e}")
            return False
    
    def get_recent_activity(self, limit: int = 10) -> List[Dict]:
        """Get recent activity log entries"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT action, details, timestamp 
                    FROM activity_log 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error getting recent activity: {e}")
            return []
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information"""
        try:
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()

                return {
                    'size': f"{db_size / 1024 / 1024:.2f} MB",
                    'tables': len(tables),
                    'last_backup': 'Not implemented'
                }

        except Exception as e:
            self.logger.error(f"Error getting database info: {e}")
            return {}

    def create_backup(self) -> Dict[str, Any]:
        """Create a backup of the database"""
        try:
            import shutil
            from datetime import datetime

            # Create backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"sigma_platform_backup_{timestamp}.db"

            # Convert db_path to Path object if it's a string
            from pathlib import Path
            db_path = Path(self.db_path)
            backup_dir = db_path.parent / "backups"
            backup_path = backup_dir / backup_filename

            # Ensure backup directory exists
            backup_dir.mkdir(exist_ok=True)

            # Copy database file
            shutil.copy2(str(db_path), str(backup_path))

            self.logger.info(f"Database backup created: {backup_filename}")
            return {
                'success': True,
                'filename': backup_filename,
                'path': str(backup_path)
            }

        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
