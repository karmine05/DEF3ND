"""
Detection Search Engine Component
Provides advanced search capabilities for SIGMA rules with semantic and keyword search
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import re
from typing import Dict, List, Optional, Any, Tuple
import logging
import pickle
import os
from functools import lru_cache
import time

from difflib import SequenceMatcher

class SearchEngine:
    """Advanced search engine for SIGMA detection rules"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize sentence transformer for semantic search
        self.embedding_model = None
        self.embeddings_cache = {}
        self._load_embedding_model()
        
        # Search filters and options
        self.search_filters = {
            'level': ['low', 'medium', 'high', 'critical'],
            'status': ['experimental', 'test', 'stable'],
            'source': ['SigmaHQ Main Rules', 'SigmaHQ Threat Hunting Rules', 'SigmaHQ Emerging Threats', 'Custom Rules'],
            'tags': []  # Will be populated dynamically
        }
        
        # Search history and caching
        if 'search_history' not in st.session_state:
            st.session_state.search_history = []

        # Initialize pagination state
        if 'search_page' not in st.session_state:
            st.session_state.search_page = 0

        # Cache for search results
        self.results_cache = {}
        self.cache_ttl = 300  # 5 minutes

    @lru_cache(maxsize=100)
    def _cached_search(self, query: str, filters_hash: str) -> List[Dict]:
        """Cached search method to improve performance"""
        cache_key = f"{query}_{filters_hash}"
        current_time = time.time()

        # Check if result is in cache and not expired
        if cache_key in self.results_cache:
            cached_result, timestamp = self.results_cache[cache_key]
            if current_time - timestamp < self.cache_ttl:
                return cached_result

        # Perform actual search (will be implemented in specific search methods)
        return []
    
    def render(self):
        """Render the search engine interface"""
        st.markdown('<h2 class="sub-header">🔍 Detection Search Engine</h2>', unsafe_allow_html=True)

        # Check if we should show rule details modal
        if 'viewing_rule_details' in st.session_state and st.session_state.viewing_rule_details:
            self._render_rule_details_modal()
            return

        # Search interface
        self._render_search_interface()

        # Search results
        if 'search_results' in st.session_state and st.session_state.search_results:
            self._render_search_results()
        elif 'search_results' in st.session_state:
            st.info("🔍 No results found. Try adjusting your search criteria.")

        # Search history and saved searches
        with st.sidebar:
            self._render_search_sidebar()
    
    def _render_search_interface(self):
        """Render the main search interface"""
        st.markdown("### 🔍 Search Detection Rules")
        
        # Search tabs
        tab1, tab2, tab3, tab4 = st.tabs(["🔤 Text Search", "🧠 Semantic Search", "🎯 MITRE Search", "🔧 Advanced Search"])

        with tab1:
            self._render_text_search()

        with tab2:
            self._render_semantic_search()

        with tab3:
            self._render_mitre_search()

        with tab4:
            self._render_advanced_search()
    
    def _render_text_search(self):
        """Render text-based search interface"""
        st.markdown("#### 🔤 Keyword & Text Search")
        
        with st.form("text_search_form"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                search_query = st.text_input(
                    "Search Query",
                    placeholder="Enter keywords, technique IDs, or rule names...",
                    help="Search in rule titles, descriptions, tags, and content"
                )
            
            with col2:
                search_type = st.selectbox(
                    "Search Type",
                    ["All Fields", "Title Only", "Description", "Tags", "Content"]
                )
            
            # Quick filters
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                level_filter = st.multiselect("Severity", self.search_filters['level'])
            
            with col2:
                status_filter = st.multiselect("Status", self.search_filters['status'])
            
            with col3:
                source_filter = st.multiselect("Source", self.search_filters['source'])
            
            with col4:
                custom_only = st.checkbox("Custom Rules Only")
            
            # Search options
            with st.expander("🔧 Search Options"):
                col1, col2 = st.columns(2)
                
                with col1:
                    case_sensitive = st.checkbox("Case Sensitive")
                    regex_search = st.checkbox("Regular Expression")
                
                with col2:
                    exact_match = st.checkbox("Exact Match")
                    include_content = st.checkbox("Search in Rule Content", value=True)
            
            submitted = st.form_submit_button("🔍 Search", type="primary")
            
            if submitted and search_query:
                with st.spinner("Searching detection rules..."):
                    results = self._perform_text_search(
                        search_query, search_type, level_filter, status_filter,
                        source_filter, custom_only, case_sensitive, regex_search,
                        exact_match, include_content
                    )
                    
                    st.session_state.search_results = results
                    st.session_state.search_query = search_query
                    st.session_state.search_type = "text"
                    
                    # Add to search history
                    self._add_to_search_history(search_query, "text", len(results))
                    
                    st.rerun()

    def _render_mitre_search(self):
        """Render MITRE ATT&CK technique search interface"""
        st.markdown("#### 🎯 MITRE ATT&CK Technique Search")
        st.info("💡 Search MITRE ATT&CK techniques with enhanced detection and mitigation information")

        with st.form("mitre_search_form"):
            col1, col2 = st.columns([3, 1])

            with col1:
                search_query = st.text_input(
                    "Search MITRE Techniques",
                    placeholder="Enter technique ID (T1055), name, or keywords...",
                    help="Search in technique names, descriptions, detection methods, and mitigation strategies"
                )

            with col2:
                search_scope = st.selectbox(
                    "Search Scope",
                    ["All Fields", "Technique ID", "Name", "Description", "Detection", "Mitigation"]
                )

            # MITRE-specific filters
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                framework_filter = st.multiselect("Framework", ["Enterprise", "ICS"], default=["Enterprise", "ICS"])

            with col2:
                tactic_filter = st.multiselect("Tactic", self._get_available_tactics())

            with col3:
                platform_filter = st.multiselect("Platform", self._get_available_platforms())

            with col4:
                has_detection = st.checkbox("Has Detection Info")
                has_mitigation = st.checkbox("Has Mitigation Info")

            submitted = st.form_submit_button("🎯 Search MITRE Techniques", type="primary")

            if submitted and search_query:
                with st.spinner("Searching MITRE ATT&CK techniques..."):
                    results = self._perform_mitre_search(
                        search_query, search_scope, framework_filter, tactic_filter,
                        platform_filter, has_detection, has_mitigation
                    )

                    st.session_state.search_results = results
                    st.session_state.search_query = search_query
                    st.session_state.search_type = "mitre"

                    # Add to search history
                    self._add_to_search_history(search_query, "mitre", len(results))

                    st.rerun()

    def _render_semantic_search(self):
        """Render semantic search interface"""
        st.markdown("#### 🧠 Semantic Search")

        st.info("💡 Using intelligent text similarity matching for semantic search")

        with st.form("semantic_search_form"):
            search_description = st.text_area(
                "Describe what you're looking for",
                placeholder="Describe the detection scenario you're looking for...",
                height=100,
                help="Describe the detection scenario in natural language"
            )

            col1, col2 = st.columns(2)

            with col1:
                similarity_threshold = st.slider(
                    "Similarity Threshold",
                    min_value=0.1,
                    max_value=1.0,
                    value=0.6,
                    step=0.05,
                    help="Higher values return more similar results"
                )

            with col2:
                max_results = st.number_input(
                    "Max Results",
                    min_value=5,
                    max_value=100,
                    value=20,
                    step=5
                )

            # Filters
            col1, col2, col3 = st.columns(3)

            with col1:
                level_filter = st.multiselect("Severity", self.search_filters['level'])

            with col2:
                source_filter = st.multiselect("Source", self.search_filters['source'])

            with col3:
                custom_only = st.checkbox("Custom Rules Only")

            # Additional options
            include_mitre = st.checkbox("Include MITRE Techniques", value=True,
                                      help="Include MITRE ATT&CK techniques in semantic search results")

            submitted = st.form_submit_button("🧠 Semantic Search", type="primary")

            if submitted and search_description:
                with st.spinner("Performing semantic search..."):
                    try:
                        # Debug logging
                        self.logger.info(f"Semantic search query: '{search_description}' with threshold {similarity_threshold}")

                        results = self._perform_semantic_search(
                            search_description, similarity_threshold, max_results,
                            level_filter, source_filter, custom_only, include_mitre
                        )

                        self.logger.info(f"Semantic search returned {len(results)} results")

                        # Clear any existing search results first
                        if 'search_results' in st.session_state:
                            del st.session_state.search_results

                        # Set new results
                        st.session_state.search_results = results
                        st.session_state.search_query = search_description
                        st.session_state.search_type = "semantic"

                        # Add to search history
                        self._add_to_search_history(search_description, "semantic", len(results))

                        # Show immediate feedback
                        if results:
                            st.success(f"✅ Found {len(results)} matching rules!")
                        else:
                            st.warning("⚠️ No results found. Try lowering the similarity threshold or using different keywords.")

                        st.rerun()

                    except Exception as e:
                        self.logger.error(f"Error in semantic search: {e}")
                        st.error(f"❌ Search failed: {str(e)}")

            elif submitted and not search_description:
                st.warning("⚠️ Please enter a search description.")
    
    def _render_advanced_search(self):
        """Render advanced search interface"""
        st.markdown("#### 🔧 Advanced Search")
        
        with st.form("advanced_search_form"):
            # Multiple search criteria
            st.markdown("**Search Criteria**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                title_contains = st.text_input("Title contains")
                description_contains = st.text_input("Description contains")
                author_contains = st.text_input("Author contains")
            
            with col2:
                tags_include = st.text_input("Must include tags (comma-separated)")
                tags_exclude = st.text_input("Must exclude tags (comma-separated)")
                technique_id = st.text_input("MITRE Technique ID")
            
            # Date range
            st.markdown("**Date Range**")
            col1, col2 = st.columns(2)
            
            with col1:
                date_from = st.date_input("From Date", value=None)
            
            with col2:
                date_to = st.date_input("To Date", value=None)
            
            # Advanced filters
            st.markdown("**Advanced Filters**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                level_filter = st.multiselect("Severity Levels", self.search_filters['level'])
                status_filter = st.multiselect("Status", self.search_filters['status'])
            
            with col2:
                source_filter = st.multiselect("Sources", self.search_filters['source'])
                has_references = st.checkbox("Has References")
            
            with col3:
                custom_only = st.checkbox("Custom Rules Only")
                has_false_positives = st.checkbox("Has False Positives Listed")
            
            # Detection logic search
            with st.expander("🔍 Detection Logic Search"):
                detection_field = st.text_input("Detection field contains")
                condition_contains = st.text_input("Condition contains")
                logsource_product = st.text_input("Log source product")
                logsource_service = st.text_input("Log source service")
            
            submitted = st.form_submit_button("🔍 Advanced Search", type="primary")
            
            if submitted:
                with st.spinner("Performing advanced search..."):
                    search_criteria = {
                        'title_contains': title_contains,
                        'description_contains': description_contains,
                        'author_contains': author_contains,
                        'tags_include': tags_include,
                        'tags_exclude': tags_exclude,
                        'technique_id': technique_id,
                        'date_from': date_from,
                        'date_to': date_to,
                        'level_filter': level_filter,
                        'status_filter': status_filter,
                        'source_filter': source_filter,
                        'custom_only': custom_only,
                        'has_references': has_references,
                        'has_false_positives': has_false_positives,
                        'detection_field': detection_field,
                        'condition_contains': condition_contains,
                        'logsource_product': logsource_product,
                        'logsource_service': logsource_service
                    }
                    
                    results = self._perform_advanced_search(search_criteria)
                    
                    st.session_state.search_results = results
                    st.session_state.search_query = "Advanced Search"
                    st.session_state.search_type = "advanced"
                    
                    # Add to search history
                    self._add_to_search_history("Advanced Search", "advanced", len(results))
                    
                    st.rerun()
    
    def _render_search_results(self):
        """Render search results"""
        results = st.session_state.search_results
        query = st.session_state.get('search_query', '')
        search_type = st.session_state.get('search_type', 'text')
        
        st.markdown("---")
        st.markdown(f"### 📊 Search Results ({len(results)} found)")
        
        if not results:
            st.info("No rules found matching your search criteria.")
            return
        
        # Results controls
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            sort_by = st.selectbox(
                "Sort by",
                ["Relevance", "Title", "Date", "Level", "Author"],
                key="sort_results"
            )
        
        with col2:
            sort_order = st.selectbox("Order", ["Descending", "Ascending"], key="sort_order")
        
        with col3:
            results_per_page = st.selectbox("Results per page", [10, 20, 50, 100], index=1)
        
        with col4:
            if st.button("📥 Export Results"):
                self._export_search_results(results)
        
        # Sort results
        sorted_results = self._sort_results(results, sort_by, sort_order)
        
        # Pagination
        total_pages = (len(sorted_results) - 1) // results_per_page + 1
        
        if total_pages > 1:
            page = st.selectbox("Page", range(1, total_pages + 1)) - 1
        else:
            page = 0
        
        start_idx = page * results_per_page
        end_idx = start_idx + results_per_page
        page_results = sorted_results[start_idx:end_idx]
        
        # Display results
        for i, result in enumerate(page_results):
            if search_type == "mitre" or result.get('result_type') == 'mitre_technique':
                self._render_technique_card(result, start_idx + i + 1)
            else:
                self._render_rule_card(result, start_idx + i + 1, search_type)
    
    def _render_rule_card(self, rule: Dict, index: int, search_type: str):
        """Render individual rule card"""
        with st.expander(f"**{index}.** {rule.get('title', 'Untitled Rule')} ({rule.get('rule_id', 'No ID')})"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Rule metadata
                st.markdown(f"**Description:** {rule.get('description', 'No description')[:200]}...")
                
                # Tags
                if rule.get('tags'):
                    tags = json.loads(rule['tags']) if isinstance(rule['tags'], str) else rule['tags']
                    tag_display = " ".join([f"`{tag}`" for tag in tags[:5]])
                    if len(tags) > 5:
                        tag_display += f" +{len(tags) - 5} more"
                    st.markdown(f"**Tags:** {tag_display}")
                
                # Additional metadata
                col_meta1, col_meta2, col_meta3 = st.columns(3)
                
                with col_meta1:
                    st.write(f"**Level:** {rule.get('level', 'Unknown')}")
                    st.write(f"**Status:** {rule.get('status', 'Unknown')}")
                
                with col_meta2:
                    st.write(f"**Author:** {rule.get('author', 'Unknown')}")
                    st.write(f"**Date:** {rule.get('date', 'Unknown')}")
                
                with col_meta3:
                    st.write(f"**Source:** {rule.get('source_repo', 'Unknown')}")
                    if rule.get('is_custom'):
                        st.write("🏷️ **Custom Rule**")
            
            with col2:
                # Actions
                if st.button(f"👁️ View", key=f"view_{rule.get('rule_id')}"):
                    self._show_rule_details(rule)
                
                if st.button(f"✏️ Edit", key=f"edit_{rule.get('rule_id')}"):
                    # Set the rule to edit in session state
                    st.session_state.edit_rule_data = rule
                    st.session_state.current_page = "📝 SIGMA Rule Builder"
                    st.success(f"✅ Rule '{rule.get('title', 'Unknown')}' loaded for editing. Navigate to SIGMA Rule Builder.")
                    st.info("💡 Go to the 'SIGMA Rule Builder' page in the sidebar to edit this rule.")
                
                if st.button(f"📋 Copy", key=f"copy_{rule.get('rule_id')}"):
                    # Store in session state for potential use and show instructions
                    st.session_state.clipboard = rule.get('rule_content', '')
                    st.info("💡 Click 'View' to see the full YAML content with copy functionality!")
                    st.success("Rule content prepared for copying!")
                
                # Similarity score for semantic search
                if search_type == "semantic" and 'similarity_score' in rule:
                    st.metric("Similarity", f"{rule['similarity_score']:.2f}")

    def _render_technique_card(self, technique: Dict, index: int):
        """Render individual MITRE technique card"""
        technique_id = technique.get('technique_id', 'Unknown')
        name = technique.get('name', 'Unknown')
        tactic = technique.get('tactic', 'Unknown')

        with st.expander(f"**{index}.** {technique_id} - {name}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                # Basic information
                st.markdown(f"**Tactic:** {tactic}")

                # Description (truncated)
                description = technique.get('description', 'No description available')
                if len(description) > 300:
                    st.markdown(f"**Description:** {description[:300]}...")
                else:
                    st.markdown(f"**Description:** {description}")

                # Platforms
                platforms = technique.get('platform', [])
                if isinstance(platforms, str):
                    try:
                        platforms = json.loads(platforms)
                    except:
                        platforms = []

                if platforms:
                    st.markdown(f"**Platforms:** {', '.join(platforms[:5])}")

                # Data Sources
                data_sources = technique.get('data_sources', [])
                if isinstance(data_sources, str):
                    try:
                        data_sources = json.loads(data_sources)
                    except:
                        data_sources = []

                if data_sources:
                    st.markdown(f"**Data Sources:** {', '.join(data_sources[:3])}")

            with col2:
                # Detection info indicator
                has_detection = bool(technique.get('detection'))
                has_mitigation = bool(technique.get('mitigation'))

                if has_detection:
                    st.success("🔍 Detection Info Available")
                else:
                    st.warning("⚠️ No Detection Info")

                if has_mitigation:
                    st.success("🛡️ Mitigation Info Available")
                else:
                    st.warning("⚠️ No Mitigation Info")

                # Get related SIGMA rules
                related_rules = self._get_related_sigma_rules(technique_id)
                st.metric("Related SIGMA Rules", len(related_rules))

                # View details button
                if st.button(f"📋 View Complete Details", key=f"view_technique_{technique_id}_{index}"):
                    st.session_state.viewing_technique_detail = technique_id
                    st.rerun()

            # Show detection preview if available
            if has_detection:
                st.markdown("**🔍 Detection Preview:**")
                detection_text = technique.get('detection', '')
                if len(detection_text) > 200:
                    st.markdown(f"> {detection_text[:200]}...")
                    if st.button("Show Full Detection", key=f"show_detection_{technique_id}_{index}"):
                        st.markdown(f"> {detection_text}")
                else:
                    st.markdown(f"> {detection_text}")

            # Show mitigation preview if available
            if has_mitigation:
                st.markdown("**🛡️ Mitigation Preview:**")
                mitigation_text = technique.get('mitigation', '')
                if len(mitigation_text) > 200:
                    st.markdown(f"> {mitigation_text[:200]}...")
                    if st.button("Show Full Mitigation", key=f"show_mitigation_{technique_id}_{index}"):
                        st.markdown(f"> {mitigation_text}")
                else:
                    st.markdown(f"> {mitigation_text}")

    def _get_related_sigma_rules(self, technique_id: str) -> List[Dict]:
        """Get SIGMA rules related to a MITRE technique - USES CENTRALIZED METHOD"""
        try:
            return self.db_manager.get_rules_for_technique(technique_id)

        except Exception as e:
            self.logger.error(f"Error getting related SIGMA rules: {e}")
            return []

    def _perform_text_search(self, query: str, search_type: str, level_filter: List[str],
                           status_filter: List[str], source_filter: List[str], custom_only: bool,
                           case_sensitive: bool, regex_search: bool, exact_match: bool,
                           include_content: bool) -> List[Dict]:
        """Perform text-based search"""
        try:
            # Build search filters
            filters = {}
            
            if level_filter:
                filters['level'] = level_filter
            
            if status_filter:
                filters['status'] = status_filter
            
            if source_filter:
                filters['source_repo'] = source_filter
            
            if custom_only:
                filters['is_custom'] = True
            
            # Get rules from database
            all_rules = self.db_manager.get_sigma_rules(filters)
            
            if not all_rules:
                return []
            
            # Apply text search
            matching_rules = []
            
            for rule in all_rules:
                if self._rule_matches_text_query(
                    rule, query, search_type, case_sensitive, regex_search, exact_match, include_content
                ):
                    matching_rules.append(rule)
            
            return matching_rules
            
        except Exception as e:
            self.logger.error(f"Error in text search: {e}")
            st.error(f"Search error: {str(e)}")
            return []

    def _perform_mitre_search(self, query: str, search_scope: str, framework_filter: List[str],
                             tactic_filter: List[str], platform_filter: List[str],
                             has_detection: bool, has_mitigation: bool) -> List[Dict]:
        """Perform MITRE ATT&CK technique search"""
        try:
            # Build search filters
            filters = {}

            if tactic_filter:
                filters['tactic'] = tactic_filter

            if platform_filter:
                filters['platforms'] = platform_filter

            # Add search term for database-level filtering
            if query and search_scope in ["All Fields", "Technique ID", "Name", "Description"]:
                filters['search_term'] = query

            # Get techniques from database
            all_techniques = self.db_manager.get_mitre_techniques(filters)

            if not all_techniques:
                return []

            # Apply additional filters
            filtered_techniques = []

            for technique in all_techniques:
                # Framework filter (based on technique ID pattern)
                technique_id = technique.get('technique_id', '')
                if framework_filter:
                    is_enterprise = technique_id.startswith('T') and not technique_id.startswith('T0')
                    is_ics = technique_id.startswith('T0')

                    if "Enterprise" in framework_filter and is_enterprise:
                        pass  # Include
                    elif "ICS" in framework_filter and is_ics:
                        pass  # Include
                    else:
                        continue  # Skip

                # Platform filter
                if platform_filter:
                    technique_platforms = technique.get('platform', [])
                    if isinstance(technique_platforms, str):
                        try:
                            technique_platforms = json.loads(technique_platforms)
                        except:
                            technique_platforms = []

                    if not any(platform in technique_platforms for platform in platform_filter):
                        continue

                # Detection/Mitigation filters
                if has_detection and not technique.get('detection'):
                    continue

                if has_mitigation and not technique.get('mitigation'):
                    continue

                # Apply text search
                if self._technique_matches_query(technique, query, search_scope):
                    filtered_techniques.append(technique)

            return filtered_techniques

        except Exception as e:
            self.logger.error(f"Error in MITRE search: {e}")
            st.error(f"MITRE search error: {str(e)}")
            return []

    def _technique_matches_query(self, technique: Dict, query: str, search_scope: str) -> bool:
        """Check if technique matches search query"""
        try:
            search_query = query.lower()

            # Get search fields based on scope
            search_fields = []

            if search_scope == "All Fields":
                search_fields = ['technique_id', 'name', 'description', 'detection', 'mitigation']
            elif search_scope == "Technique ID":
                search_fields = ['technique_id']
            elif search_scope == "Name":
                search_fields = ['name']
            elif search_scope == "Description":
                search_fields = ['description']
            elif search_scope == "Detection":
                search_fields = ['detection']
            elif search_scope == "Mitigation":
                search_fields = ['mitigation']

            # Search in specified fields
            for field in search_fields:
                field_value = technique.get(field, '')

                if not field_value:
                    continue

                field_text = str(field_value).lower()

                if search_query in field_text:
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Error matching technique to query: {e}")
            return False

    def _get_available_tactics(self) -> List[str]:
        """Get available tactics from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT tactic FROM mitre_techniques WHERE tactic IS NOT NULL")
                tactics = [row[0] for row in cursor.fetchall()]
                return sorted(tactics)
        except Exception as e:
            self.logger.error(f"Error getting tactics: {e}")
            return []

    def _get_available_platforms(self) -> List[str]:
        """Get available platforms from database"""
        try:
            platforms = set()
            techniques = self.db_manager.get_mitre_techniques()

            for technique in techniques:
                technique_platforms = technique.get('platform', [])
                if isinstance(technique_platforms, str):
                    try:
                        technique_platforms = json.loads(technique_platforms)
                    except:
                        continue

                if isinstance(technique_platforms, list):
                    platforms.update(technique_platforms)

            return sorted(list(platforms))
        except Exception as e:
            self.logger.error(f"Error getting platforms: {e}")
            return []
    
    def _rule_matches_text_query(self, rule: Dict, query: str, search_type: str,
                                case_sensitive: bool, regex_search: bool, exact_match: bool,
                                include_content: bool) -> bool:
        """Check if rule matches text query"""
        try:
            # Prepare query
            search_query = query if case_sensitive else query.lower()
            
            # Get search fields based on search type
            search_fields = []
            
            if search_type == "All Fields":
                search_fields = ['title', 'description', 'tags', 'author']
                if include_content:
                    search_fields.append('rule_content')
            elif search_type == "Title Only":
                search_fields = ['title']
            elif search_type == "Description":
                search_fields = ['description']
            elif search_type == "Tags":
                search_fields = ['tags']
            elif search_type == "Content":
                search_fields = ['rule_content']
            
            # Search in specified fields
            for field in search_fields:
                field_value = rule.get(field, '')
                
                if not field_value:
                    continue
                
                # Convert to string and handle case sensitivity
                field_text = str(field_value)
                if not case_sensitive:
                    field_text = field_text.lower()
                
                # Apply search logic
                if regex_search:
                    try:
                        if re.search(search_query, field_text):
                            return True
                    except re.error:
                        # Fallback to normal search if regex is invalid
                        if search_query in field_text:
                            return True
                elif exact_match:
                    if search_query == field_text:
                        return True
                else:
                    if search_query in field_text:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error matching rule to query: {e}")
            return False
    
    def _load_embedding_model(self):
        """Load semantic search model - using simple text similarity"""
        # Using simple text-based semantic search
        self.embedding_model = "simple_text_similarity"
        self.logger.info("Using simple text-based semantic search")

    def _perform_semantic_search(self, query: str, threshold: float, max_results: int,
                               level_filter: List[str], source_filter: List[str],
                               custom_only: bool, include_mitre: bool = False) -> List[Dict]:
        """Perform semantic search using enhanced text similarity"""
        try:
            # Get all rules with basic filters
            filters = {}
            if level_filter:
                filters['level'] = level_filter
            if source_filter:
                filters['source_repo'] = source_filter
            if custom_only:
                filters['is_custom'] = True

            all_rules = self.db_manager.get_sigma_rules(filters)
            self.logger.info(f"Semantic search processing {len(all_rules)} rules")

            if not all_rules:
                return []

            # Calculate text similarities for SIGMA rules
            similar_items = []
            query_lower = query.lower().strip()
            query_words = set(word.strip() for word in query_lower.split() if word.strip())

            # Process SIGMA rules
            for rule in all_rules:
                # Combine rule text for similarity calculation - include more fields
                rule_text_parts = [
                    rule.get('title', ''),
                    rule.get('description', ''),
                    ' '.join(rule.get('tags', []) if isinstance(rule.get('tags'), list) else
                            (rule.get('tags', '').split(',') if rule.get('tags') else [])),
                    rule.get('rule_content', '')[:500]  # Include some rule content
                ]
                rule_text = ' '.join(part for part in rule_text_parts if part)
                rule_text_lower = rule_text.lower()

                # Calculate similarity score using multiple methods
                similarity_score = 0.0

                # 1. Exact phrase match (highest weight)
                if query_lower in rule_text_lower:
                    similarity_score += 0.7

                # 2. Enhanced word overlap with better scoring
                rule_words = set(word.strip() for word in rule_text_lower.split() if word.strip())
                if query_words and rule_words:
                    intersection = query_words.intersection(rule_words)
                    if intersection:
                        # Score based on how many query words are found
                        word_match_ratio = len(intersection) / len(query_words)
                        similarity_score += word_match_ratio * 0.4

                        # Bonus for matching important words (longer words get higher weight)
                        for word in intersection:
                            if len(word) > 4:  # Longer words are more significant
                                similarity_score += 0.05

                # 3. Partial word matching (for compound words, etc.)
                for query_word in query_words:
                    if len(query_word) > 3:  # Only check meaningful words
                        for rule_word in rule_words:
                            if query_word in rule_word or rule_word in query_word:
                                similarity_score += 0.02

                # 4. Sequence similarity for partial matches (reduced weight)
                if len(rule_text_lower) > 0:
                    seq_similarity = SequenceMatcher(None, query_lower, rule_text_lower[:300]).ratio()
                    similarity_score += seq_similarity * 0.05

                # Only include rules above threshold
                if similarity_score >= threshold:
                    rule['similarity_score'] = similarity_score
                    rule['result_type'] = 'sigma_rule'
                    similar_items.append(rule)
                    self.logger.debug(f"Rule '{rule.get('title', 'Unknown')}' scored {similarity_score:.3f}")

            # Process MITRE techniques if requested
            if include_mitre:
                try:
                    all_techniques = self.db_manager.get_mitre_techniques()
                    self.logger.info(f"Processing {len(all_techniques)} MITRE techniques for semantic search")

                    for technique in all_techniques:
                        # Combine technique text for similarity calculation
                        technique_text_parts = [
                            technique.get('technique_id', ''),
                            technique.get('name', ''),
                            technique.get('description', ''),
                            technique.get('detection', ''),
                            technique.get('mitigation', ''),
                            technique.get('tactic', '')
                        ]
                        technique_text = ' '.join(part for part in technique_text_parts if part)
                        technique_text_lower = technique_text.lower()

                        # Calculate similarity score
                        similarity_score = 0.0

                        # Exact phrase match
                        if query_lower in technique_text_lower:
                            similarity_score += 0.7

                        # Word overlap
                        technique_words = set(word.strip() for word in technique_text_lower.split() if word.strip())
                        word_overlap = len(query_words.intersection(technique_words))
                        if word_overlap > 0:
                            similarity_score += (word_overlap / len(query_words)) * 0.5

                        # Technique ID match (high priority)
                        if query_lower in technique.get('technique_id', '').lower():
                            similarity_score += 0.8

                        if similarity_score >= threshold:
                            technique['similarity_score'] = similarity_score
                            technique['result_type'] = 'mitre_technique'
                            similar_items.append(technique)

                except Exception as e:
                    self.logger.error(f"Error processing MITRE techniques in semantic search: {e}")

            # Sort by similarity and limit results
            similar_items.sort(key=lambda x: x.get('similarity_score', 0), reverse=True)
            result = similar_items[:max_results]

            self.logger.info(f"Semantic search found {len(result)} results above threshold {threshold}")
            return result

        except Exception as e:
            self.logger.error(f"Error in semantic search: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return []

    def _perform_advanced_search(self, criteria: Dict[str, Any]) -> List[Dict]:
        """Perform advanced search with multiple criteria"""
        try:
            # Build complex filters from criteria
            filters = {}

            # Basic filters
            if criteria.get('level_filter'):
                filters['level'] = criteria['level_filter']
            if criteria.get('status_filter'):
                filters['status'] = criteria['status_filter']
            if criteria.get('source_filter'):
                filters['source_repo'] = criteria['source_filter']
            if criteria.get('custom_only'):
                filters['is_custom'] = True

            # Get rules with basic filters
            rules = self.db_manager.get_sigma_rules(filters)

            # Apply additional text-based filters
            filtered_rules = []
            for rule in rules:
                if self._rule_matches_advanced_criteria(rule, criteria):
                    filtered_rules.append(rule)

            return filtered_rules

        except Exception as e:
            self.logger.error(f"Error in advanced search: {e}")
            return []

    def _rule_matches_advanced_criteria(self, rule: Dict, criteria: Dict[str, Any]) -> bool:
        """Check if rule matches advanced search criteria"""
        try:
            # Title contains
            if criteria.get('title_contains'):
                if criteria['title_contains'].lower() not in rule.get('title', '').lower():
                    return False

            # Description contains
            if criteria.get('description_contains'):
                if criteria['description_contains'].lower() not in rule.get('description', '').lower():
                    return False

            # Author contains
            if criteria.get('author_contains'):
                if criteria['author_contains'].lower() not in rule.get('author', '').lower():
                    return False

            # Tags include/exclude
            rule_tags = rule.get('tags', [])
            if isinstance(rule_tags, str):
                rule_tags = json.loads(rule_tags)

            if criteria.get('tags_include'):
                required_tags = [tag.strip() for tag in criteria['tags_include'].split(',')]
                if not any(tag in rule_tags for tag in required_tags):
                    return False

            if criteria.get('tags_exclude'):
                excluded_tags = [tag.strip() for tag in criteria['tags_exclude'].split(',')]
                if any(tag in rule_tags for tag in excluded_tags):
                    return False

            # Technique ID
            if criteria.get('technique_id'):
                technique_id = criteria['technique_id'].upper()
                if technique_id not in str(rule_tags):
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Error matching advanced criteria: {e}")
            return False

    def _add_to_search_history(self, query: str, search_type: str, result_count: int):
        """Add search to history"""
        try:
            if 'search_history' not in st.session_state:
                st.session_state.search_history = []

            history_entry = {
                'query': query,
                'type': search_type,
                'results': result_count,
                'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Add to beginning of list and limit to 20 entries
            st.session_state.search_history.insert(0, history_entry)
            st.session_state.search_history = st.session_state.search_history[:20]

        except Exception as e:
            self.logger.error(f"Error adding to search history: {e}")

    def _export_search_results(self, results: List[Dict]):
        """Export search results to CSV"""
        try:
            if not results:
                st.warning("No results to export")
                return

            # Convert to DataFrame
            df = pd.DataFrame(results)

            # Select relevant columns
            export_columns = ['rule_id', 'title', 'description', 'level', 'status', 'author', 'source_repo']
            available_columns = [col for col in export_columns if col in df.columns]
            export_df = df[available_columns]

            # Generate CSV
            csv = export_df.to_csv(index=False)

            # Provide download button
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"search_results_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

        except Exception as e:
            self.logger.error(f"Error exporting results: {e}")
            st.error(f"Export failed: {str(e)}")

    def _sort_results(self, results: List[Dict], sort_by: str, sort_order: str) -> List[Dict]:
        """Sort search results"""
        try:
            if not results:
                return results

            # Define sort key
            if sort_by == "Title":
                key_func = lambda x: x.get('title', '').lower()
            elif sort_by == "Date":
                key_func = lambda x: x.get('date', '')
            elif sort_by == "Level":
                level_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                key_func = lambda x: level_order.get(x.get('level', ''), 0)
            elif sort_by == "Author":
                key_func = lambda x: x.get('author', '').lower()
            else:  # Relevance or default
                key_func = lambda x: x.get('similarity_score', 0)

            # Sort
            reverse = sort_order == "Descending"
            return sorted(results, key=key_func, reverse=reverse)

        except Exception as e:
            self.logger.error(f"Error sorting results: {e}")
            return results

    def _show_rule_details(self, rule: Dict):
        """Show detailed rule information in a modal"""
        try:
            st.session_state.viewing_rule_details = rule
            st.rerun()
        except Exception as e:
            self.logger.error(f"Error showing rule details: {e}")

    def _render_rule_details_modal(self):
        """Render the rule details modal with full YAML content"""
        try:
            rule = st.session_state.viewing_rule_details

            # Modal header with close button
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"# 📄 Rule Details: {rule.get('title', 'Untitled Rule')}")
            with col2:
                if st.button("❌ Close", key="close_rule_details"):
                    st.session_state.viewing_rule_details = None
                    st.rerun()

            st.markdown("---")

            # Rule metadata section
            st.markdown("## 📋 Rule Metadata")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown(f"**Rule ID:** `{rule.get('rule_id', 'N/A')}`")
                st.markdown(f"**Level:** `{rule.get('level', 'Unknown')}`")
                st.markdown(f"**Status:** `{rule.get('status', 'Unknown')}`")

            with col2:
                st.markdown(f"**Author:** {rule.get('author', 'Unknown')}")
                st.markdown(f"**Date:** {rule.get('date', 'Unknown')}")
                st.markdown(f"**Source:** {rule.get('source_repo', 'Unknown')}")

            with col3:
                if rule.get('is_custom'):
                    st.markdown("🏷️ **Custom Rule**")
                if rule.get('tags'):
                    tags = json.loads(rule['tags']) if isinstance(rule['tags'], str) else rule['tags']
                    st.markdown(f"**Tags:** {len(tags)} tags")

            # Description
            if rule.get('description'):
                st.markdown("## 📝 Description")
                st.markdown(rule['description'])

            # Tags section
            if rule.get('tags'):
                st.markdown("## 🏷️ Tags")
                tags = json.loads(rule['tags']) if isinstance(rule['tags'], str) else rule['tags']

                # Display tags in a nice format - ensure we have at least 1 column
                if tags and len(tags) > 0:
                    tag_cols = st.columns(min(len(tags), 4))
                    for i, tag in enumerate(tags):
                        with tag_cols[i % 4]:
                            st.markdown(f"`{tag}`")
                else:
                    st.markdown("No tags available")

            # YAML Rule Content
            st.markdown("## 📄 SIGMA Rule (YAML)")

            if rule.get('rule_content'):
                # Display the YAML content in a code block for viewing
                st.code(rule['rule_content'], language='yaml')

                # Copy functionality section
                st.markdown("### 📋 Copy YAML Content")

                # Create expandable section for copying
                with st.expander("🔽 Click here to copy YAML content", expanded=False):
                    st.markdown("**Method 1: Select and Copy from Text Area**")

                    # Create a text area with the YAML content for easy copying
                    st.text_area(
                        "Select all text and copy to clipboard",
                        value=rule['rule_content'],
                        height=150,
                        key="yaml_copy_area",
                        help="1. Click in this text area\n2. Select All (Ctrl+A or Cmd+A)\n3. Copy (Ctrl+C or Cmd+C)"
                    )

                    st.markdown("**Method 2: Download as File**")
                    col1, col2 = st.columns(2)

                    with col1:
                        st.download_button(
                            label="📥 Download YAML File",
                            data=rule['rule_content'],
                            file_name=f"{rule.get('rule_id', 'rule')}.yml",
                            mime="text/yaml",
                            key="download_yaml_from_modal",
                            use_container_width=True
                        )

                    with col2:
                        # Show character count for reference
                        char_count = len(rule['rule_content'])
                        st.metric("Content Size", f"{char_count} chars")

                # Quick copy instructions
                st.info("💡 **Quick Copy:** Expand the section above, click in the text area, select all (Ctrl+A), and copy (Ctrl+C)")
            else:
                st.warning("⚠️ No YAML content available for this rule.")

            # Action buttons
            st.markdown("---")
            st.markdown("## 🔧 Actions")

            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button("✏️ Edit Rule", key="edit_from_details"):
                    st.session_state.edit_rule_data = rule
                    st.session_state.current_page = "📝 SIGMA Rule Builder"
                    st.session_state.viewing_rule_details = None
                    st.success("✅ Rule loaded for editing. Redirecting to SIGMA Rule Builder...")
                    st.rerun()

            with col2:
                if st.button("📥 Download YAML", key="download_yaml"):
                    if rule.get('rule_content'):
                        st.download_button(
                            label="💾 Download",
                            data=rule['rule_content'],
                            file_name=f"{rule.get('rule_id', 'rule')}.yml",
                            mime="text/yaml",
                            key="download_yaml_file"
                        )
                    else:
                        st.error("No YAML content to download")

            with col3:
                if st.button("🔍 Search Similar", key="search_similar"):
                    # Use the rule title as a semantic search query
                    if rule.get('title'):
                        st.session_state.search_query = rule['title']
                        st.session_state.search_type = "semantic"
                        st.session_state.viewing_rule_details = None
                        st.info("🔍 Searching for similar rules...")
                        st.rerun()
                    else:
                        st.error("Cannot search for similar rules without a title")

        except Exception as e:
            self.logger.error(f"Error rendering rule details modal: {e}")
            st.error(f"Error displaying rule details: {str(e)}")
            # Clear the session state on error
            st.session_state.viewing_rule_details = None

    def _render_search_sidebar(self):
        """Render search sidebar with history and saved searches"""
        try:
            st.markdown("### 📚 Search History")

            if 'search_history' in st.session_state and st.session_state.search_history:
                for i, entry in enumerate(st.session_state.search_history[:5]):
                    with st.expander(f"{entry['type'].title()}: {entry['query'][:30]}..."):
                        st.write(f"**Results:** {entry['results']}")
                        st.write(f"**Time:** {entry['timestamp']}")
                        if st.button(f"🔄 Repeat", key=f"repeat_{i}"):
                            # Repeat search logic would go here
                            st.info("Repeat search functionality coming soon!")
            else:
                st.info("No search history yet")

            st.markdown("---")
            st.markdown("### ⭐ Saved Searches")
            st.info("Saved searches functionality coming soon!")

        except Exception as e:
            self.logger.error(f"Error rendering search sidebar: {e}")
