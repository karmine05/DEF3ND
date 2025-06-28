"""
MITRE ATT&CK Explorer Component
Provides comprehensive MITRE ATT&CK framework exploration and analysis
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
from stix2 import MemoryStore, Filter
import stix2
from components.technique_detail_view import TechniqueDetailView
class MitreExplorer:
    """MITRE ATT&CK Explorer component for the detection platform"""

    def __init__(self, db_manager, llm_integration=None):
        self.db_manager = db_manager
        self.llm_integration = llm_integration
        self.logger = logging.getLogger(__name__)

        # Initialize technique detail view if LLM integration is available
        if self.llm_integration:
            self.technique_detail_view = TechniqueDetailView(db_manager, llm_integration)
        else:
            self.technique_detail_view = None

        # MITRE ATT&CK data sources
        self.mitre_sources = {
            'enterprise': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'ics': 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json'
        }

        # MITRE ATT&CK tactic mapping for consistent formatting
        # This ensures proper capitalization and handles special cases
        self.tactic_mapping = {
            'initial-access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'privilege-escalation': 'Privilege Escalation',
            'defense-evasion': 'Defense Evasion',
            'credential-access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral-movement': 'Lateral Movement',
            'collection': 'Collection',
            'command-and-control': 'Command and Control',  # Proper formatting
            'exfiltration': 'Exfiltration',
            'impact': 'Impact',
            'reconnaissance': 'Reconnaissance',
            'resource-development': 'Resource Development'
        }

        # Initialize MITRE data store
        self.mitre_store = None
        self._load_mitre_data()

    def _generate_stix_uuid(self, technique_id: str) -> str:
        """Generate a deterministic UUID for STIX identifier based on technique ID"""
        # Create a deterministic UUID based on technique ID
        # This ensures the same technique always gets the same UUID
        namespace = uuid.UUID('12345678-1234-5678-1234-123456789abc')
        return str(uuid.uuid5(namespace, technique_id))

    def _create_manual_bundle(self, raw_data: Dict) -> Any:
        """Create a manual bundle from raw JSON data when STIX parsing fails"""
        try:
            # Create a simple object container that mimics a STIX bundle
            class ManualBundle:
                def __init__(self, objects):
                    self.objects = objects

            objects = raw_data.get('objects', [])
            return ManualBundle(objects)

        except Exception as e:
            self.logger.error(f"Error creating manual bundle: {e}")
            return ManualBundle([])
    
    def render(self):
        """Render the MITRE ATT&CK Explorer interface"""
        st.markdown('<h2 class="sub-header">🎯 MITRE ATT&CK Explorer</h2>', unsafe_allow_html=True)

        # Show enhanced features notification
        with st.expander("✨ Enhanced Features Available", expanded=False):
            st.markdown("""
            **🎯 Enhanced Technique Detail View** - Click "📋 View Complete Details" on any technique to access:

            - **📋 Complete MITRE Data**: All framework information without truncation
            - **🤖 AI Analysis**: Comprehensive technical analysis and threat intelligence
            - **🎯 Detection Recommendations**: Specific guidance for building detection rules
            - **⚔️ Attack Scenarios**: Real-world implementation examples

            **💡 Missing Detection/Mitigation Data?**
            Go to Settings → Data Management → Sync MITRE Data to update with enhanced extraction.
            """)

        st.markdown("---")
        
        # Sidebar filters
        with st.sidebar:
            st.markdown("### 🔍 Filters")
            
            # Framework selection
            framework = st.selectbox(
                "Framework",
                ["Enterprise", "ICS", "Both"],
                index=0
            )
            
            # Tactic filter
            tactics = self._get_tactics(framework.lower())
            selected_tactic = st.selectbox(
                "Tactic",
                ["All"] + tactics,
                index=0
            )
            
            # Platform filter
            platforms = self._get_platforms(framework.lower())
            selected_platforms = st.multiselect(
                "Platforms",
                platforms,
                default=[]
            )
            
            # Data source filter
            data_sources = self._get_data_sources()
            selected_data_sources = st.multiselect(
                "Data Sources",
                data_sources,
                default=[]
            )
        
        # Main content tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Overview", 
            "🎯 Techniques", 
            "🗺️ Tactics Matrix", 
            "📈 Analytics", 
            "🔗 Rule Mappings"
        ])
        
        with tab1:
            self._render_overview(framework)
        
        with tab2:
            self._render_techniques(framework, selected_tactic, selected_platforms, selected_data_sources)
        
        with tab3:
            self._render_tactics_matrix(framework)
        
        with tab4:
            self._render_analytics(framework)
        
        with tab5:
            self._render_rule_mappings(framework, selected_tactic)

        # Check if we need to display related rules modal
        if 'viewing_related_rules' in st.session_state and st.session_state.viewing_related_rules:
            self._render_related_rules_modal()
    
    def _render_overview(self, framework: str):
        """Render MITRE ATT&CK overview"""
        st.markdown("### 📊 MITRE ATT&CK Framework Overview")
        
        # Get framework statistics
        stats = self._get_framework_stats(framework.lower())
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Techniques", stats.get('techniques', 0))
        
        with col2:
            st.metric("Tactics", stats.get('tactics', 0))
        
        with col3:
            st.metric("Sub-techniques", stats.get('sub_techniques', 0))
        
        with col4:
            st.metric("Data Sources", stats.get('data_sources', 0))
        
        # Framework description
        st.markdown("---")
        
        if framework.lower() in ['enterprise', 'both']:
            with st.expander("🏢 Enterprise Framework", expanded=True):
                st.markdown("""
                The MITRE ATT&CK Enterprise framework covers techniques used against enterprise networks,
                including Windows, macOS, Linux, and cloud environments. It provides a comprehensive
                knowledge base of adversary tactics and techniques based on real-world observations.
                """)
        
        if framework.lower() in ['ics', 'both']:
            with st.expander("🏭 ICS Framework", expanded=True):
                st.markdown("""
                The MITRE ATT&CK for ICS framework focuses on techniques used against Industrial Control Systems,
                including SCADA systems, PLCs, and other operational technology environments.
                """)
        
        # Recent updates
        st.markdown("### 📅 Recent Updates")
        recent_updates = self._get_recent_updates()
        
        if recent_updates:
            for update in recent_updates[:5]:
                st.write(f"• {update['date']}: {update['description']}")
        else:
            st.info("No recent updates available. Click 'Update MITRE Data' to refresh.")
    
    def _render_techniques(self, framework: str, tactic: str, platforms: List[str], data_sources: List[str]):
        """Render techniques browser"""
        st.markdown("### 🎯 Techniques Browser")
        
        # Get filtered techniques
        techniques = self._get_techniques(framework.lower(), tactic, platforms, data_sources)
        
        if not techniques:
            st.warning("No techniques found matching the selected filters.")
            return
        
        # Search functionality
        search_term = st.text_input("🔍 Search techniques", placeholder="Enter technique name or ID...")
        
        if search_term:
            techniques = [t for t in techniques if 
                         search_term.lower() in t.get('name', '').lower() or 
                         search_term.lower() in t.get('technique_id', '').lower()]
        
        # Display techniques
        st.write(f"Found {len(techniques)} techniques")
        
        # Pagination
        items_per_page = 10
        total_pages = (len(techniques) - 1) // items_per_page + 1
        
        if total_pages > 1:
            page = st.selectbox("Page", range(1, total_pages + 1)) - 1
        else:
            page = 0
        
        start_idx = page * items_per_page
        end_idx = start_idx + items_per_page
        page_techniques = techniques[start_idx:end_idx]
        
        # Check if we should show technique detail view
        if 'viewing_technique_detail' in st.session_state and st.session_state.viewing_technique_detail:
            technique_id = st.session_state.viewing_technique_detail

            # Back button
            if st.button("← Back to Techniques List", key="back_to_list"):
                del st.session_state.viewing_technique_detail
                st.rerun()

            # Show enhanced technique detail view
            if self.technique_detail_view:
                self.technique_detail_view.render_technique_detail(technique_id)
            else:
                st.error("Enhanced technique detail view not available. LLM integration required.")
            return

        # Display technique cards
        for technique in page_techniques:
            with st.expander(f"**{technique.get('technique_id', 'Unknown')}** - {technique.get('name', 'Unknown')}"):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(f"**Description:** {technique.get('description', 'No description available')[:300]}...")

                    if technique.get('tactic'):
                        st.markdown(f"**Tactic:** {technique['tactic']}")

                    if technique.get('platform'):
                        platforms_list = json.loads(technique['platform']) if isinstance(technique['platform'], str) else technique['platform']
                        st.markdown(f"**Platforms:** {', '.join(platforms_list)}")

                    if technique.get('data_sources'):
                        data_sources_list = json.loads(technique['data_sources']) if isinstance(technique['data_sources'], str) else technique['data_sources']
                        st.markdown(f"**Data Sources:** {', '.join(data_sources_list[:3])}{'...' if len(data_sources_list) > 3 else ''}")

                with col2:
                    # Enhanced Detail View Button
                    technique_id = technique.get('technique_id', '')
                    if st.button(f"📋 View Complete Details", key=f"detail_{technique_id}"):
                        st.session_state.viewing_technique_detail = technique_id
                        st.rerun()

                    # Get related SIGMA rules
                    related_rules = self._get_related_sigma_rules(technique_id)
                    st.metric("Related SIGMA Rules", len(related_rules))

                    if related_rules:
                        if st.button(f"View Rules", key=f"rules_{technique_id}"):
                            # Store rules in session state for modal display
                            st.session_state.viewing_related_rules = {
                                'technique_id': technique_id,
                                'technique_name': technique.get('name', 'Unknown'),
                                'rules': related_rules
                            }
                            st.rerun()

                    # Detection and mitigation info (truncated)
                    if technique.get('detection'):
                        st.markdown("**🔍 Detection:**")
                        st.write(technique['detection'][:200] + "...")
                        st.markdown("---")

                    if technique.get('mitigation'):
                        st.markdown("**🛡️ Mitigation:**")
                        st.write(technique['mitigation'][:200] + "...")
                        st.markdown("---")
    
    def _render_tactics_matrix(self, framework: str):
        """Render MITRE ATT&CK tactics matrix"""
        st.markdown("### 🗺️ MITRE ATT&CK Tactics Matrix")

        # Matrix controls at the top
        col1, col2, col3 = st.columns(3)

        with col1:
            show_sub_techniques = st.checkbox("Show Sub-techniques", value=False, key="matrix_sub_techniques")

        with col2:
            color_by = st.selectbox("Color by", ["Rule Coverage"], key="matrix_color_by")

        with col3:
            matrix_view = st.selectbox("View", [
                "Coverage Dashboard",
                "Technique Network"
            ], key="matrix_view")

        # Get tactics and techniques for matrix
        matrix_data = self._get_matrix_data(framework.lower(), show_sub_techniques)

        if not matrix_data:
            st.warning("No matrix data available. Please sync MITRE data from the Settings page.")
            st.info("💡 Go to Settings → Data Management → Sync MITRE Data to load the ATT&CK framework.")
            return

        # Create interactive matrix visualization
        total_techniques = sum(len(techniques) for techniques in matrix_data.values())
        st.success(f"🎯 Loaded {total_techniques} techniques across {len(matrix_data)} tactics")

        try:
            if matrix_view == "Coverage Dashboard":
                self._render_coverage_dashboard(matrix_data, color_by)
            elif matrix_view == "Technique Network":
                fig = self._create_technique_network(matrix_data, color_by)
                if fig:
                    st.plotly_chart(fig, use_container_width=True, key="network_chart")
                else:
                    st.error("Failed to create network visualization")
                    self._render_coverage_dashboard(matrix_data, color_by)
            else:
                # Fallback to dashboard
                self._render_coverage_dashboard(matrix_data, color_by)

        except Exception as e:
            st.error(f"Error creating visualization: {str(e)}")
            st.info("🔄 Switching to basic dashboard view...")
            self._render_coverage_dashboard(matrix_data, color_by)

        # Matrix statistics only (removed legend as it wasn't mapping correctly)
        if matrix_data:
            total_techniques = sum(len(techniques) for techniques in matrix_data.values())
            total_tactics = len(matrix_data)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📊 Total Techniques", total_techniques)
            with col2:
                st.metric("🎯 Total Tactics", total_tactics)
            with col3:
                # Calculate coverage statistics
                coverage_stats = self._calculate_matrix_coverage(matrix_data)
                if coverage_stats:
                    st.metric("📈 Coverage", f"{coverage_stats.get('coverage_percentage', 0):.1f}%")
    
    def _render_analytics(self, framework: str):
        """Render enhanced MITRE ATT&CK analytics with detection and mitigation insights"""
        st.markdown("### 📈 Enhanced MITRE ATT&CK Analytics")

        # Get enhanced analytics data
        analytics_data = self._get_enhanced_analytics_data(framework.lower())

        # Enhanced overview metrics
        st.markdown("#### 🎯 Enhanced Coverage Overview")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total Techniques",
                analytics_data.get('total_techniques', 0)
            )

        with col2:
            detection_coverage = analytics_data.get('detection_coverage', {})
            st.metric(
                "With Detection Info",
                detection_coverage.get('count', 0),
                delta=f"{detection_coverage.get('percentage', 0):.1f}%"
            )

        with col3:
            mitigation_coverage = analytics_data.get('mitigation_coverage', {})
            st.metric(
                "With Mitigation Info",
                mitigation_coverage.get('count', 0),
                delta=f"{mitigation_coverage.get('percentage', 0):.1f}%"
            )

        with col4:
            complete_coverage = analytics_data.get('complete_coverage', {})
            st.metric(
                "Complete Data",
                complete_coverage.get('count', 0),
                delta=f"{complete_coverage.get('percentage', 0):.1f}%"
            )

        # Tactic distribution with enhanced data
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 🎯 Techniques by Tactic")
            tactic_counts = analytics_data.get('tactic_distribution', {})

            if tactic_counts:
                fig = px.bar(
                    x=list(tactic_counts.keys()),
                    y=list(tactic_counts.values()),
                    title="Number of Techniques per Tactic"
                )
                fig.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### 🖥️ Platform Coverage")
            platform_counts = analytics_data.get('platform_distribution', {})
            
            if platform_counts:
                fig = px.pie(
                    values=list(platform_counts.values()),
                    names=list(platform_counts.keys()),
                    title="Techniques by Platform"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # Enhanced detection and mitigation analysis
        st.markdown("#### 🔍 Detection & Mitigation Data Quality")

        # Data quality metrics
        data_quality = analytics_data.get('data_quality', {})

        col1, col2 = st.columns(2)

        with col1:
            # Detection data quality chart
            detection_quality = data_quality.get('detection_quality', {})
            if detection_quality:
                fig = px.pie(
                    values=[
                        detection_quality.get('with_detection', 0),
                        detection_quality.get('without_detection', 0)
                    ],
                    names=['With Detection Info', 'Without Detection Info'],
                    title="Detection Information Availability",
                    color_discrete_map={
                        'With Detection Info': '#4CAF50',
                        'Without Detection Info': '#F44336'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Mitigation data quality chart
            mitigation_quality = data_quality.get('mitigation_quality', {})
            if mitigation_quality:
                fig = px.pie(
                    values=[
                        mitigation_quality.get('with_mitigation', 0),
                        mitigation_quality.get('without_mitigation', 0)
                    ],
                    names=['With Mitigation Info', 'Without Mitigation Info'],
                    title="Mitigation Information Availability",
                    color_discrete_map={
                        'With Mitigation Info': '#2196F3',
                        'Without Mitigation Info': '#FF9800'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)

        # SIGMA rule coverage analysis
        st.markdown("#### 📊 SIGMA Rule Coverage Analysis")
        coverage_data = self._get_enhanced_coverage_analysis(framework.lower())

        if coverage_data:
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "Techniques with Rules",
                    coverage_data.get('covered_techniques', 0),
                    delta=f"{coverage_data.get('coverage_percentage', 0):.1f}%"
                )

            with col2:
                st.metric(
                    "Total SIGMA Rules",
                    coverage_data.get('total_rules', 0)
                )

            with col3:
                st.metric(
                    "Avg Rules per Technique",
                    f"{coverage_data.get('avg_rules_per_technique', 0):.1f}"
                )

            with col4:
                st.metric(
                    "High-Quality Mappings",
                    coverage_data.get('high_confidence_mappings', 0),
                    delta=f"{coverage_data.get('high_confidence_percentage', 0):.1f}%"
                )

            # Enhanced coverage matrix
            if coverage_data.get('enhanced_coverage_matrix'):
                fig = self._create_enhanced_coverage_heatmap(coverage_data['enhanced_coverage_matrix'])
                st.plotly_chart(fig, use_container_width=True)
    
    def _render_rule_mappings(self, framework: str, tactic: str):
        """Render SIGMA rule to MITRE technique mappings"""
        st.markdown("### 🔗 SIGMA Rule Mappings")
        
        # Get mapping data
        mappings = self._get_rule_mappings(framework.lower(), tactic)
        
        if not mappings:
            st.warning("No rule mappings found for the selected filters.")
            return
        
        # Display mapping statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Mappings", len(mappings))
        
        with col2:
            unique_techniques = len(set(m['technique_id'] for m in mappings))
            st.metric("Mapped Techniques", unique_techniques)
        
        with col3:
            unique_rules = len(set(m['rule_id'] for m in mappings))
            st.metric("Mapped Rules", unique_rules)
        
        # Mapping table
        st.markdown("#### 📋 Rule-Technique Mappings")
        
        # Convert to DataFrame for display
        df = pd.DataFrame(mappings)
        
        if not df.empty:
            # Add technique names
            df['technique_name'] = df['technique_id'].apply(lambda x: self._get_technique_name(x))
            df['rule_title'] = df['rule_id'].apply(lambda x: self._get_rule_title(x))
            
            # Display table
            display_df = df[['technique_id', 'technique_name', 'rule_id', 'rule_title', 'confidence']].copy()
            display_df.columns = ['Technique ID', 'Technique Name', 'Rule ID', 'Rule Title', 'Confidence']
            
            st.dataframe(display_df, use_container_width=True)
            
            # Export functionality
            if st.button("📥 Export Mappings"):
                csv = display_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"mitre_sigma_mappings_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
    
    def update_mitre_data(self) -> Dict[str, Any]:
        """Update MITRE ATT&CK data from official sources"""
        try:
            total_updated = 0
            
            for framework, url in self.mitre_sources.items():
                self.logger.info(f"Updating MITRE {framework} data from {url}")
                
                # Download STIX data
                response = requests.get(url, timeout=30)
                response.raise_for_status()

                # Parse STIX bundle with custom object support and error handling
                try:
                    bundle = stix2.parse(response.text, allow_custom=True)
                except Exception as parse_error:
                    self.logger.warning(f"STIX parsing error for {framework}: {parse_error}")
                    # Try to parse as raw JSON and process manually
                    try:
                        raw_data = json.loads(response.text)
                        bundle = self._create_manual_bundle(raw_data)
                    except Exception as json_error:
                        self.logger.error(f"Failed to parse {framework} data: {json_error}")
                        continue
                
                # Process techniques and tactics
                techniques_count = self._process_stix_bundle(bundle, framework)
                total_updated += techniques_count
                
                self.logger.info(f"Updated {techniques_count} techniques from {framework}")
            
            # Update local store
            self._load_mitre_data()

            # Process any pending rule-technique mappings
            mapping_results = self.db_manager.process_pending_mappings()
            self.logger.info(f"Processed pending mappings: {mapping_results}")

            # Log activity
            self.db_manager.log_activity(
                "MITRE Data Update",
                f"Updated {total_updated} techniques from MITRE ATT&CK, processed {mapping_results['processed']} pending mappings"
            )

            return {
                'success': True,
                'count': total_updated,
                'mappings_processed': mapping_results['processed'],
                'message': f'Successfully updated {total_updated} MITRE techniques and processed {mapping_results["processed"]} rule mappings'
            }
            
        except Exception as e:
            self.logger.error(f"Error updating MITRE data: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _load_mitre_data(self):
        """Load MITRE data into memory store from database"""
        try:
            # Disable STIX memory store for now due to validation issues
            # Just initialize an empty store to prevent errors
            self.mitre_store = MemoryStore()

            # Get techniques count for logging
            techniques = self.db_manager.get_mitre_techniques()
            self.logger.info(f"MITRE data available: {len(techniques)} techniques (STIX store disabled)")

        except Exception as e:
            self.logger.error(f"Error loading MITRE data: {e}")
            # Fallback to empty store
            self.mitre_store = MemoryStore()

    def _process_stix_bundle(self, bundle, framework: str) -> int:
        """Process STIX bundle and extract MITRE ATT&CK data with relationships"""
        try:
            techniques_count = 0
            attack_patterns_found = 0
            total_objects = len(bundle.objects)

            self.logger.debug(f"Processing {total_objects} objects from {framework} bundle")

            # First pass: collect all objects by type
            attack_patterns = {}
            course_of_actions = {}
            relationships = []

            for obj in bundle.objects:
                try:
                    obj_type = getattr(obj, 'type', obj.get('type') if isinstance(obj, dict) else None)
                    obj_id = getattr(obj, 'id', obj.get('id') if isinstance(obj, dict) else None)

                    if not obj_type:
                        continue

                    if obj_type == 'attack-pattern':
                        attack_patterns[obj_id] = obj
                    elif obj_type == 'course-of-action':
                        course_of_actions[obj_id] = obj
                    elif obj_type == 'relationship':
                        relationships.append(obj)

                except Exception as e:
                    self.logger.debug(f"Error collecting object: {e}")
                    continue

            self.logger.info(f"Collected {len(attack_patterns)} attack patterns, {len(course_of_actions)} mitigations, {len(relationships)} relationships")

            # Second pass: process attack patterns with their relationships
            for pattern_id, attack_pattern in attack_patterns.items():
                try:
                    attack_patterns_found += 1

                    # Extract basic technique data
                    technique_data = self._extract_technique_data(attack_pattern, framework)
                    if not technique_data:
                        continue

                    # Extract detection information
                    detection_info = self._extract_detection_info(attack_pattern, pattern_id, relationships)
                    if detection_info:
                        technique_data['detection'] = detection_info

                    # Extract mitigation information
                    mitigation_info = self._extract_mitigation_info(pattern_id, relationships, course_of_actions)
                    if mitigation_info:
                        technique_data['mitigation'] = mitigation_info

                    # Insert technique with complete data
                    if self.db_manager.insert_mitre_technique(technique_data):
                        techniques_count += 1
                    else:
                        self.logger.warning(f"Failed to insert technique: {technique_data.get('technique_id', 'Unknown')}")

                except Exception as e:
                    self.logger.error(f"Error processing attack pattern {pattern_id}: {e}")
                    continue

            self.logger.info(f"Processed {techniques_count} techniques from {framework} framework ({attack_patterns_found} attack patterns found)")
            return techniques_count

        except Exception as e:
            self.logger.error(f"Error processing STIX bundle for {framework}: {e}")
            return 0

    def _extract_technique_data(self, attack_pattern, framework: str) -> Optional[Dict[str, Any]]:
        """Extract technique data from STIX attack-pattern object"""
        try:
            # Handle both STIX objects and dictionaries
            def get_attr(obj, attr, default=None):
                if hasattr(obj, attr):
                    return getattr(obj, attr)
                elif isinstance(obj, dict):
                    return obj.get(attr, default)
                return default

            # Get external references to find MITRE technique ID
            technique_id = None
            references = []

            external_refs = get_attr(attack_pattern, 'external_references', [])
            for ref in external_refs:
                # Handle STIX ExternalReference objects properly
                if hasattr(ref, 'source_name'):
                    # STIX object - access attributes directly
                    source_name = getattr(ref, 'source_name', '')
                    external_id = getattr(ref, 'external_id', '')
                    url = getattr(ref, 'url', '')
                elif isinstance(ref, dict):
                    # Dictionary - access as dict
                    source_name = ref.get('source_name', '')
                    external_id = ref.get('external_id', '')
                    url = ref.get('url', '')
                else:
                    continue

                if source_name == 'mitre-attack':
                    technique_id = external_id

                references.append({
                    'source_name': source_name,
                    'external_id': external_id,
                    'url': url
                })

            if not technique_id:
                return None

            # Extract kill chain phases (tactics)
            tactics = []
            kill_chain_phases = get_attr(attack_pattern, 'kill_chain_phases', [])

            for phase in kill_chain_phases:
                # Handle multiple formats: dict, STIX object, or object with attributes
                kill_chain_name = ''
                phase_name = ''

                if isinstance(phase, dict):
                    # Direct dictionary access
                    kill_chain_name = phase.get('kill_chain_name', '')
                    phase_name = phase.get('phase_name', '')
                elif hasattr(phase, 'kill_chain_name') and hasattr(phase, 'phase_name'):
                    # STIX object with direct attributes
                    kill_chain_name = getattr(phase, 'kill_chain_name', '')
                    phase_name = getattr(phase, 'phase_name', '')
                elif hasattr(phase, '__dict__'):
                    # Object with __dict__ containing the data
                    phase_dict = phase.__dict__
                    kill_chain_name = phase_dict.get('kill_chain_name', '')
                    phase_name = phase_dict.get('phase_name', '')



                if kill_chain_name == 'mitre-attack' and phase_name:
                    # Use the class-level tactic mapping for consistent formatting
                    tactic_name = self.tactic_mapping.get(phase_name, phase_name.replace('-', ' ').title())
                    tactics.append(tactic_name)

            # Extract platforms
            platforms = get_attr(attack_pattern, 'x_mitre_platforms', [])

            # Extract data sources
            data_sources = get_attr(attack_pattern, 'x_mitre_data_sources', [])

            # Extract detection information
            detection_info = get_attr(attack_pattern, 'x_mitre_detection', "")

            # Get name and description
            name = get_attr(attack_pattern, 'name', '')
            description = get_attr(attack_pattern, 'description', '')

            # Extract additional MITRE ATT&CK properties
            permissions_required = get_attr(attack_pattern, 'x_mitre_permissions_required', [])
            system_requirements = get_attr(attack_pattern, 'x_mitre_system_requirements', [])
            network_requirements = get_attr(attack_pattern, 'x_mitre_network_requirements', '')
            remote_support = get_attr(attack_pattern, 'x_mitre_remote_support', '')
            impact_type = get_attr(attack_pattern, 'x_mitre_impact_type', [])
            effective_permissions = get_attr(attack_pattern, 'x_mitre_effective_permissions', [])
            defense_bypassed = get_attr(attack_pattern, 'x_mitre_defense_bypassed', [])

            # Convert impact_type to string if it's a list
            if isinstance(impact_type, list):
                impact_type = ', '.join(impact_type)

            # Get sub-techniques (techniques with same base ID but with .XXX suffix)
            sub_techniques = []
            if technique_id and '.' not in technique_id:  # Only for parent techniques
                # This will be populated later when we have access to all techniques
                pass

            # Prepare kill chain phases data
            kill_chain_phases_data = []
            for phase in kill_chain_phases:
                if isinstance(phase, dict):
                    kill_chain_phases_data.append({
                        'kill_chain_name': phase.get('kill_chain_name', ''),
                        'phase_name': phase.get('phase_name', '')
                    })
                elif hasattr(phase, 'kill_chain_name') and hasattr(phase, 'phase_name'):
                    kill_chain_phases_data.append({
                        'kill_chain_name': getattr(phase, 'kill_chain_name', ''),
                        'phase_name': getattr(phase, 'phase_name', '')
                    })

            # Prepare technique data for database
            technique_data = {
                'technique_id': technique_id,
                'name': name,
                'description': description,
                'tactic': tactics[0] if tactics else None,  # Use first tactic as primary
                'platform': platforms,
                'data_sources': data_sources,
                'detection': detection_info,
                'mitigation': '',  # Will be populated from course-of-action objects
                'references': references,
                'permissions_required': permissions_required,
                'sub_techniques': sub_techniques,
                'procedure_examples': [],  # Will be populated from relationship objects
                'kill_chain_phases': kill_chain_phases_data,
                'system_requirements': system_requirements,
                'network_requirements': network_requirements,
                'remote_support': remote_support,
                'impact_type': impact_type,
                'effective_permissions': effective_permissions,
                'defense_bypassed': defense_bypassed
            }

            return technique_data

        except Exception as e:
            self.logger.error(f"Error extracting technique data: {e}")
            return None

    def _extract_detection_info(self, attack_pattern, pattern_id: str, relationships: list) -> str:
        """Extract detection information from attack pattern and relationships"""
        try:
            # First, try to get detection info from x_mitre_detection
            def get_attr(obj, attr, default=None):
                if hasattr(obj, attr):
                    return getattr(obj, attr)
                elif isinstance(obj, dict):
                    return obj.get(attr, default)
                return default

            detection_info = get_attr(attack_pattern, 'x_mitre_detection', '')

            # If no direct detection info, look for data sources and components
            if not detection_info:
                data_sources = get_attr(attack_pattern, 'x_mitre_data_sources', [])
                if data_sources:
                    detection_parts = []
                    detection_parts.append("**Data Sources:**")
                    for ds in data_sources:
                        if isinstance(ds, dict):
                            ds_name = ds.get('name', str(ds))
                            ds_components = ds.get('data_components', [])
                            if ds_components:
                                detection_parts.append(f"- {ds_name}: {', '.join(ds_components)}")
                            else:
                                detection_parts.append(f"- {ds_name}")
                        else:
                            detection_parts.append(f"- {ds}")

                    detection_info = '\n'.join(detection_parts)

            # Look for additional detection guidance in relationships
            # This would require processing data-source and data-component objects
            # For now, we'll use what we have from the attack pattern itself

            return detection_info

        except Exception as e:
            self.logger.error(f"Error extracting detection info: {e}")
            return ""

    def _extract_mitigation_info(self, pattern_id: str, relationships: list, course_of_actions: dict) -> str:
        """Extract mitigation information from relationships and course-of-action objects"""
        try:
            mitigation_parts = []

            # Find relationships where this technique is the target and relationship is 'mitigates'
            for rel in relationships:
                try:
                    rel_type = getattr(rel, 'relationship_type', rel.get('relationship_type') if isinstance(rel, dict) else None)
                    source_ref = getattr(rel, 'source_ref', rel.get('source_ref') if isinstance(rel, dict) else None)
                    target_ref = getattr(rel, 'target_ref', rel.get('target_ref') if isinstance(rel, dict) else None)

                    # Look for 'mitigates' relationships where this technique is the target
                    if rel_type == 'mitigates' and target_ref == pattern_id and source_ref in course_of_actions:
                        mitigation_obj = course_of_actions[source_ref]

                        # Extract mitigation details
                        def get_attr(obj, attr, default=None):
                            if hasattr(obj, attr):
                                return getattr(obj, attr)
                            elif isinstance(obj, dict):
                                return obj.get(attr, default)
                            return default

                        mit_name = get_attr(mitigation_obj, 'name', 'Unknown Mitigation')
                        mit_description = get_attr(mitigation_obj, 'description', '')

                        if mit_name and mit_description:
                            mitigation_parts.append(f"**{mit_name}**")
                            mitigation_parts.append(mit_description)
                            mitigation_parts.append("")  # Add spacing

                except Exception as e:
                    self.logger.debug(f"Error processing relationship: {e}")
                    continue

            return '\n'.join(mitigation_parts) if mitigation_parts else ""

        except Exception as e:
            self.logger.error(f"Error extracting mitigation info: {e}")
            return ""

    def _get_tactics(self, framework: str) -> List[str]:
        """Get available tactics for framework"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                if framework and framework.lower() != 'both':
                    cursor.execute(
                        "SELECT DISTINCT tactic FROM mitre_techniques WHERE tactic IS NOT NULL AND tactic != 'None' AND tactic != '' AND framework = ?",
                        (framework.lower(),)
                    )
                else:
                    cursor.execute("SELECT DISTINCT tactic FROM mitre_techniques WHERE tactic IS NOT NULL AND tactic != 'None' AND tactic != ''")

                tactics = [row[0] for row in cursor.fetchall()]

                # For ICS framework, if no tactics found, return a default set
                if framework and framework.lower() == 'ics' and not tactics:
                    # ICS techniques might not have traditional tactics, so return empty or ICS-specific categories
                    return []

                return sorted(tactics)
        except Exception as e:
            self.logger.error(f"Error getting tactics: {e}")
            return []
    
    def _get_platforms(self, framework: str) -> List[str]:
        """Get available platforms for framework from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get unique platforms from techniques in database
                if framework and framework.lower() != 'both':
                    cursor.execute("""
                        SELECT DISTINCT platform
                        FROM mitre_techniques
                        WHERE platform IS NOT NULL AND platform != '' AND framework = ?
                    """, (framework.lower(),))
                else:
                    cursor.execute("""
                        SELECT DISTINCT platform
                        FROM mitre_techniques
                        WHERE platform IS NOT NULL AND platform != ''
                    """)

                platforms = set()
                for row in cursor.fetchall():
                    platform_data = row[0]
                    if platform_data:
                        try:
                            platform_list = json.loads(platform_data) if isinstance(platform_data, str) else platform_data
                            if isinstance(platform_list, list):
                                platforms.update(platform_list)
                        except (json.JSONDecodeError, TypeError):
                            # Handle single platform strings
                            platforms.add(platform_data)

                # Return sorted list of platforms
                return sorted(list(platforms)) if platforms else ['Windows', 'Linux', 'macOS']

        except Exception as e:
            self.logger.error(f"Error getting platforms: {e}")
            # Fallback to common platforms
            return ['Windows', 'Linux', 'macOS', 'Cloud', 'Network']
    
    def _get_data_sources(self) -> List[str]:
        """Get available data sources from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get unique data sources from techniques in database
                cursor.execute("""
                    SELECT DISTINCT data_sources
                    FROM mitre_techniques
                    WHERE data_sources IS NOT NULL AND data_sources != ''
                """)

                data_sources = set()
                for row in cursor.fetchall():
                    data_source_data = row[0]
                    if data_source_data:
                        try:
                            source_list = json.loads(data_source_data) if isinstance(data_source_data, str) else data_source_data
                            if isinstance(source_list, list):
                                data_sources.update(source_list)
                        except (json.JSONDecodeError, TypeError):
                            # Handle single data source strings
                            data_sources.add(data_source_data)

                # Return sorted list of data sources
                return sorted(list(data_sources)) if data_sources else [
                    'Process monitoring', 'File monitoring', 'Network traffic',
                    'Windows event logs', 'Authentication logs'
                ]

        except Exception as e:
            self.logger.error(f"Error getting data sources: {e}")
            # Fallback to common data sources
            return [
                'Process monitoring', 'File monitoring', 'Network traffic',
                'Windows event logs', 'Authentication logs', 'DNS records'
            ]
    
    # Additional helper methods would be implemented here...
    # Due to length constraints, I'm showing the structure and key methods
    
    def _get_framework_stats(self, framework: str) -> Dict[str, int]:
        """Get framework statistics from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get technique counts
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques WHERE technique_id NOT LIKE '%.%'")
                techniques_count = cursor.fetchone()[0]

                # Get sub-technique counts
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques WHERE technique_id LIKE '%.%'")
                sub_techniques_count = cursor.fetchone()[0]

                # Get unique tactics count
                cursor.execute("SELECT COUNT(DISTINCT tactic) FROM mitre_techniques WHERE tactic IS NOT NULL")
                tactics_count = cursor.fetchone()[0]

                # Get unique data sources count
                cursor.execute("SELECT COUNT(DISTINCT data_sources) FROM mitre_techniques WHERE data_sources IS NOT NULL")
                data_sources_count = cursor.fetchone()[0]

                return {
                    'techniques': techniques_count,
                    'tactics': tactics_count,
                    'sub_techniques': sub_techniques_count,
                    'data_sources': data_sources_count
                }

        except Exception as e:
            self.logger.error(f"Error getting framework stats: {e}")
            return {
                'techniques': 0,
                'tactics': 0,
                'sub_techniques': 0,
                'data_sources': 0
            }
    
    def _get_techniques(self, framework: str, tactic: str, platforms: List[str], data_sources: List[str]) -> List[Dict]:
        """Get filtered techniques"""
        filters = {}

        # Add framework filter
        if framework and framework.lower() != 'both':
            filters['framework'] = framework.lower()

        # Add tactic filter
        if tactic and tactic != 'All':
            filters['tactic'] = tactic

        # Add platform filter
        if platforms:
            filters['platforms'] = platforms

        # Add data source filter
        if data_sources:
            filters['data_sources'] = data_sources

        return self.db_manager.get_mitre_techniques(filters)
    
    def _get_related_sigma_rules(self, technique_id: str) -> List[Dict]:
        """Get SIGMA rules related to a technique"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT sr.* FROM sigma_rules sr
                    JOIN rule_technique_mappings rtm ON sr.rule_id = rtm.rule_id
                    WHERE rtm.technique_id = ?
                """, (technique_id,))

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting related rules: {e}")
            return []

    # Additional helper methods for UI components
    def _get_recent_updates(self) -> List[Dict]:
        """Get recent MITRE data updates"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # First try to get from activity log for MITRE updates
                cursor.execute("""
                    SELECT action as description, timestamp as date, details
                    FROM activity_log
                    WHERE action LIKE '%MITRE%' OR action LIKE '%mitre%'
                    ORDER BY timestamp DESC
                    LIMIT 5
                """)

                activity_updates = [dict(row) for row in cursor.fetchall()]

                # If no activity log entries, get recent technique updates
                if not activity_updates:
                    cursor.execute("""
                        SELECT
                            ('Updated technique: ' || name) as description,
                            updated_at as date,
                            technique_id
                        FROM mitre_techniques
                        ORDER BY updated_at DESC
                        LIMIT 5
                    """)

                    technique_updates = [dict(row) for row in cursor.fetchall()]
                    return technique_updates

                return activity_updates

        except Exception as e:
            self.logger.error(f"Error getting recent updates: {e}")
            return []

    def _get_matrix_data(self, framework: str, include_sub_techniques: bool = False) -> Optional[Dict]:
        """Get matrix data for visualization"""
        try:
            # Apply framework filter
            filters = {}
            if framework and framework.lower() != 'both':
                filters['framework'] = framework.lower()

            techniques = self.db_manager.get_mitre_techniques(filters)
            if not techniques:
                return None

            # Organize techniques by tactic with enhanced data
            matrix_data = {}
            for technique in techniques:
                tactic = technique.get('tactic', 'Unknown')
                technique_id = technique.get('technique_id', '') or ''

                # Filter sub-techniques if not requested
                if not include_sub_techniques and '.' in technique_id:
                    continue

                if tactic not in matrix_data:
                    matrix_data[tactic] = []

                # Enhance technique data with rule coverage
                enhanced_technique = dict(technique)
                rule_count = self._get_technique_rule_count(technique_id)
                enhanced_technique['rule_count'] = rule_count
                enhanced_technique['coverage_level'] = self._get_coverage_level(rule_count)

                matrix_data[tactic].append(enhanced_technique)

            return matrix_data
        except Exception as e:
            self.logger.error(f"Error getting matrix data: {e}")
            return None

    def _create_matrix_visualization(self, matrix_data: Dict) -> Any:
        """Create matrix visualization"""
        try:
            import plotly.graph_objects as go

            # Create a simple heatmap representation
            tactics = list(matrix_data.keys())
            technique_counts = [len(matrix_data[tactic]) for tactic in tactics]

            fig = go.Figure(data=go.Bar(
                x=tactics,
                y=technique_counts,
                text=technique_counts,
                textposition='auto',
            ))

            fig.update_layout(
                title="MITRE ATT&CK Techniques by Tactic",
                xaxis_title="Tactics",
                yaxis_title="Number of Techniques",
                height=400
            )

            return fig
        except Exception as e:
            self.logger.error(f"Error creating matrix visualization: {e}")
            return None

    def _create_matrix_heatmap(self, matrix_data: Dict, color_by: str = "Rule Coverage") -> Any:
        """Create proper MITRE ATT&CK matrix heatmap"""
        try:
            import plotly.graph_objects as go
            import plotly.express as px

            if not matrix_data:
                self.logger.error("No matrix data provided")
                return None

            # Prepare data for heatmap - organize by tactic columns
            tactics = sorted(list(matrix_data.keys()))

            # Create a more efficient matrix structure
            # Each tactic will be a column, techniques will be rows within each tactic
            tactic_technique_map = {}
            max_techniques_per_tactic = 0

            for tactic in tactics:
                techniques = matrix_data.get(tactic, [])
                if not techniques:
                    continue

                # Sort techniques by ID, handling None values safely
                try:
                    # Filter out any techniques with None or empty technique_id first
                    valid_techniques = []
                    for t in techniques:
                        tech_id = t.get('technique_id')
                        if tech_id is not None and str(tech_id).strip():
                            valid_techniques.append(t)

                    # Sort the valid techniques
                    valid_techniques.sort(key=lambda x: str(x.get('technique_id', '')))
                    techniques = valid_techniques

                except Exception as sort_error:
                    self.logger.warning(f"Error sorting techniques for tactic {tactic}: {sort_error}")
                    # Fallback: create a minimal valid list
                    techniques = [t for t in techniques if t.get('technique_id') is not None]

                tactic_technique_map[tactic] = techniques
                max_techniques_per_tactic = max(max_techniques_per_tactic, len(techniques))

            # Create matrix data
            z_values = []
            hover_text = []
            y_labels = []

            # Create rows for the matrix (one row per technique position)
            for row_idx in range(max_techniques_per_tactic):
                row_values = []
                row_hover = []

                for tactic in tactics:
                    techniques = tactic_technique_map[tactic]

                    if row_idx < len(techniques):
                        technique = techniques[row_idx]
                        technique_id = str(technique.get('technique_id', '') or '')
                        technique_name = str(technique.get('name', 'Unknown') or 'Unknown')

                        if color_by == "Rule Coverage":
                            rule_count = int(technique.get('rule_count', 0) or 0)
                            # Map rule count to color values for better visualization
                            if rule_count >= 100:
                                color_val = 4  # Very high coverage - Dark Green
                            elif rule_count >= 10:
                                color_val = 3  # High coverage - Green
                            elif rule_count >= 1:
                                color_val = 2  # Medium coverage - Orange
                            else:
                                color_val = 1  # No coverage - Red

                            # Debug: Log some actual values to see what's happening
                            if technique_id in ['T1059', 'T1218', 'T1003', 'T1190', 'T1027']:
                                print(f"DEBUG: {technique_id} -> rules={rule_count}, color_val={color_val}")
                        else:
                            color_val = 2  # Default value for other color schemes

                        hover_info = f"<b>{technique_id}</b><br>{technique_name}<br>Tactic: {tactic}<br>Rules: {int(technique.get('rule_count', 0) or 0)}"
                    else:
                        color_val = 0  # Empty cell - will be gray
                        hover_info = ""

                    row_values.append(color_val)
                    row_hover.append(hover_info)

                z_values.append(row_values)
                hover_text.append(row_hover)
                y_labels.append(f"T{row_idx + 1}")  # Generic row labels

            # Debug: Show some sample z_values to verify color mapping
            if z_values:
                sample_values = []
                for row in z_values[:3]:  # First 3 rows
                    sample_values.extend(row[:5])  # First 5 values per row
                unique_values = sorted(set(sample_values))
                self.logger.info(f"Matrix color values found: {unique_values}")

            # Create custom color scale for rule coverage
            if color_by == "Rule Coverage":
                # Custom discrete color scale with more distinct colors
                custom_colorscale = [
                    [0.0, '#E0E0E0'],    # Gray for empty cells (value 0)
                    [0.2, '#E0E0E0'],    # Gray for empty cells
                    [0.2, '#FF4444'],    # Red for no coverage (value 1)
                    [0.4, '#FF4444'],    # Red for no coverage
                    [0.4, '#FFAA00'],    # Orange for low coverage (value 2)
                    [0.6, '#FFAA00'],    # Orange for low coverage
                    [0.6, '#44AA44'],    # Green for medium coverage (value 3)
                    [0.8, '#44AA44'],    # Green for medium coverage
                    [0.8, '#006600'],    # Dark Green for high coverage (value 4)
                    [1.0, '#006600']     # Dark Green for high coverage
                ]
                colorbar_title = "Rule Coverage"
                zmin, zmax = 0, 4
            else:
                custom_colorscale = 'Viridis'
                colorbar_title = "Value"
                zmin, zmax = 0, 4

            # Create heatmap
            fig = go.Figure(data=go.Heatmap(
                z=z_values,
                x=tactics,
                y=y_labels,
                hovertemplate='%{hovertext}<extra></extra>',
                hovertext=hover_text,
                colorscale=custom_colorscale,
                showscale=True,
                colorbar=dict(
                    title=colorbar_title,
                    titleside="right",
                    tickmode='array',
                    tickvals=[0, 1, 2, 3, 4] if color_by == "Rule Coverage" else None,
                    ticktext=['Empty', 'No Rules', '1-9 Rules', '10-99 Rules', '100+ Rules'] if color_by == "Rule Coverage" else None
                ),
                zmin=zmin,
                zmax=zmax
            ))

            fig.update_layout(
                title=f"MITRE ATT&CK Matrix - {color_by}",
                xaxis_title="Tactics",
                yaxis_title="Technique Positions",
                height=max(400, max_techniques_per_tactic * 30),
                xaxis=dict(side="top"),
                yaxis=dict(autorange="reversed"),
                margin=dict(l=100, r=100, t=100, b=50)
            )

            return fig

        except Exception as e:
            self.logger.error(f"Error creating matrix heatmap: {e}")
            return None

    def _create_simple_fallback_chart(self, matrix_data: Dict) -> Any:
        """Create a simple fallback chart when heatmap fails"""
        try:
            import plotly.graph_objects as go

            # Create a simple bar chart showing technique counts per tactic
            tactics = list(matrix_data.keys())
            technique_counts = [len(matrix_data[tactic]) for tactic in tactics]

            fig = go.Figure(data=go.Bar(
                x=tactics,
                y=technique_counts,
                text=technique_counts,
                textposition='auto',
                marker_color='lightblue'
            ))

            fig.update_layout(
                title="MITRE ATT&CK Techniques by Tactic (Simplified View)",
                xaxis_title="Tactics",
                yaxis_title="Number of Techniques",
                height=400,
                xaxis_tickangle=-45
            )

            return fig

        except Exception as e:
            self.logger.error(f"Error creating fallback chart: {e}")
            return None



    def _render_coverage_dashboard(self, matrix_data: Dict, color_by: str):
        """Render a comprehensive coverage dashboard"""
        try:
            st.markdown("### 🎯 MITRE ATT&CK Coverage Dashboard")

            # Calculate coverage statistics
            coverage_stats = self._calculate_detailed_coverage_stats(matrix_data)

            # Top metrics row
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "🎯 Total Techniques",
                    coverage_stats['total_techniques'],
                    delta=f"{coverage_stats['coverage_percentage']:.1f}% covered"
                )

            with col2:
                st.metric(
                    "🟢 Well Covered",
                    coverage_stats['high_coverage'],
                    delta=f"{coverage_stats['high_coverage_pct']:.1f}%"
                )

            with col3:
                st.metric(
                    "🟡 Partially Covered",
                    coverage_stats['medium_coverage'],
                    delta=f"{coverage_stats['medium_coverage_pct']:.1f}%"
                )

            with col4:
                st.metric(
                    "🔴 No Coverage",
                    coverage_stats['no_coverage'],
                    delta=f"{coverage_stats['no_coverage_pct']:.1f}%"
                )

            # Visualization row
            col1, col2 = st.columns(2)

            with col1:
                # Tactic coverage bar chart
                fig1 = self._create_tactic_coverage_chart(matrix_data)
                if fig1:
                    st.plotly_chart(fig1, use_container_width=True, key="tactic_coverage")

            with col2:
                # Coverage distribution pie chart
                fig2 = self._create_coverage_distribution_pie(coverage_stats)
                if fig2:
                    st.plotly_chart(fig2, use_container_width=True, key="coverage_pie")

            # Detailed tactic breakdown
            st.markdown("### 📊 Detailed Tactic Breakdown")
            self._render_tactic_breakdown_table(matrix_data)

        except Exception as e:
            st.error(f"Error rendering coverage dashboard: {e}")
            self.logger.error(f"Dashboard error: {e}")

    def _calculate_detailed_coverage_stats(self, matrix_data: Dict) -> Dict:
        """Calculate detailed coverage statistics - USES CENTRALIZED METHOD"""
        return self.db_manager.calculate_detailed_coverage_stats(matrix_data)

    def _create_tactic_coverage_chart(self, matrix_data: Dict) -> Any:
        """Create tactic coverage bar chart"""
        try:
            import plotly.express as px

            # Prepare data for chart
            tactic_data = []
            for tactic, techniques in matrix_data.items():
                high_count = sum(1 for t in techniques if t.get('rule_count', 0) >= 10)
                medium_count = sum(1 for t in techniques if 1 <= t.get('rule_count', 0) < 10)
                no_count = sum(1 for t in techniques if t.get('rule_count', 0) == 0)

                tactic_data.append({
                    'Tactic': tactic,
                    'High Coverage (10+ rules)': high_count,
                    'Medium Coverage (1-9 rules)': medium_count,
                    'No Coverage (0 rules)': no_count
                })

            # Create DataFrame
            df = pd.DataFrame(tactic_data)

            # Create stacked bar chart
            fig = px.bar(
                df,
                x='Tactic',
                y=['High Coverage (10+ rules)', 'Medium Coverage (1-9 rules)', 'No Coverage (0 rules)'],
                title="SIGMA Rule Coverage by Tactic",
                color_discrete_map={
                    'High Coverage (10+ rules)': '#44AA44',
                    'Medium Coverage (1-9 rules)': '#FFAA00',
                    'No Coverage (0 rules)': '#FF4444'
                }
            )

            fig.update_layout(
                xaxis_tickangle=-45,
                height=400,
                yaxis_title="Number of Techniques"
            )

            return fig

        except Exception as e:
            self.logger.error(f"Error creating tactic coverage chart: {e}")
            return None

    def _create_coverage_distribution_pie(self, coverage_stats: Dict) -> Any:
        """Create coverage distribution pie chart"""
        try:
            import plotly.express as px

            # Prepare data
            labels = ['High Coverage (10+ rules)', 'Medium Coverage (1-9 rules)', 'No Coverage (0 rules)']
            values = [
                coverage_stats.get('high_coverage', 0),
                coverage_stats.get('medium_coverage', 0),
                coverage_stats.get('no_coverage', 0)
            ]
            colors = ['#44AA44', '#FFAA00', '#FF4444']

            fig = px.pie(
                values=values,
                names=labels,
                title="Overall SIGMA Rule Coverage Distribution",
                color_discrete_sequence=colors
            )

            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)

            return fig

        except Exception as e:
            self.logger.error(f"Error creating coverage pie chart: {e}")
            return None

    def _render_tactic_breakdown_table(self, matrix_data: Dict):
        """Render detailed tactic breakdown table"""
        try:
            # Prepare table data
            table_data = []
            for tactic, techniques in matrix_data.items():
                total_techniques = len(techniques)
                high_coverage = sum(1 for t in techniques if t.get('rule_count', 0) >= 10)
                medium_coverage = sum(1 for t in techniques if 1 <= t.get('rule_count', 0) < 10)
                no_coverage = sum(1 for t in techniques if t.get('rule_count', 0) == 0)

                coverage_pct = ((high_coverage + medium_coverage) / total_techniques * 100) if total_techniques > 0 else 0

                table_data.append({
                    'Tactic': tactic,
                    'Total Techniques': total_techniques,
                    'High Coverage': high_coverage,
                    'Medium Coverage': medium_coverage,
                    'No Coverage': no_coverage,
                    'Coverage %': f"{coverage_pct:.1f}%"
                })

            # Create DataFrame and display
            df = pd.DataFrame(table_data)
            df = df.sort_values('Coverage %', ascending=False)

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Coverage %": st.column_config.ProgressColumn(
                        "Coverage %",
                        help="Percentage of techniques with SIGMA rules",
                        format="%.1f%%",
                        min_value=0,
                        max_value=100,
                    ),
                }
            )

        except Exception as e:
            st.error(f"Error creating tactic breakdown table: {e}")
            self.logger.error(f"Table error: {e}")



    def _create_technique_network(self, matrix_data: Dict, color_by: str) -> Any:
        """Create technique network visualization as bubble chart"""
        try:
            import plotly.express as px

            # Prepare data for bubble chart
            data = []
            tactic_positions = {tactic: i for i, tactic in enumerate(matrix_data.keys())}

            for tactic, techniques in matrix_data.items():
                for technique in techniques:
                    rule_count = technique.get('rule_count', 0)
                    technique_id = technique.get('technique_id', '')
                    technique_name = technique.get('name', 'Unknown')

                    # Determine coverage category for color
                    if rule_count >= 10:
                        coverage_category = "High Coverage (10+ rules)"
                        color_val = "#44AA44"  # Green
                    elif rule_count >= 1:
                        coverage_category = "Medium Coverage (1-9 rules)"
                        color_val = "#FFAA00"  # Orange
                    else:
                        coverage_category = "No Coverage (0 rules)"
                        color_val = "#FF4444"  # Red

                    data.append({
                        'Tactic': tactic,
                        'Technique ID': technique_id,
                        'Technique Name': technique_name[:40] + "..." if len(technique_name) > 40 else technique_name,
                        'Rule Count': rule_count,
                        'Coverage Category': coverage_category,
                        'Tactic Position': tactic_positions[tactic],
                        'Bubble Size': max(10, min(100, rule_count * 2))  # Size for bubble
                    })

            df = pd.DataFrame(data)

            # Create bubble chart
            fig = px.scatter(
                df,
                x='Tactic Position',
                y='Rule Count',
                size='Bubble Size',
                color='Coverage Category',
                hover_data=['Technique ID', 'Technique Name'],
                title="MITRE ATT&CK Techniques by Rule Coverage",
                color_discrete_map={
                    'High Coverage (10+ rules)': '#44AA44',
                    'Medium Coverage (1-9 rules)': '#FFAA00',
                    'No Coverage (0 rules)': '#FF4444'
                }
            )

            # Update layout
            fig.update_layout(
                xaxis=dict(
                    title="Tactics",
                    tickmode='array',
                    tickvals=list(tactic_positions.values()),
                    ticktext=list(tactic_positions.keys()),
                    tickangle=-45
                ),
                yaxis_title="Number of SIGMA Rules",
                height=600,
                showlegend=True
            )

            # Update hover template
            fig.update_traces(
                hovertemplate='<b>%{customdata[0]}</b><br>' +
                             '%{customdata[1]}<br>' +
                             'Rules: %{y}<br>' +
                             'Tactic: %{customdata[2]}<extra></extra>',
                customdata=df[['Technique ID', 'Technique Name', 'Tactic']].values
            )

            return fig

        except Exception as e:
            self.logger.error(f"Error creating technique network: {e}")
            return None

    def _get_technique_rule_count(self, technique_id: str) -> int:
        """Get count of SIGMA rules for a technique"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM rule_technique_mappings
                    WHERE technique_id = ?
                """, (technique_id,))
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting technique rule count: {e}")
            return 0

    def _get_coverage_level(self, rule_count: int) -> str:
        """Get coverage level based on rule count"""
        if rule_count >= 3:
            return "high"
        elif rule_count >= 1:
            return "medium"
        else:
            return "low"

    def _calculate_matrix_coverage(self, matrix_data: Dict) -> Dict:
        """Calculate coverage statistics for matrix - USES CENTRALIZED METHOD"""
        try:
            total_techniques = 0
            covered_techniques = 0

            for techniques in matrix_data.values():
                for technique in techniques:
                    total_techniques += 1
                    if technique.get('rule_count', 0) > 0:
                        covered_techniques += 1

            coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0

            return {
                'total_techniques': total_techniques,
                'covered_techniques': covered_techniques,
                'coverage_percentage': coverage_percentage
            }
        except Exception as e:
            self.logger.error(f"Error calculating matrix coverage: {e}")
            return {}

    def _get_enhanced_analytics_data(self, framework: str) -> Dict:
        """Get enhanced analytics data including detection and mitigation coverage"""
        try:
            # Apply framework filter
            filters = {}
            if framework and framework.lower() != 'both':
                filters['framework'] = framework.lower()

            techniques = self.db_manager.get_mitre_techniques(filters)
            total_techniques = len(techniques)

            # Count techniques by tactic
            tactic_counts = {}
            platform_counts = {}

            # Enhanced data quality metrics
            with_detection = 0
            with_mitigation = 0
            with_both = 0

            for technique in techniques:
                tactic = technique.get('tactic', 'Unknown')
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

                # Handle platform field - could be list or JSON string
                platform_data = technique.get('platform', [])
                if isinstance(platform_data, str):
                    try:
                        platforms = json.loads(platform_data) if platform_data else []
                    except (json.JSONDecodeError, TypeError):
                        platforms = []
                elif isinstance(platform_data, list):
                    platforms = platform_data
                else:
                    platforms = []

                for platform in platforms:
                    platform_counts[platform] = platform_counts.get(platform, 0) + 1

                # Check for enhanced data
                has_detection = bool(technique.get('detection', '').strip())
                has_mitigation = bool(technique.get('mitigation', '').strip())

                if has_detection:
                    with_detection += 1
                if has_mitigation:
                    with_mitigation += 1
                if has_detection and has_mitigation:
                    with_both += 1

            return {
                'total_techniques': total_techniques,
                'tactic_distribution': tactic_counts,
                'platform_distribution': platform_counts,
                'detection_coverage': {
                    'count': with_detection,
                    'percentage': (with_detection / total_techniques * 100) if total_techniques > 0 else 0
                },
                'mitigation_coverage': {
                    'count': with_mitigation,
                    'percentage': (with_mitigation / total_techniques * 100) if total_techniques > 0 else 0
                },
                'complete_coverage': {
                    'count': with_both,
                    'percentage': (with_both / total_techniques * 100) if total_techniques > 0 else 0
                },
                'data_quality': {
                    'detection_quality': {
                        'with_detection': with_detection,
                        'without_detection': total_techniques - with_detection
                    },
                    'mitigation_quality': {
                        'with_mitigation': with_mitigation,
                        'without_mitigation': total_techniques - with_mitigation
                    }
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting enhanced analytics data: {e}")
            return {}

    def _get_analytics_data(self, framework: str) -> Dict:
        """Get analytics data for framework (legacy method)"""
        return self._get_enhanced_analytics_data(framework)

    def _get_enhanced_coverage_analysis(self, framework: str) -> Dict:
        """Get enhanced SIGMA rule coverage analysis with confidence metrics"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Count techniques with rules
                cursor.execute("""
                    SELECT COUNT(DISTINCT rtm.technique_id)
                    FROM rule_technique_mappings rtm
                    JOIN mitre_techniques mt ON rtm.technique_id = mt.technique_id
                """)
                covered_techniques = cursor.fetchone()[0]

                # Count total techniques
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                total_techniques = cursor.fetchone()[0]

                # Count total rules
                cursor.execute("SELECT COUNT(*) FROM sigma_rules")
                total_rules = cursor.fetchone()[0]

                # Count high-confidence mappings
                cursor.execute("""
                    SELECT COUNT(DISTINCT rtm.technique_id)
                    FROM rule_technique_mappings rtm
                    WHERE rtm.confidence >= 1.0
                """)
                high_confidence_mappings = cursor.fetchone()[0]

                # Get enhanced coverage matrix with detection/mitigation data
                cursor.execute("""
                    SELECT
                        mt.tactic,
                        COUNT(*) as total_techniques,
                        COUNT(CASE WHEN rtm.technique_id IS NOT NULL THEN 1 END) as covered_techniques,
                        COUNT(CASE WHEN mt.detection IS NOT NULL AND mt.detection != '' THEN 1 END) as with_detection,
                        COUNT(CASE WHEN mt.mitigation IS NOT NULL AND mt.mitigation != '' THEN 1 END) as with_mitigation,
                        AVG(CASE WHEN rtm.confidence IS NOT NULL THEN rtm.confidence ELSE 0 END) as avg_confidence
                    FROM mitre_techniques mt
                    LEFT JOIN rule_technique_mappings rtm ON mt.technique_id = rtm.technique_id
                    GROUP BY mt.tactic
                    ORDER BY mt.tactic
                """)

                enhanced_coverage_matrix = {}
                for row in cursor.fetchall():
                    tactic, total, covered, with_detection, with_mitigation, avg_confidence = row
                    enhanced_coverage_matrix[tactic] = {
                        'total_techniques': total,
                        'covered_techniques': covered,
                        'with_detection': with_detection,
                        'with_mitigation': with_mitigation,
                        'coverage_percentage': (covered / total * 100) if total > 0 else 0,
                        'detection_percentage': (with_detection / total * 100) if total > 0 else 0,
                        'mitigation_percentage': (with_mitigation / total * 100) if total > 0 else 0,
                        'avg_confidence': avg_confidence or 0
                    }

                coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0
                avg_rules_per_technique = (total_rules / covered_techniques) if covered_techniques > 0 else 0
                high_confidence_percentage = (high_confidence_mappings / covered_techniques * 100) if covered_techniques > 0 else 0

                return {
                    'covered_techniques': covered_techniques,
                    'total_techniques': total_techniques,
                    'total_rules': total_rules,
                    'coverage_percentage': coverage_percentage,
                    'avg_rules_per_technique': avg_rules_per_technique,
                    'high_confidence_mappings': high_confidence_mappings,
                    'high_confidence_percentage': high_confidence_percentage,
                    'enhanced_coverage_matrix': enhanced_coverage_matrix
                }
        except Exception as e:
            self.logger.error(f"Error getting enhanced coverage analysis: {e}")
            return {}

    def _get_coverage_analysis(self, framework: str) -> Dict:
        """Get SIGMA rule coverage analysis (legacy method)"""
        return self._get_enhanced_coverage_analysis(framework)

    def _create_coverage_heatmap(self, coverage_matrix: Dict) -> Any:
        """Create coverage heatmap from actual data"""
        try:
            import plotly.graph_objects as go

            # Use the existing matrix heatmap implementation
            matrix_data = self._get_matrix_data('enterprise', include_sub_techniques=False)
            if matrix_data:
                return self._create_matrix_heatmap(matrix_data, "Rule Coverage")
            else:
                # Fallback to simple chart if no data
                return self._create_simple_fallback_chart({})

        except Exception as e:
            self.logger.error(f"Error creating coverage heatmap: {e}")
            return None

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name by ID"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
                result = cursor.fetchone()
                return result[0] if result else technique_id
        except Exception as e:
            self.logger.error(f"Error getting technique name: {e}")
            return technique_id

    def _get_rule_title(self, rule_id: str) -> str:
        """Get rule title by ID"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT title FROM sigma_rules WHERE rule_id = ?", (rule_id,))
                result = cursor.fetchone()
                return result[0] if result else rule_id
        except Exception as e:
            self.logger.error(f"Error getting rule title: {e}")
            return rule_id

    def _get_rule_mappings(self, framework: str, tactic: str) -> List[Dict]:
        """Get rule-technique mappings for framework and tactic"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                query = """
                    SELECT rtm.rule_id, rtm.technique_id, rtm.confidence,
                           sr.title as rule_title, mt.name as technique_name
                    FROM rule_technique_mappings rtm
                    JOIN sigma_rules sr ON rtm.rule_id = sr.rule_id
                    JOIN mitre_techniques mt ON rtm.technique_id = mt.technique_id
                    WHERE 1=1
                """
                params = []

                if framework and framework.lower() != 'both':
                    query += " AND mt.framework = ?"
                    params.append(framework.lower())

                if tactic and tactic != 'All':
                    query += " AND mt.tactic = ?"
                    params.append(tactic)

                query += " ORDER BY rtm.confidence DESC, mt.technique_id"

                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting rule mappings: {e}")
            return []

    def _create_enhanced_coverage_heatmap(self, coverage_matrix: Dict) -> go.Figure:
        """Create enhanced coverage heatmap with detection and mitigation data"""
        try:
            tactics = list(coverage_matrix.keys())

            # Prepare data for multiple metrics
            coverage_data = [coverage_matrix[tactic]['coverage_percentage'] for tactic in tactics]
            detection_data = [coverage_matrix[tactic]['detection_percentage'] for tactic in tactics]
            mitigation_data = [coverage_matrix[tactic]['mitigation_percentage'] for tactic in tactics]
            confidence_data = [coverage_matrix[tactic]['avg_confidence'] * 100 for tactic in tactics]

            # Create subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=('SIGMA Rule Coverage', 'Detection Info Coverage',
                              'Mitigation Info Coverage', 'Mapping Confidence'),
                specs=[[{"type": "bar"}, {"type": "bar"}],
                       [{"type": "bar"}, {"type": "bar"}]]
            )

            # Add coverage bars
            fig.add_trace(
                go.Bar(x=tactics, y=coverage_data, name="Rule Coverage",
                      marker_color='#4CAF50', showlegend=False),
                row=1, col=1
            )

            fig.add_trace(
                go.Bar(x=tactics, y=detection_data, name="Detection Coverage",
                      marker_color='#2196F3', showlegend=False),
                row=1, col=2
            )

            fig.add_trace(
                go.Bar(x=tactics, y=mitigation_data, name="Mitigation Coverage",
                      marker_color='#FF9800', showlegend=False),
                row=2, col=1
            )

            fig.add_trace(
                go.Bar(x=tactics, y=confidence_data, name="Mapping Confidence",
                      marker_color='#9C27B0', showlegend=False),
                row=2, col=2
            )

            # Update layout
            fig.update_layout(
                title="Enhanced MITRE ATT&CK Coverage Analysis",
                height=600,
                showlegend=False
            )

            # Update y-axes to show percentages
            for i in range(1, 3):
                for j in range(1, 3):
                    fig.update_yaxes(title_text="Percentage (%)", range=[0, 100], row=i, col=j)

            # Rotate x-axis labels
            fig.update_xaxes(tickangle=-45)

            return fig

        except Exception as e:
            self.logger.error(f"Error creating enhanced coverage heatmap: {e}")
            return go.Figure()

    def _show_related_rules(self, rules: List[Dict]):
        """Legacy method - now handled by modal display"""
        # This method is no longer used but kept for compatibility
        pass

    def _render_related_rules_modal(self):
        """Render the related rules modal"""
        try:
            rules_data = st.session_state.viewing_related_rules
            technique_id = rules_data['technique_id']
            technique_name = rules_data['technique_name']
            rules = rules_data['rules']

            # Modal header
            st.markdown("---")
            st.markdown(f"## 📋 Related SIGMA Rules for {technique_id}")
            st.markdown(f"**Technique:** {technique_name}")

            # Close button
            col1, col2 = st.columns([4, 1])
            with col2:
                if st.button("❌ Close", key="close_related_rules"):
                    st.session_state.viewing_related_rules = None
                    st.rerun()

            # Display rules
            if rules:
                st.markdown(f"Found **{len(rules)}** related SIGMA rules:")

                for i, rule in enumerate(rules):
                    with st.expander(f"**{i+1}.** {rule.get('title', 'Unknown Rule')} ({rule.get('rule_id', 'No ID')})"):
                        col1, col2 = st.columns([2, 1])

                        with col1:
                            st.markdown(f"**Description:** {rule.get('description', 'No description')[:300]}...")
                            st.markdown(f"**Level:** {rule.get('level', 'Unknown')}")
                            st.markdown(f"**Status:** {rule.get('status', 'Unknown')}")
                            st.markdown(f"**Author:** {rule.get('author', 'Unknown')}")

                            # Tags
                            if rule.get('tags'):
                                tags = json.loads(rule['tags']) if isinstance(rule['tags'], str) else rule['tags']
                                tag_display = " ".join([f"`{tag}`" for tag in tags[:5]])
                                if len(tags) > 5:
                                    tag_display += f" +{len(tags) - 5} more"
                                st.markdown(f"**Tags:** {tag_display}")

                        with col2:
                            # Action buttons
                            if st.button(f"👁️ View Full Rule", key=f"view_full_{rule.get('rule_id')}"):
                                # Navigate to search engine with this rule
                                st.session_state.viewing_rule_details = rule
                                st.session_state.current_page = "🔍 Detection Search Engine"
                                st.success("✅ Opening rule in Detection Search Engine...")
                                st.rerun()

                            if st.button(f"✏️ Edit Rule", key=f"edit_rule_{rule.get('rule_id')}"):
                                # Navigate to rule builder with this rule
                                st.session_state.edit_rule_data = rule
                                st.session_state.current_page = "📝 SIGMA Rule Builder"
                                st.success("✅ Opening rule in SIGMA Rule Builder...")
                                st.rerun()

                            # Show rule metadata
                            st.markdown(f"**Date:** {rule.get('date', 'Unknown')}")
                            st.markdown(f"**Source:** {rule.get('source_repo', 'Unknown')}")
                            if rule.get('is_custom'):
                                st.markdown("🏷️ **Custom Rule**")
            else:
                st.info("No related SIGMA rules found for this technique.")

        except Exception as e:
            self.logger.error(f"Error rendering related rules modal: {e}")
            st.error(f"Error displaying related rules: {str(e)}")
            # Clear the session state on error
            st.session_state.viewing_related_rules = None
