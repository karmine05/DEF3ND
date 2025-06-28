"""
Attack Path Mapper Component
Provides attack path visualization and mapping using MITRE ATT&CK and SIGMA rules
"""

import streamlit as st
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import json
from typing import Dict, List, Optional, Any, Tuple
import logging
from streamlit_agraph import agraph, Node, Edge, Config

class AttackMapper:
    """Attack path mapping and visualization component"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # MITRE ATT&CK tactic order for attack path visualization
        self.tactic_order = [
            'initial-access',
            'execution',
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'collection',
            'command-and-control',
            'exfiltration',
            'impact'
        ]

        # Mapping between display format and database format
        self.tactic_db_mapping = {
            'initial-access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'privilege-escalation': 'Privilege Escalation',
            'defense-evasion': 'Defense Evasion',
            'credential-access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral-movement': 'Lateral Movement',
            'collection': 'Collection',
            'command-and-control': 'Command and Control',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        }

        # Reverse mapping for database to display format
        self.db_tactic_mapping = {v: k for k, v in self.tactic_db_mapping.items()}
        
        # Enhanced color scheme for different elements
        self.colors = {
            'tactic': '#3f51b5',           # Indigo - for tactics
            'technique': '#ff9800',        # Orange - for techniques
            'rule': '#4caf50',             # Green - for rules
            'custom_rule': '#e91e63',      # Pink - for custom rules
            'high_coverage': '#4caf50',    # Green - excellent coverage
            'medium_coverage': '#ff9800',  # Orange - medium coverage
            'low_coverage': '#f44336',     # Red - poor coverage
            'no_coverage': '#9e9e9e',      # Gray - no coverage
            'center_node': '#e91e63',      # Pink - center node in relationships
            'related_node': '#00bcd4'      # Cyan - related nodes
        }

    def _get_available_platforms(self) -> List[str]:
        """Get available platforms from database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get unique platforms from techniques in database
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
            self.logger.error(f"Error getting available platforms: {e}")
            # Fallback to common platforms
            return ['Windows', 'Linux', 'macOS', 'Cloud', 'Network']

    def _validate_technique_id(self, technique_id: str) -> bool:
        """Validate MITRE ATT&CK technique ID format - USES CENTRALIZED METHOD"""
        return self.db_manager.validate_technique_id(technique_id)

    def _get_technique_suggestions(self, partial_id: str) -> List[Dict]:
        """Get technique suggestions based on partial input"""
        try:
            suggestions = []

            # Search by technique ID prefix
            all_techniques = self.db_manager.get_mitre_techniques()

            for technique in all_techniques:
                tech_id = technique.get('technique_id', '')
                tech_name = technique.get('name', '')

                # Match by ID prefix or name contains
                if (tech_id.startswith(partial_id.upper()) or
                    partial_id.lower() in tech_name.lower()):
                    suggestions.append({
                        'technique_id': tech_id,
                        'name': tech_name,
                        'tactic': technique.get('tactic', 'Unknown')
                    })

            # Sort by relevance (exact ID match first, then alphabetical)
            suggestions.sort(key=lambda x: (
                not x['technique_id'].startswith(partial_id.upper()),
                x['technique_id']
            ))

            return suggestions[:10]  # Return top 10 suggestions

        except Exception as e:
            self.logger.error(f"Error getting technique suggestions: {e}")
            return []
    
    def render(self):
        """Render the attack path mapper interface"""
        # Add custom CSS for better styling
        st.markdown("""
        <style>
        .attack-mapper-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .coverage-good { color: #28a745; font-weight: bold; }
        .coverage-medium { color: #ffc107; font-weight: bold; }
        .coverage-poor { color: #dc3545; font-weight: bold; }
        .technique-card {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<h2 class="sub-header">🗺️ Attack Path Mapper</h2>', unsafe_allow_html=True)
        
        # Main tabs (removed Coverage Analysis as requested)
        tab1, tab2, tab3, tab4 = st.tabs([
            "🎯 Attack Path Builder",
            "✋ Manual Path Builder",
            "🔗 Technique Relationships",
            "📈 Attack Scenarios"
        ])

        with tab1:
            self._render_attack_path_builder()

        with tab2:
            self._render_manual_path_builder()

        with tab3:
            self._render_technique_relationships()

        with tab4:
            self._render_attack_scenarios()
    
    def _render_attack_path_builder(self):
        """Render attack path building interface"""
        st.markdown("### 🎯 Build Attack Path")

        # Database overview metrics
        coverage_metrics = self._get_coverage_metrics()

        # Display database statistics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total SIGMA Rules",
                coverage_metrics.get('total_rules', 0)
            )

        with col2:
            st.metric(
                "MITRE Techniques",
                coverage_metrics.get('total_techniques', 0)
            )

        with col3:
            st.metric(
                "Covered Techniques",
                coverage_metrics.get('covered_techniques', 0)
            )

        with col4:
            st.metric(
                "Overall Coverage",
                f"{coverage_metrics.get('overall_coverage', 0):.1f}%"
            )

        st.markdown("---")

        # Path building controls
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("#### 🔧 Path Configuration")
            
            # Attack scenario selection
            scenario_type = st.selectbox(
                "Attack Scenario",
                [
                    "Custom Path",
                    "APT Campaign",
                    "Ransomware Attack",
                    "Data Exfiltration",
                    "Insider Threat",
                    "Supply Chain Attack"
                ]
            )
            
            # Starting tactic
            start_tactic = st.selectbox(
                "Starting Tactic",
                self.tactic_order,
                index=0
            )
            
            # Target tactics
            target_tactics = st.multiselect(
                "Target Tactics",
                self.tactic_order,
                default=[self.tactic_order[-1]]  # Default to 'impact'
            )
            
            # Path constraints
            with st.expander("🔧 Path Constraints"):
                max_path_length = st.slider("Max Path Length", 3, 12, 8)
                include_sub_techniques = st.checkbox("Include Sub-techniques", value=True)
                prioritize_coverage = st.checkbox("Prioritize Rule Coverage", value=True)
                # Get available platforms from database
                available_platforms = self._get_available_platforms()
                platform_filter = st.multiselect(
                    "Platform Filter",
                    available_platforms,
                    default=[available_platforms[0]] if available_platforms else []
                )
            
            # Generate path button
            if st.button("🗺️ Generate Attack Path", type="primary"):
                with st.spinner("Generating attack path..."):
                    path_data = self._generate_attack_path(
                        scenario_type, start_tactic, target_tactics,
                        max_path_length, include_sub_techniques,
                        prioritize_coverage, platform_filter
                    )
                    
                    st.session_state.attack_path = path_data
                    st.rerun()
        
        with col2:
            st.markdown("#### 🗺️ Attack Path Visualization")

            if 'attack_path' in st.session_state and st.session_state.attack_path:
                # Add full-screen toggle button with enhanced styling
                st.markdown("""
                <style>
                .fullscreen-btn {
                    background: linear-gradient(45deg, #4caf50, #45a049) !important;
                    color: white !important;
                    border: none !important;
                    padding: 8px 16px !important;
                    border-radius: 6px !important;
                    font-weight: bold !important;
                    transition: all 0.3s ease !important;
                    box-shadow: 0 2px 10px rgba(76, 175, 80, 0.3) !important;
                }
                </style>
                """, unsafe_allow_html=True)

                # Full screen button aligned to the right
                col_spacer, col_fullscreen = st.columns([4, 1])
                with col_fullscreen:
                    if st.button("🔍 Full Screen", help="Open visualization in full screen mode (or press F for browser full-screen)", key="main_fullscreen"):
                        st.session_state.show_fullscreen_viz = True
                        st.rerun()

                # Render the attack path graph outside of columns to avoid nesting
                self._render_attack_path_graph(st.session_state.attack_path)

                # Full-screen modal
                if st.session_state.get('show_fullscreen_viz', False):
                    self._render_fullscreen_visualization(st.session_state.attack_path)
            else:
                st.info("👆 Configure and generate an attack path to see the visualization")
        
        # Path analysis
        if 'attack_path' in st.session_state and st.session_state.attack_path:
            st.markdown("---")
            self._render_path_analysis(st.session_state.attack_path)

    def _render_manual_path_builder(self):
        """Render manual attack path builder interface"""
        st.markdown("### ✋ Manual Attack Path Builder")
        st.markdown("Build custom attack paths by manually selecting tactics and techniques step by step.")

        # Initialize manual path in session state
        if 'manual_attack_path' not in st.session_state:
            st.session_state.manual_attack_path = []

        # Path building interface
        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("#### 🔧 Path Builder")

            # Path metadata
            with st.expander("📋 Path Information"):
                path_name = st.text_input(
                    "Path Name",
                    value=st.session_state.get('manual_path_name', ''),
                    placeholder="My Custom Attack Path"
                )
                st.session_state.manual_path_name = path_name

                path_description = st.text_area(
                    "Description",
                    value=st.session_state.get('manual_path_description', ''),
                    placeholder="Describe this attack path..."
                )
                st.session_state.manual_path_description = path_description

            # Step-by-step builder
            st.markdown("#### ➕ Add Path Steps")

            # Step type selection
            step_type = st.radio(
                "Step Type",
                ["Tactic", "Technique"],
                help="Choose whether to add a tactic or specific technique"
            )

            if step_type == "Tactic":
                # Tactic selection
                available_tactics = [t for t in self.tactic_order if t not in st.session_state.manual_attack_path]
                if available_tactics:
                    selected_tactic = st.selectbox(
                        "Select Tactic",
                        available_tactics,
                        format_func=lambda x: x.replace('-', ' ').title()
                    )

                    if st.button("➕ Add Tactic", type="primary"):
                        st.session_state.manual_attack_path.append(selected_tactic)
                        st.rerun()
                else:
                    st.info("All tactics have been added to the path")

            else:  # Technique
                # Platform filter for techniques
                available_platforms = self._get_available_platforms()
                platform_filter = st.multiselect(
                    "Filter by Platform",
                    available_platforms,
                    default=[available_platforms[0]] if available_platforms else []
                )

                # Tactic filter for techniques
                tactic_filter = st.selectbox(
                    "Filter by Tactic",
                    ["All"] + self.tactic_order,
                    format_func=lambda x: x.replace('-', ' ').title() if x != "All" else x
                )

                # Get available techniques
                techniques_by_tactic = self._get_techniques_by_tactic(platform_filter)
                available_techniques = []

                if tactic_filter == "All":
                    for tactic_techniques in techniques_by_tactic.values():
                        available_techniques.extend(tactic_techniques)
                elif tactic_filter in techniques_by_tactic:
                    available_techniques = techniques_by_tactic[tactic_filter]

                if available_techniques:
                    # Technique selection with search
                    technique_search = st.text_input(
                        "Search Techniques",
                        placeholder="Type to search techniques..."
                    )

                    # Filter techniques by search
                    if technique_search:
                        filtered_techniques = [
                            t for t in available_techniques
                            if technique_search.lower() in t.get('name', '').lower() or
                               technique_search.upper() in t.get('technique_id', '')
                        ]
                    else:
                        filtered_techniques = available_techniques[:50]  # Limit to 50 for performance

                    if filtered_techniques:
                        selected_technique = st.selectbox(
                            "Select Technique",
                            filtered_techniques,
                            format_func=lambda x: f"{x.get('technique_id', 'Unknown')}: {x.get('name', 'Unknown')[:50]}..."
                        )

                        # Show technique details
                        if selected_technique:
                            with st.expander("🔍 Technique Details"):
                                st.markdown(f"**ID:** {selected_technique.get('technique_id', 'Unknown')}")
                                st.markdown(f"**Name:** {selected_technique.get('name', 'Unknown')}")
                                st.markdown(f"**Tactic:** {selected_technique.get('tactic', 'Unknown')}")
                                description = selected_technique.get('description', 'No description available')
                                st.markdown(f"**Description:** {description[:200]}...")

                        if st.button("➕ Add Technique", type="primary"):
                            technique_id = selected_technique.get('technique_id')
                            if technique_id not in st.session_state.manual_attack_path:
                                st.session_state.manual_attack_path.append(technique_id)
                                st.rerun()
                            else:
                                st.warning("This technique is already in the path")
                    else:
                        st.info("No techniques found matching your search")
                else:
                    st.info("No techniques available for the selected filters")

            # Path management
            st.markdown("#### 🛠️ Path Management")

            col_clear, col_save = st.columns(2)
            with col_clear:
                if st.button("🗑️ Clear Path"):
                    st.session_state.manual_attack_path = []
                    st.session_state.manual_path_name = ""
                    st.session_state.manual_path_description = ""
                    st.rerun()

            with col_save:
                if st.button("💾 Save Path"):
                    if st.session_state.manual_attack_path and path_name:
                        # Save the manual path (you can implement database storage here)
                        st.success("Path saved successfully!")
                        # Save path to database
                        self._save_custom_attack_path(path_name, st.session_state.manual_attack_path)
                    else:
                        st.error("Please add steps to the path and provide a name")

        with col2:
            st.markdown("#### 🗺️ Current Path")

            if st.session_state.manual_attack_path:
                # Display current path
                self._render_manual_path_display(st.session_state.manual_attack_path)

                # Generate visualization button
                if st.button("🎨 Generate Visualization", type="primary"):
                    # Create path data structure compatible with existing visualization
                    manual_path_data = {
                        'path': st.session_state.manual_attack_path,
                        'coverage': self._get_path_coverage(st.session_state.manual_attack_path),
                        'scenario_type': 'Manual Path',
                        'platforms': [],
                        'name': st.session_state.get('manual_path_name', 'Manual Attack Path'),
                        'description': st.session_state.get('manual_path_description', '')
                    }

                    st.session_state.manual_path_visualization = manual_path_data
                    st.rerun()

                # Show visualization if generated
                if 'manual_path_visualization' in st.session_state:
                    st.markdown("---")
                    st.markdown("#### 🎭 Path Visualization")

                    # Full screen button aligned to the right
                    col_spacer2, col_fullscreen2 = st.columns([4, 1])
                    with col_fullscreen2:
                        if st.button("🔍 Full Screen", key="manual_fullscreen", help="Open visualization in full screen mode (or press F for browser full-screen)"):
                            st.session_state.show_manual_fullscreen_viz = True
                            st.rerun()

                    # Render the attack path graph outside of columns to avoid nesting
                    self._render_attack_path_graph(st.session_state.manual_path_visualization)

                    # Full-screen modal for manual path
                    if st.session_state.get('show_manual_fullscreen_viz', False):
                        self._render_fullscreen_visualization(st.session_state.manual_path_visualization, is_manual=True)
            else:
                st.info("👆 Start building your attack path by adding tactics or techniques")

    def _render_manual_path_display(self, path_steps: List[str]):
        """Display the current manual attack path with step management"""
        st.markdown(f"**Path Steps ({len(path_steps)}):**")

        if not path_steps:
            st.info("No steps added yet")
            return

        # Display each step with controls
        for i, step in enumerate(path_steps):
            col1, col2, col3, col4 = st.columns([0.5, 3, 1, 1])

            with col1:
                st.markdown(f"**{i+1}.**")

            with col2:
                # Determine if step is a tactic or technique
                if step in self.tactic_order:
                    step_type = "Tactic"
                    display_name = step.replace('-', ' ').title()
                    st.markdown(f"🎯 **{step_type}:** {display_name}")
                else:
                    step_type = "Technique"
                    # Get technique info
                    technique_info = self._get_technique_info(step)
                    technique_name = technique_info.get('name', step)
                    st.markdown(f"⚔️ **{step_type}:** {step} - {technique_name[:40]}...")

            with col3:
                # Move up/down buttons
                if i > 0:
                    if st.button("⬆️", key=f"up_{i}", help="Move up"):
                        st.session_state.manual_attack_path[i], st.session_state.manual_attack_path[i-1] = \
                            st.session_state.manual_attack_path[i-1], st.session_state.manual_attack_path[i]
                        st.rerun()

                if i < len(path_steps) - 1:
                    if st.button("⬇️", key=f"down_{i}", help="Move down"):
                        st.session_state.manual_attack_path[i], st.session_state.manual_attack_path[i+1] = \
                            st.session_state.manual_attack_path[i+1], st.session_state.manual_attack_path[i]
                        st.rerun()

            with col4:
                # Remove button
                if st.button("🗑️", key=f"remove_{i}", help="Remove step"):
                    st.session_state.manual_attack_path.pop(i)
                    st.rerun()

        # Path statistics
        st.markdown("---")
        col1, col2, col3 = st.columns(3)

        tactics_count = len([s for s in path_steps if s in self.tactic_order])
        techniques_count = len([s for s in path_steps if s not in self.tactic_order])

        with col1:
            st.metric("Total Steps", len(path_steps))
        with col2:
            st.metric("Tactics", tactics_count)
        with col3:
            st.metric("Techniques", techniques_count)

        # Coverage analysis
        if techniques_count > 0:
            technique_steps = [s for s in path_steps if s not in self.tactic_order]
            coverage_info = self._get_path_coverage(technique_steps)

            if coverage_info:
                st.markdown("#### 📊 Coverage Analysis")
                col1, col2 = st.columns(2)

                # Calculate coverage metrics
                total_rules = 0
                covered_techniques = 0

                for technique_id, coverage_data in coverage_info.items():
                    if coverage_data.get('type') == 'technique':
                        rule_count = coverage_data.get('rule_count', 0)
                        total_rules += rule_count
                        if rule_count > 0:
                            covered_techniques += 1

                with col1:
                    st.metric("SIGMA Rules", total_rules)
                    st.metric("Covered Techniques", f"{covered_techniques}/{techniques_count}")

                with col2:
                    if techniques_count > 0:
                        coverage_percentage = (covered_techniques / techniques_count) * 100
                        st.metric("Coverage", f"{coverage_percentage:.1f}%")

    def _render_technique_relationships(self):
        """Render technique relationship mapping"""
        st.markdown("### 🔗 Technique Relationships")
        
        # Relationship analysis controls
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("#### 🔧 Analysis Configuration")
            
            # Technique selection
            technique_id = st.text_input(
                "Focus Technique",
                placeholder="T1055, T1566.001",
                help="Enter a MITRE ATT&CK technique ID"
            ).upper().strip()  # Normalize input

            # Show technique suggestions if partial input
            if technique_id and len(technique_id) >= 2:
                suggestions = self._get_technique_suggestions(technique_id)
                if suggestions:
                    with st.expander("💡 Technique Suggestions"):
                        for suggestion in suggestions[:5]:  # Show top 5
                            if st.button(f"{suggestion['technique_id']}: {suggestion['name'][:40]}...",
                                       key=f"suggest_{suggestion['technique_id']}"):
                                technique_id = suggestion['technique_id']
                                st.rerun()
            
            # Relationship types
            relationship_types = st.multiselect(
                "Relationship Types",
                [
                    "Prerequisites",
                    "Enables",
                    "Similar Techniques",
                    "Same Tactic",
                    "Shared Data Sources",
                    "Rule Overlaps"
                ],
                default=["Prerequisites", "Enables"]
            )
            
            # Analysis depth
            analysis_depth = st.slider("Analysis Depth", 1, 3, 2)
            
            # Platform filter
            available_platforms = self._get_available_platforms()
            platform_filter = st.multiselect(
                "Platforms",
                available_platforms,
                default=[available_platforms[0]] if available_platforms else []
            )
            
            if st.button("🔗 Analyze Relationships"):
                if technique_id:
                    # Validate technique ID format
                    if not self._validate_technique_id(technique_id):
                        st.error("❌ Invalid technique ID format. Please enter a valid MITRE ATT&CK technique ID (e.g., T1055, T1566.001)")
                    elif not relationship_types:
                        st.error("❌ Please select at least one relationship type to analyze")
                    else:
                        with st.spinner("Analyzing technique relationships..."):
                            relationships = self._analyze_technique_relationships(
                                technique_id, relationship_types, analysis_depth, platform_filter
                            )

                            if 'error' in relationships:
                                st.error(f"❌ Analysis failed: {relationships['error']}")
                            elif not relationships.get('nodes') or len(relationships['nodes']) <= 1:
                                st.warning("⚠️ No relationships found for the specified technique and criteria. Try different relationship types or platforms.")
                            else:
                                st.session_state.technique_relationships = relationships
                                st.success(f"✅ Found {len(relationships['nodes'])-1} related techniques")
                                st.rerun()
                else:
                    st.error("❌ Please enter a technique ID to analyze")
        
        with col2:
            st.markdown("#### 🕸️ Relationship Network")
            
            if 'technique_relationships' in st.session_state:
                self._render_relationship_network(st.session_state.technique_relationships)
            else:
                st.info("👆 Select a technique and analyze relationships to see the network")
        
        # Relationship details
        if 'technique_relationships' in st.session_state:
            st.markdown("---")
            self._render_relationship_details(st.session_state.technique_relationships)
    
    def _render_attack_scenarios(self):
        """Render attack scenarios with custom scenario management"""
        st.markdown("### 📈 Attack Scenarios")

        # Tabs for different scenario views
        tab1, tab2 = st.tabs(["📚 Scenario Library", "➕ Create Custom Scenario"])

        with tab1:
            self._render_scenario_library()

        with tab2:
            self._render_custom_scenario_builder()

    def _render_scenario_library(self):
        """Render the scenario library with both predefined and custom scenarios"""
        # Scenario library
        scenarios = self._get_attack_scenarios()

        # Scenario selection
        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("#### 📚 Scenario Library")

            # Category filter
            all_categories = ["All"] + list(set([s['category'] for s in scenarios]))
            scenario_category = st.selectbox(
                "Category",
                all_categories
            )

            # Filter scenarios by category
            filtered_scenarios = [s for s in scenarios if
                                scenario_category == "All" or s['category'] == scenario_category]

            # Scenario type filter
            scenario_type_filter = st.selectbox(
                "Type",
                ["All", "Predefined", "Custom"]
            )

            if scenario_type_filter == "Predefined":
                filtered_scenarios = [s for s in filtered_scenarios if not s.get('is_custom', False)]
            elif scenario_type_filter == "Custom":
                filtered_scenarios = [s for s in filtered_scenarios if s.get('is_custom', False)]

            # Scenario selection
            if filtered_scenarios:
                selected_scenario = st.selectbox(
                    "Scenario",
                    [s['name'] for s in filtered_scenarios],
                    format_func=lambda x: x
                )

                if selected_scenario:
                    scenario_data = next(s for s in filtered_scenarios if s['name'] == selected_scenario)

                    # Scenario details
                    with st.expander("📋 Scenario Details"):
                        st.markdown(f"**Description:** {scenario_data['description']}")
                        st.markdown(f"**Category:** {scenario_data['category']}")
                        st.markdown(f"**Type:** {'Custom' if scenario_data.get('is_custom') else 'Predefined'}")
                        st.markdown(f"**Tactics:** {', '.join(scenario_data['tactics'])}")
                        st.markdown(f"**Techniques:** {len(scenario_data['techniques'])} techniques")
                        st.markdown(f"**Coverage:** {scenario_data['coverage']:.1f}%")

                        if scenario_data.get('is_custom'):
                            st.markdown(f"**Author:** {scenario_data.get('author', 'Unknown')}")
                            if scenario_data.get('tags'):
                                st.markdown(f"**Tags:** {', '.join(scenario_data['tags'])}")

                    # Action buttons
                    if scenario_data.get('is_custom'):
                        col_load, col_edit, col_duplicate, col_delete = st.columns(4)

                        with col_load:
                            if st.button("🗺️ Load", key=f"load_{scenario_data.get('scenario_id', selected_scenario)}"):
                                st.session_state.loaded_scenario = scenario_data
                                st.rerun()

                        with col_edit:
                            if st.button("✏️ Edit", key=f"edit_{scenario_data.get('scenario_id')}"):
                                st.session_state.editing_scenario = scenario_data
                                st.rerun()

                        with col_duplicate:
                            if st.button("📋 Duplicate", key=f"duplicate_{scenario_data.get('scenario_id', selected_scenario)}"):
                                # Create a duplicate scenario
                                import uuid
                                duplicate_data = scenario_data.copy()
                                duplicate_data['scenario_id'] = str(uuid.uuid4())
                                duplicate_data['name'] = f"{scenario_data['name']} (Copy)"
                                duplicate_data['is_custom'] = True
                                duplicate_data['author'] = duplicate_data.get('author', 'Unknown')

                                # Remove predefined-only fields
                                duplicate_data.pop('coverage', None)

                                # Save duplicate
                                if self.db_manager.insert_custom_scenario(duplicate_data):
                                    st.success("Scenario duplicated successfully!")
                                    self.db_manager.log_activity(
                                        "Custom Scenario Duplicated",
                                        f"Duplicated scenario: {duplicate_data['name']}"
                                    )
                                    st.rerun()
                                else:
                                    st.error("Failed to duplicate scenario")

                        with col_delete:
                            if st.button("🗑️ Delete", key=f"delete_{scenario_data.get('scenario_id')}"):
                                if st.session_state.get('confirm_delete') == scenario_data.get('scenario_id'):
                                    # Perform deletion
                                    if self.db_manager.delete_custom_scenario(scenario_data['scenario_id']):
                                        st.success("Scenario deleted successfully!")
                                        st.session_state.pop('confirm_delete', None)
                                        self.db_manager.log_activity(
                                            "Custom Scenario Deleted",
                                            f"Deleted scenario: {scenario_data['name']}"
                                        )
                                        st.rerun()
                                    else:
                                        st.error("Failed to delete scenario")
                                else:
                                    st.session_state.confirm_delete = scenario_data.get('scenario_id')
                                    st.warning("Click delete again to confirm")
                                    st.rerun()
                    else:
                        # For predefined scenarios, only show load and duplicate
                        col_load, col_duplicate = st.columns(2)

                        with col_load:
                            if st.button("🗺️ Load", key=f"load_{scenario_data.get('scenario_id', selected_scenario)}"):
                                st.session_state.loaded_scenario = scenario_data
                                st.rerun()

                        with col_duplicate:
                            if st.button("📋 Duplicate", key=f"duplicate_{scenario_data.get('scenario_id', selected_scenario)}"):
                                # Create a duplicate scenario
                                import uuid
                                duplicate_data = scenario_data.copy()
                                duplicate_data['scenario_id'] = str(uuid.uuid4())
                                duplicate_data['name'] = f"{scenario_data['name']} (Copy)"
                                duplicate_data['is_custom'] = True
                                duplicate_data['author'] = duplicate_data.get('author', 'Unknown')

                                # Remove predefined-only fields
                                duplicate_data.pop('coverage', None)

                                # Save duplicate
                                if self.db_manager.insert_custom_scenario(duplicate_data):
                                    st.success("Scenario duplicated successfully!")
                                    self.db_manager.log_activity(
                                        "Custom Scenario Duplicated",
                                        f"Duplicated scenario: {duplicate_data['name']}"
                                    )
                                    st.rerun()
                                else:
                                    st.error("Failed to duplicate scenario")
            else:
                st.info("No scenarios found for the selected filters")

        with col2:
            st.markdown("#### 🎭 Scenario Visualization")

            if 'loaded_scenario' in st.session_state:
                self._render_scenario_visualization(st.session_state.loaded_scenario)
            else:
                st.info("👆 Select and load a scenario to see the visualization")

        # Scenario analysis (full width)
        if 'loaded_scenario' in st.session_state:
            st.markdown("---")
            self._render_scenario_analysis(st.session_state.loaded_scenario)

    def _render_custom_scenario_builder(self):
        """Render the custom scenario builder interface"""
        st.markdown("#### ➕ Create Custom Attack Scenario")

        # Check if we're editing an existing scenario
        editing_scenario = st.session_state.get('editing_scenario')
        if editing_scenario:
            st.info(f"✏️ Editing scenario: {editing_scenario['name']}")
            if st.button("Cancel Edit"):
                st.session_state.pop('editing_scenario', None)
                st.rerun()

        # Form for scenario creation/editing
        with st.form("custom_scenario_form"):
            col1, col2 = st.columns(2)

            with col1:
                # Basic information
                scenario_name = st.text_input(
                    "Scenario Name *",
                    value=editing_scenario.get('name', '') if editing_scenario else '',
                    help="Enter a descriptive name for your attack scenario"
                )

                scenario_description = st.text_area(
                    "Description *",
                    value=editing_scenario.get('description', '') if editing_scenario else '',
                    help="Describe the attack scenario and its objectives"
                )

                scenario_category = st.selectbox(
                    "Category *",
                    ["APT Campaigns", "Ransomware", "Data Theft", "Insider Threats", "Supply Chain", "Cloud Attacks", "IoT/OT Attacks", "Custom"],
                    index=0 if not editing_scenario else max(0, ["APT Campaigns", "Ransomware", "Data Theft", "Insider Threats", "Supply Chain", "Cloud Attacks", "IoT/OT Attacks", "Custom"].index(editing_scenario.get('category', 'Custom')))
                )

                if scenario_category == "Custom":
                    custom_category = st.text_input(
                        "Custom Category",
                        value=editing_scenario.get('category', '') if editing_scenario and editing_scenario.get('category') not in ["APT Campaigns", "Ransomware", "Data Theft", "Insider Threats", "Supply Chain", "Cloud Attacks", "IoT/OT Attacks"] else ''
                    )
                    if custom_category:
                        scenario_category = custom_category

                author_name = st.text_input(
                    "Author",
                    value=editing_scenario.get('author', '') if editing_scenario else '',
                    help="Your name or organization"
                )

            with col2:
                # Tactics selection
                st.markdown("**Select Tactics ***")
                selected_tactics = []

                # Create checkboxes for each tactic
                for i, tactic in enumerate(self.tactic_order):
                    tactic_display = tactic.replace('-', ' ').title()
                    is_selected = editing_scenario and tactic in editing_scenario.get('tactics', []) if editing_scenario else False

                    if st.checkbox(tactic_display, value=is_selected, key=f"tactic_{tactic}"):
                        selected_tactics.append(tactic)

                # Platforms selection
                available_platforms = self._get_available_platforms()
                selected_platforms = st.multiselect(
                    "Target Platforms",
                    available_platforms,
                    default=editing_scenario.get('platforms', []) if editing_scenario else [],
                    help="Select the platforms this scenario targets"
                )

                # Tags
                tags_input = st.text_input(
                    "Tags (comma-separated)",
                    value=', '.join(editing_scenario.get('tags', [])) if editing_scenario else '',
                    help="Add tags to categorize your scenario"
                )
                tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()] if tags_input else []

            # Techniques selection
            st.markdown("**Select Techniques ***")

            if selected_tactics:
                # Get techniques for selected tactics
                techniques_by_tactic = self._get_techniques_by_tactic(selected_platforms)
                selected_techniques = []

                # Show techniques grouped by tactic
                for tactic in selected_tactics:
                    if tactic in techniques_by_tactic:
                        st.markdown(f"**{tactic.replace('-', ' ').title()}**")

                        # Create columns for technique selection
                        techniques = techniques_by_tactic[tactic][:20]  # Limit to 20 techniques per tactic

                        for technique in techniques:
                            technique_id = technique.get('technique_id')
                            technique_name = technique.get('name', technique_id)

                            is_selected = editing_scenario and technique_id in editing_scenario.get('techniques', []) if editing_scenario else False

                            display_name = f"{technique_id}: {technique_name[:50]}..." if technique_name and len(technique_name) > 50 else f"{technique_id}: {technique_name}" if technique_name else technique_id

                            if st.checkbox(
                                display_name,
                                value=is_selected,
                                key=f"technique_{technique_id}"
                            ):
                                selected_techniques.append(technique_id)

                # Manual technique input
                st.markdown("**Additional Techniques**")
                manual_techniques = st.text_area(
                    "Enter technique IDs (one per line)",
                    value='\n'.join([t for t in editing_scenario.get('techniques', []) if t not in selected_techniques]) if editing_scenario else '',
                    help="Add technique IDs manually (e.g., T1566.001)"
                )

                if manual_techniques:
                    manual_tech_list = [t.strip().upper() for t in manual_techniques.split('\n') if t.strip()]
                    selected_techniques.extend(manual_tech_list)
            else:
                st.warning("Please select at least one tactic to see available techniques")
                selected_techniques = []

            # Form submission
            col_submit, col_preview = st.columns(2)

            with col_submit:
                submit_button = st.form_submit_button(
                    "💾 Save Scenario" if editing_scenario else "➕ Create Scenario",
                    type="primary"
                )

            with col_preview:
                preview_button = st.form_submit_button("👁️ Preview Scenario")

            # Form validation and submission
            if submit_button:
                if not scenario_name or not scenario_description or not selected_tactics or not selected_techniques:
                    st.error("Please fill in all required fields (*)")
                else:
                    # Create scenario data
                    import uuid
                    scenario_data = {
                        'scenario_id': editing_scenario.get('scenario_id') if editing_scenario else str(uuid.uuid4()),
                        'name': scenario_name,
                        'description': scenario_description,
                        'category': scenario_category,
                        'tactics': selected_tactics,
                        'techniques': list(set(selected_techniques)),  # Remove duplicates
                        'platforms': selected_platforms,
                        'author': author_name,
                        'tags': tags,
                        'is_public': False
                    }

                    # Save to database
                    if editing_scenario:
                        success = self.db_manager.update_custom_scenario(scenario_data['scenario_id'], scenario_data)
                        action = "updated"
                    else:
                        success = self.db_manager.insert_custom_scenario(scenario_data)
                        action = "created"

                    if success:
                        st.success(f"✅ Scenario {action} successfully!")

                        # Log activity
                        self.db_manager.log_activity(
                            f"Custom Scenario {action.title()}",
                            f"{action.title()} custom scenario: {scenario_name}"
                        )

                        # Clear editing state
                        if editing_scenario:
                            st.session_state.pop('editing_scenario', None)

                        st.rerun()
                    else:
                        st.error(f"❌ Failed to {action[:-1]} scenario")

            elif preview_button:
                if scenario_name and selected_tactics and selected_techniques:
                    # Show preview
                    st.markdown("#### 👁️ Scenario Preview")
                    preview_data = {
                        'name': scenario_name,
                        'description': scenario_description,
                        'category': scenario_category,
                        'tactics': selected_tactics,
                        'techniques': list(set(selected_techniques)),
                        'platforms': selected_platforms,
                        'author': author_name,
                        'tags': tags,
                        'coverage': self._calculate_scenario_coverage(list(set(selected_techniques)))
                    }

                    col_prev1, col_prev2 = st.columns(2)
                    with col_prev1:
                        st.markdown(f"**Name:** {preview_data['name']}")
                        st.markdown(f"**Category:** {preview_data['category']}")
                        st.markdown(f"**Author:** {preview_data['author']}")
                        st.markdown(f"**Coverage:** {preview_data['coverage']:.1f}%")

                    with col_prev2:
                        st.markdown(f"**Tactics:** {len(preview_data['tactics'])}")
                        st.markdown(f"**Techniques:** {len(preview_data['techniques'])}")
                        st.markdown(f"**Platforms:** {', '.join(preview_data['platforms'])}")
                        st.markdown(f"**Tags:** {', '.join(preview_data['tags'])}")

                    st.markdown(f"**Description:** {preview_data['description']}")
                else:
                    st.warning("Please fill in the required fields to preview the scenario")
    
    def _generate_attack_path(self, scenario_type: str, start_tactic: str, target_tactics: List[str],
                            max_length: int, include_sub: bool, prioritize_coverage: bool,
                            platforms: List[str]) -> Dict[str, Any]:
        """Generate detailed attack path with techniques between tactics"""
        try:
            # Get techniques for each tactic
            techniques_by_tactic = self._get_techniques_by_tactic(platforms)

            # Generate detailed kill chain paths
            paths = []
            for target in target_tactics:
                detailed_path = self._create_detailed_kill_chain(
                    start_tactic, target, techniques_by_tactic,
                    max_length, include_sub, prioritize_coverage
                )
                if detailed_path:
                    paths.append(detailed_path)

            # Select best path based on criteria
            if paths:
                best_path = self._select_best_path(paths, prioritize_coverage)

                # Get rule coverage for path
                path_coverage = self._get_path_coverage(best_path)

                return {
                    'path': best_path,
                    'coverage': path_coverage,
                    'scenario_type': scenario_type,
                    'platforms': platforms
                }
            else:
                return {
                    'path': [],
                    'coverage': {},
                    'error': 'No path found between specified tactics'
                }

        except Exception as e:
            self.logger.error(f"Error generating attack path: {e}")
            return {
                'path': [],
                'coverage': {},
                'error': str(e)
            }

    def _create_detailed_kill_chain(self, start_tactic: str, target_tactic: str,
                                  techniques_by_tactic: Dict, max_length: int,
                                  include_sub: bool, prioritize_coverage: bool) -> List[str]:
        """Create a detailed kill chain with techniques between tactics"""
        try:
            # Find the index positions of start and target tactics
            start_idx = self.tactic_order.index(start_tactic) if start_tactic in self.tactic_order else 0
            target_idx = self.tactic_order.index(target_tactic) if target_tactic in self.tactic_order else len(self.tactic_order) - 1

            # Create detailed path: Tactic -> Technique(s) -> Next Tactic -> Technique(s)
            detailed_path = []

            self.logger.info(f"Creating kill chain from {start_tactic} (idx {start_idx}) to {target_tactic} (idx {target_idx})")

            if start_idx <= target_idx:
                # Forward path through tactics
                for i in range(start_idx, target_idx + 1):
                    tactic = self.tactic_order[i]
                    detailed_path.append(tactic)
                    self.logger.info(f"Added tactic: {tactic}")

                    # Add 1-2 best techniques from this tactic
                    if tactic in techniques_by_tactic and techniques_by_tactic[tactic]:
                        selected_techniques = self._select_best_techniques_for_tactic(
                            techniques_by_tactic[tactic], prioritize_coverage, include_sub
                        )
                        if selected_techniques:
                            detailed_path.extend(selected_techniques)
                            self.logger.info(f"Added techniques for {tactic}: {selected_techniques}")
                        else:
                            self.logger.warning(f"No techniques selected for tactic: {tactic}")
                    else:
                        self.logger.warning(f"No techniques available for tactic: {tactic}")

                    # Limit path length
                    if len(detailed_path) >= max_length:
                        self.logger.info(f"Path length limit reached: {len(detailed_path)}")
                        break

            self.logger.info(f"Final detailed path: {detailed_path}")
            return detailed_path if len(detailed_path) > 1 else []

        except Exception as e:
            self.logger.error(f"Error creating detailed kill chain: {e}")
            return []

    def _select_best_techniques_for_tactic(self, techniques: List[Dict],
                                         prioritize_coverage: bool, include_sub: bool) -> List[str]:
        """Select the best 1-3 techniques for a tactic with enhanced sub-technique support"""
        try:
            if not techniques:
                return []

            # Separate main techniques and sub-techniques
            main_techniques = [t for t in techniques if '.' not in t.get('technique_id', '')]
            sub_techniques = [t for t in techniques if '.' in t.get('technique_id', '')]

            self.logger.info(f"Selecting from {len(main_techniques)} main techniques and {len(sub_techniques)} sub-techniques (include_sub: {include_sub})")

            # Score techniques based on criteria
            scored_main = self._score_techniques(main_techniques, prioritize_coverage)
            scored_sub = self._score_techniques(sub_techniques, prioritize_coverage) if include_sub else []

            # Select techniques with enhanced logic
            selected = []

            # Always include at least one main technique if available
            if scored_main:
                selected.append(scored_main[0][0])

                # Add a second main technique if it has good coverage
                if len(scored_main) > 1 and scored_main[1][1] > 5:
                    selected.append(scored_main[1][0])

            # Add sub-techniques if requested and space allows
            if include_sub and scored_sub and len(selected) < 3:
                # Prefer sub-techniques that are related to selected main techniques
                related_sub = []
                unrelated_sub = []

                for sub_tech_id, score, rule_count in scored_sub:
                    parent_id = sub_tech_id.split('.')[0]  # T1234.001 -> T1234
                    if parent_id in selected:
                        related_sub.append((sub_tech_id, score, rule_count))
                    else:
                        unrelated_sub.append((sub_tech_id, score, rule_count))

                # Add related sub-techniques first
                for sub_tech_id, _, _ in related_sub[:1]:
                    if len(selected) < 3:
                        selected.append(sub_tech_id)

                # Add unrelated sub-techniques if space and good coverage
                for sub_tech_id, score, _ in unrelated_sub[:1]:
                    if len(selected) < 3 and score > 10:
                        selected.append(sub_tech_id)

            self.logger.info(f"Selected techniques for tactic: {selected}")
            return selected

        except Exception as e:
            self.logger.error(f"Error selecting best techniques: {e}")
            return []

    def _score_techniques(self, techniques: List[Dict], prioritize_coverage: bool) -> List[Tuple[str, int, int]]:
        """Score techniques based on various criteria"""
        try:
            scored_techniques = []

            for technique in techniques:
                technique_id = technique.get('technique_id', '')
                if not technique_id:
                    continue

                score = 0

                # Get rule count for this technique
                rules = self._get_rules_for_technique(technique_id)
                rule_count = len(rules)

                # Coverage scoring
                if prioritize_coverage:
                    # Higher score for more rules when prioritizing coverage
                    if rule_count >= 10:
                        score += 15
                    elif rule_count >= 5:
                        score += 10
                    elif rule_count >= 3:
                        score += 7
                    elif rule_count >= 1:
                        score += 4
                else:
                    # Moderate coverage scoring when not prioritizing
                    if rule_count >= 5:
                        score += 5
                    elif rule_count >= 1:
                        score += 3

                # Quality bonus for high-level rules
                for rule in rules:
                    level = rule.get('level', '').lower()
                    if level in ['high', 'critical']:
                        score += 3
                    elif level == 'medium':
                        score += 1

                # Popularity bonus for commonly used techniques
                if technique_id in ['T1059', 'T1055', 'T1003', 'T1083', 'T1021', 'T1566', 'T1078', 'T1105']:
                    score += 4

                # Platform relevance
                try:
                    platforms = json.loads(technique.get('platform', '[]')) if technique.get('platform') else []
                    if 'Windows' in platforms:
                        score += 2
                    if 'Linux' in platforms:
                        score += 1
                except:
                    pass

                # Sub-technique specific scoring
                if '.' in technique_id:
                    # Slight penalty to prefer main techniques
                    score -= 1
                    # But bonus for well-documented sub-techniques
                    if rule_count >= 2:
                        score += 2

                # Bonus for techniques with any coverage
                if rule_count > 0:
                    score += 2

                # Enhanced MITRE data scoring (NEW)
                detection_info = technique.get('detection', '')
                mitigation_info = technique.get('mitigation', '')

                if detection_info and detection_info.strip():
                    score += 3  # Bonus for having detection information

                if mitigation_info and mitigation_info.strip():
                    score += 2  # Bonus for having mitigation information

                # Data sources availability
                data_sources = technique.get('data_sources', [])
                if isinstance(data_sources, str):
                    try:
                        data_sources = json.loads(data_sources)
                    except:
                        data_sources = []

                if data_sources and len(data_sources) > 0:
                    score += 1  # Bonus for having data sources

                # Permissions required (lower permissions = higher score for accessibility)
                permissions_required = technique.get('permissions_required', [])
                if isinstance(permissions_required, str):
                    try:
                        permissions_required = json.loads(permissions_required)
                    except:
                        permissions_required = []

                if 'User' in permissions_required:
                    score += 2  # User-level techniques are more accessible
                elif 'Administrator' in permissions_required:
                    score += 1  # Admin techniques still valuable but less accessible

                scored_techniques.append((technique_id, score, rule_count))
                self.logger.debug(f"Technique {technique_id}: score={score}, rules={rule_count}, detection={bool(detection_info)}, mitigation={bool(mitigation_info)}")

            # Sort by score (descending)
            scored_techniques.sort(key=lambda x: x[1], reverse=True)

            if scored_techniques:
                self.logger.info(f"Top scored techniques: {[(t[0], t[1], t[2]) for t in scored_techniques[:5]]}")

            return scored_techniques

        except Exception as e:
            self.logger.error(f"Error scoring techniques: {e}")
            return []


    
    def _render_attack_path_graph(self, path_data: Dict[str, Any]):
        """Render attack path as interactive mind map with sub-techniques and attack chains"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            # Visualization options - using horizontal layout without columns to avoid nesting
            st.markdown("**Visualization Options:**")

            # Create a single row of controls using st.container and inline styling
            with st.container():
                layout_type = st.selectbox("Layout", ["Mind Map", "Linear Flow", "Flowchart Diagram", "Hierarchical"], key="path_layout")

                # Use two columns for the checkboxes only
                option_col1, option_col2 = st.columns(2)
                with option_col1:
                    show_sub_techniques = st.checkbox("Show Sub-techniques", value=True, key="path_sub_tech")
                with option_col2:
                    show_attack_chains = st.checkbox("Show Attack Chains", value=True, key="path_chains")

            st.markdown("---")

            # Generate enhanced visualization data
            if layout_type == "Mind Map":
                self._render_mind_map_visualization(path, coverage, show_sub_techniques, show_attack_chains)
            elif layout_type == "Linear Flow":
                self._render_linear_flow_visualization(path, coverage, show_sub_techniques)
            elif layout_type == "Flowchart Diagram":
                self._render_flowchart_visualization(path, coverage, show_sub_techniques, show_attack_chains)
            else:
                self._render_hierarchical_visualization(path, coverage, show_sub_techniques, show_attack_chains)

        except Exception as e:
            self.logger.error(f"Error rendering attack path graph: {e}")
            st.error(f"Error rendering graph: {str(e)}")

    def _render_mind_map_visualization(self, path: List[str], coverage: Dict[str, Any],
                                     show_sub_techniques: bool, show_attack_chains: bool):
        """Render attack path as a fancy mind map"""
        try:
            nodes = []
            edges = []

            # Create center node (attack scenario)
            center_id = "attack_scenario"
            nodes.append(Node(
                id=center_id,
                label="🎯 Attack\nScenario",
                size=50,
                shape='star',
                font={'color': 'white', 'size': 16, 'face': 'arial bold'},
                borderWidth=4,
                color={
                    'border': '#1a237e',
                    'background': 'linear-gradient(45deg, #3f51b5, #1a237e)',
                    'highlight': {'border': '#0d47a1', 'background': '#1976d2'}
                },
                title="Central Attack Scenario"
            ))

            # Process path nodes with enhanced styling
            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Calculate position for mind map layout (radial) - for future use
                # angle = (2 * 3.14159 * i) / len(path)

                # Create main node
                nodes.append(Node(
                    id=node_id,
                    label=node_info['label'],
                    size=node_info['size'],
                    shape=node_info['shape'],
                    font=node_info['font'],
                    borderWidth=node_info['border_width'],
                    color=node_info['color'],
                    title=node_info['title'],
                    x=300 * (1 + 0.8 * i / len(path)) * (1 if i % 2 == 0 else -1),
                    y=200 * (1 + 0.6 * i / len(path)) * (1 if (i // 2) % 2 == 0 else -1)
                ))

                # Connect to center
                edges.append(Edge(
                    source=center_id,
                    target=node_id,
                    color=node_info['edge_color'],
                    width=4,
                    arrows={'to': {'enabled': True, 'scaleFactor': 1.5}},
                    smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.3},
                    dashes=node_info.get('dashed', False)
                ))

                # Add sub-techniques if enabled
                if show_sub_techniques and node_info['sub_techniques']:
                    for j, sub_tech in enumerate(node_info['sub_techniques'][:3]):  # Limit to 3
                        sub_id = f"{node_id}_sub_{j}"
                        sub_info = self._get_sub_technique_info(sub_tech, coverage)

                        nodes.append(Node(
                            id=sub_id,
                            label=sub_info['label'],
                            size=20,
                            shape='dot',
                            font={'color': 'white', 'size': 10},
                            color=sub_info['color'],
                            title=sub_info['title']
                        ))

                        edges.append(Edge(
                            source=node_id,
                            target=sub_id,
                            color="#666666",
                            width=2,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.8}},
                            smooth={'enabled': True, 'type': 'curvedCW'},
                            dashes=True
                        ))

                # Add attack chain connections
                if show_attack_chains and i < len(path) - 1:
                    edges.append(Edge(
                        source=node_id,
                        target=path[i + 1],
                        color="#ff6b35",
                        width=3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.2}},
                        smooth={'enabled': True, 'type': 'dynamic'},
                        label="⚡"
                    ))

            # Enhanced mind map configuration with responsive sizing
            config = Config(
                width="100%",  # Responsive width
                height=700,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 200},
                    "barnesHut": {
                        "gravitationalConstant": -3000,
                        "centralGravity": 0.1,
                        "springLength": 150,
                        "springConstant": 0.02,
                        "damping": 0.15
                    }
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True
                },
                layout={
                    "randomSeed": 42,
                    "improvedLayout": True
                }
            )

            # Render the mind map
            st.markdown("### 🧠 Attack Path Mind Map")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering mind map: {e}")
            st.error("Unable to render mind map visualization. Please try a different layout or refresh the page.")

    def _get_enhanced_node_info(self, node_id: str, coverage: Dict[str, Any],
                               show_sub_techniques: bool) -> Dict[str, Any]:
        """Get enhanced node information for visualization"""
        try:
            # Check if it's a tactic or technique
            if node_id in self.tactic_order:
                return self._get_tactic_node_info(node_id)
            else:
                return self._get_technique_node_info(node_id, coverage, show_sub_techniques)
        except Exception as e:
            self.logger.error(f"Error getting enhanced node info: {e}")
            return self._get_default_node_info(node_id)

    def _get_tactic_node_info(self, tactic_id: str) -> Dict[str, Any]:
        """Get enhanced tactic node information"""
        return {
            'label': f"🎯 {tactic_id.replace('-', ' ').title()}",
            'size': 40,
            'shape': 'box',
            'font': {'color': 'white', 'size': 14, 'face': 'arial bold'},
            'border_width': 4,
            'color': {
                'border': '#0d47a1',
                'background': 'linear-gradient(45deg, #1976d2, #0d47a1)',
                'highlight': {'border': '#1565c0', 'background': '#1976d2'}
            },
            'title': f"Tactic: {tactic_id.replace('-', ' ').title()}",
            'edge_color': "#1976d2",
            'sub_techniques': [],
            'dashed': False
        }

    def _get_technique_node_info(self, technique_id: str, coverage: Dict[str, Any],
                                show_sub_techniques: bool) -> Dict[str, Any]:
        """Get enhanced technique node information with detection and mitigation indicators"""
        try:
            technique_info = self._get_technique_info(technique_id)
            rule_count = coverage.get(technique_id, {}).get('rule_count', 0)

            # Check for enhanced MITRE data
            has_detection = bool(technique_info.get('detection', '').strip())
            has_mitigation = bool(technique_info.get('mitigation', '').strip())

            # Create indicators for enhanced data
            detection_indicator = "🔍" if has_detection else "❌"
            mitigation_indicator = "🛡️" if has_mitigation else "❌"

            # Determine if it's a sub-technique
            is_sub_technique = '.' in technique_id

            # Color scheme based on coverage and type
            if rule_count >= 3:
                color_scheme = {
                    'border': '#1b5e20',
                    'background': 'linear-gradient(45deg, #4caf50, #2e7d32)',
                    'edge_color': '#4caf50'
                }
            elif rule_count >= 1:
                color_scheme = {
                    'border': '#e65100',
                    'background': 'linear-gradient(45deg, #ff9800, #e65100)',
                    'edge_color': '#ff9800'
                }
            else:
                color_scheme = {
                    'border': '#b71c1c',
                    'background': 'linear-gradient(45deg, #f44336, #b71c1c)',
                    'edge_color': '#f44336'
                }

            # Get sub-techniques if applicable
            sub_techniques = []
            if show_sub_techniques and not is_sub_technique:
                sub_techniques = self._get_sub_techniques_for_technique(technique_id)

            # Determine shape and size
            if is_sub_technique:
                shape = 'diamond'
                size = 25
                label_prefix = "🔸"
            else:
                shape = 'ellipse'
                size = 35
                label_prefix = "⚙️"

            # Create enhanced title with detection and mitigation info
            title_parts = [
                f"Technique: {technique_info.get('name', technique_id)}",
                f"Rules: {rule_count}",
                f"Tactic: {technique_info.get('tactic', 'Unknown')}",
                f"Detection Info: {'Available' if has_detection else 'Not Available'}",
                f"Mitigation Info: {'Available' if has_mitigation else 'Not Available'}"
            ]

            # Add data sources if available
            data_sources = technique_info.get('data_sources', [])
            if isinstance(data_sources, str):
                try:
                    data_sources = json.loads(data_sources)
                except:
                    data_sources = []

            if data_sources:
                title_parts.append(f"Data Sources: {', '.join(data_sources[:3])}")

            return {
                'label': f"{label_prefix} {technique_id}\n({rule_count} rules)\n{detection_indicator} {mitigation_indicator}",
                'size': size,
                'shape': shape,
                'font': {'color': 'white', 'size': 12, 'face': 'arial'},
                'border_width': 3,
                'color': {
                    'border': color_scheme['border'],
                    'background': color_scheme['background'],
                    'highlight': {'border': color_scheme['border'], 'background': color_scheme['background']}
                },
                'title': '\n'.join(title_parts),
                'edge_color': color_scheme['edge_color'],
                'sub_techniques': sub_techniques,
                'dashed': is_sub_technique
            }

        except Exception as e:
            self.logger.error(f"Error getting technique node info: {e}")
            return self._get_default_node_info(technique_id)

    def _get_sub_techniques_for_technique(self, technique_id: str) -> List[str]:
        """Get sub-techniques for a given technique"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Look for sub-techniques with pattern T1234.001, T1234.002, etc.
                query = """
                    SELECT technique_id
                    FROM mitre_techniques
                    WHERE technique_id LIKE ?
                    AND technique_id != ?
                    ORDER BY technique_id
                """

                cursor.execute(query, (f"{technique_id}.%", technique_id))
                rows = cursor.fetchall()

                return [row[0] for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting sub-techniques for {technique_id}: {e}")
            return []

    def _get_sub_technique_info(self, sub_technique_id: str, coverage: Dict[str, Any]) -> Dict[str, Any]:
        """Get sub-technique information for visualization"""
        try:
            rule_count = coverage.get(sub_technique_id, {}).get('rule_count', 0)
            technique_info = self._get_technique_info(sub_technique_id)

            # Color based on coverage
            if rule_count >= 2:
                color = {'border': '#1b5e20', 'background': '#4caf50'}
            elif rule_count >= 1:
                color = {'border': '#e65100', 'background': '#ff9800'}
            else:
                color = {'border': '#b71c1c', 'background': '#f44336'}

            return {
                'label': f"{sub_technique_id}\n({rule_count})",
                'color': color,
                'title': f"Sub-technique: {technique_info.get('name', sub_technique_id)}\nRules: {rule_count}"
            }

        except Exception as e:
            self.logger.error(f"Error getting sub-technique info: {e}")
            return {
                'label': sub_technique_id,
                'color': {'border': '#666666', 'background': '#999999'},
                'title': f"Sub-technique: {sub_technique_id}"
            }

    def _get_default_node_info(self, node_id: str) -> Dict[str, Any]:
        """Get default node information"""
        return {
            'label': node_id,
            'size': 30,
            'shape': 'ellipse',
            'font': {'color': 'white', 'size': 12, 'face': 'arial'},
            'border_width': 2,
            'color': {
                'border': '#666666',
                'background': '#999999',
                'highlight': {'border': '#666666', 'background': '#999999'}
            },
            'title': f"Node: {node_id}",
            'edge_color': "#999999",
            'sub_techniques': [],
            'dashed': False
        }

    def _render_linear_flow_visualization(self, path: List[str], coverage: Dict[str, Any],
                                        show_sub_techniques: bool):
        """Render attack path as linear flow with enhanced styling"""
        try:
            nodes = []
            edges = []

            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Create main node with enhanced styling
                nodes.append(Node(
                    id=node_id,
                    label=node_info['label'],
                    size=node_info['size'],
                    shape=node_info['shape'],
                    font=node_info['font'],
                    borderWidth=node_info['border_width'],
                    color=node_info['color'],
                    title=node_info['title']
                ))

                # Add sub-techniques below main technique
                if show_sub_techniques and node_info['sub_techniques']:
                    for j, sub_tech in enumerate(node_info['sub_techniques'][:2]):
                        sub_id = f"{node_id}_sub_{j}"
                        sub_info = self._get_sub_technique_info(sub_tech, coverage)

                        nodes.append(Node(
                            id=sub_id,
                            label=sub_info['label'],
                            size=18,
                            shape='triangle',
                            font={'color': 'white', 'size': 9},
                            color=sub_info['color'],
                            title=sub_info['title']
                        ))

                        edges.append(Edge(
                            source=node_id,
                            target=sub_id,
                            color="#888888",
                            width=1,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.6}},
                            dashes=True
                        ))

                # Add flow edge to next node
                if i < len(path) - 1:
                    edges.append(Edge(
                        source=node_id,
                        target=path[i + 1],
                        color=node_info['edge_color'],
                        width=4,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.5}},
                        smooth={'enabled': True, 'type': 'dynamic'},
                        label=f"Step {i+1}"
                    ))

            # Linear flow configuration with responsive sizing
            config = Config(
                width="100%",  # Responsive width
                height=400,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 150},
                    "barnesHut": {
                        "gravitationalConstant": -5000,
                        "centralGravity": 0.2,
                        "springLength": 200,
                        "springConstant": 0.03,
                        "damping": 0.12
                    }
                },
                hierarchical={
                    "enabled": True,
                    "levelSeparation": 250,
                    "nodeSpacing": 150,
                    "treeSpacing": 200,
                    "blockShifting": True,
                    "edgeMinimization": True,
                    "parentCentralization": True,
                    "direction": "LR",
                    "sortMethod": "directed"
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True
                }
            )

            st.markdown("### ➡️ Linear Attack Flow")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering linear flow: {e}")
            st.error(f"Error rendering linear flow: {str(e)}")

    def _render_flowchart_visualization(self, path: List[str], coverage: Dict[str, Any],
                                      show_sub_techniques: bool, show_attack_chains: bool):
        """Render attack path as professional flowchart diagram similar to reference image"""
        try:
            nodes = []
            edges = []

            # Create start node (reconnaissance/initial access)
            start_node = Node(
                id="start_node",
                label="🎯 Attack\nInitiation",
                size=45,
                shape='box',
                font={'color': 'white', 'size': 14, 'face': 'arial bold'},
                borderWidth=3,
                color={
                    'border': '#1565c0',
                    'background': 'linear-gradient(135deg, #1976d2, #1565c0)',
                    'highlight': {'border': '#0d47a1', 'background': '#1976d2'}
                },
                title="Attack Initiation Point",
                x=0,
                y=0
            )
            nodes.append(start_node)

            # Process path nodes in flowchart style
            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Determine node position in flowchart layout
                level = i + 1
                x_pos = 0 if level % 2 == 1 else (200 if (level // 2) % 2 == 0 else -200)
                y_pos = level * 150

                # Create flowchart-style node
                flowchart_node = self._create_flowchart_node(node_id, node_info, x_pos, y_pos)
                nodes.append(flowchart_node)

                # Connect to previous node
                if i == 0:
                    # Connect to start node
                    edges.append(Edge(
                        source="start_node",
                        target=node_id,
                        color="#1976d2",
                        width=3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.5}},
                        smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.2},
                        label="Initiates"
                    ))
                else:
                    # Connect to previous path node
                    edges.append(Edge(
                        source=path[i-1],
                        target=node_id,
                        color=self._get_flowchart_edge_color(node_info),
                        width=3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.5}},
                        smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.3},
                        label=f"Step {i+1}"
                    ))

                # Add decision points and sub-techniques
                if show_sub_techniques and node_info['sub_techniques']:
                    self._add_flowchart_sub_techniques(nodes, edges, node_id, node_info, x_pos, y_pos, coverage)

                # Add attack chain branches
                if show_attack_chains and i < len(path) - 1:
                    self._add_flowchart_attack_chains(nodes, edges, node_id, x_pos, y_pos, i)

            # Add end node
            end_node = Node(
                id="end_node",
                label="🎯 Objective\nAchieved",
                size=45,
                shape='star',
                font={'color': 'white', 'size': 14, 'face': 'arial bold'},
                borderWidth=3,
                color={
                    'border': '#2e7d32',
                    'background': 'linear-gradient(135deg, #4caf50, #2e7d32)',
                    'highlight': {'border': '#1b5e20', 'background': '#4caf50'}
                },
                title="Attack Objective Completed",
                x=0,
                y=(len(path) + 1) * 150
            )
            nodes.append(end_node)

            # Connect last path node to end
            if path:
                edges.append(Edge(
                    source=path[-1],
                    target="end_node",
                    color="#4caf50",
                    width=4,
                    arrows={'to': {'enabled': True, 'scaleFactor': 2.0}},
                    smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.2},
                    label="Completes"
                ))

            # Flowchart configuration
            config = Config(
                width="100%",
                height=max(600, len(path) * 120 + 200),
                directed=True,
                physics={
                    "enabled": False  # Use fixed positions for flowchart
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True
                },
                layout={
                    "randomSeed": 42,
                    "improvedLayout": False
                }
            )

            st.markdown("### 📊 Professional Flowchart Diagram")
            st.info("💡 **Flowchart View**: Professional attack path visualization with clear decision points and flow")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering flowchart: {e}")
            st.error(f"Error rendering flowchart: {str(e)}")

    def _create_flowchart_node(self, node_id: str, node_info: Dict[str, Any], x_pos: int, y_pos: int) -> Node:
        """Create a flowchart-style node with professional styling"""
        # Determine node shape based on type and level
        if node_id in self.tactic_order:
            # Tactic nodes - rectangular boxes
            shape = 'box'
            size = 50
            border_width = 4
        elif '.' in node_id:
            # Sub-technique nodes - diamonds
            shape = 'diamond'
            size = 35
            border_width = 3
        else:
            # Technique nodes - rounded rectangles
            shape = 'ellipse'
            size = 40
            border_width = 3

        # Enhanced color scheme for flowchart
        if 'rule_count' in str(node_info.get('title', '')):
            # Extract rule count for color coding
            rule_count = 0
            try:
                title_text = node_info.get('title', '')
                if 'Rules:' in title_text:
                    rule_count = int(title_text.split('Rules:')[1].split('\n')[0].strip())
            except:
                rule_count = 0

            if rule_count >= 3:
                color_scheme = {
                    'border': '#1b5e20',
                    'background': 'linear-gradient(135deg, #4caf50, #2e7d32)',
                    'highlight': {'border': '#0d47a1', 'background': '#4caf50'}
                }
            elif rule_count >= 1:
                color_scheme = {
                    'border': '#e65100',
                    'background': 'linear-gradient(135deg, #ff9800, #e65100)',
                    'highlight': {'border': '#bf360c', 'background': '#ff9800'}
                }
            else:
                color_scheme = {
                    'border': '#b71c1c',
                    'background': 'linear-gradient(135deg, #f44336, #b71c1c)',
                    'highlight': {'border': '#7f0000', 'background': '#f44336'}
                }
        else:
            # Default professional blue scheme
            color_scheme = {
                'border': '#1565c0',
                'background': 'linear-gradient(135deg, #1976d2, #1565c0)',
                'highlight': {'border': '#0d47a1', 'background': '#1976d2'}
            }

        return Node(
            id=node_id,
            label=node_info['label'],
            size=size,
            shape=shape,
            font={'color': 'white', 'size': 12, 'face': 'arial bold'},
            borderWidth=border_width,
            color=color_scheme,
            title=node_info['title'],
            x=x_pos,
            y=y_pos
        )

    def _get_flowchart_edge_color(self, node_info: Dict[str, Any]) -> str:
        """Get edge color for flowchart based on node type and coverage"""
        if 'rule_count' in str(node_info.get('title', '')):
            try:
                title_text = node_info.get('title', '')
                if 'Rules:' in title_text:
                    rule_count = int(title_text.split('Rules:')[1].split('\n')[0].strip())
                    if rule_count >= 3:
                        return "#4caf50"  # Green for good coverage
                    elif rule_count >= 1:
                        return "#ff9800"  # Orange for medium coverage
                    else:
                        return "#f44336"  # Red for no coverage
            except:
                pass
        return "#1976d2"  # Default blue

    def _add_flowchart_sub_techniques(self, nodes: List[Node], edges: List[Edge], parent_id: str,
                                    node_info: Dict[str, Any], x_pos: int, y_pos: int, coverage: Dict[str, Any]):
        """Add sub-techniques as decision branches in flowchart"""
        sub_techniques = node_info.get('sub_techniques', [])[:3]  # Limit to 3 for clarity

        for i, sub_tech in enumerate(sub_techniques):
            sub_id = f"{parent_id}_sub_{i}"
            sub_info = self._get_sub_technique_info(sub_tech, coverage)

            # Position sub-techniques as branches
            sub_x = x_pos + (150 * (i - 1))  # Spread horizontally
            sub_y = y_pos + 80  # Below parent

            # Create diamond-shaped decision node
            # Extract rule count for label
            rule_text = "0"
            title_text = sub_info.get('title', '')
            if 'Rules:' in title_text:
                try:
                    rule_text = title_text.split('Rules:')[-1].split('\n')[0].strip()
                except:
                    rule_text = "0"

            sub_node = Node(
                id=sub_id,
                label=f"🔸 {sub_tech}\n({rule_text} rules)",
                size=25,
                shape='diamond',
                font={'color': 'white', 'size': 10, 'face': 'arial'},
                borderWidth=2,
                color={
                    'border': sub_info['color']['border'],
                    'background': f"linear-gradient(135deg, {sub_info['color']['background']}, {sub_info['color']['border']})",
                    'highlight': {'border': sub_info['color']['border'], 'background': sub_info['color']['background']}
                },
                title=sub_info['title'],
                x=sub_x,
                y=sub_y
            )
            nodes.append(sub_node)

            # Connect with dashed line
            edge = Edge(
                source=parent_id,
                target=sub_id,
                color="#666666",
                width=2,
                arrows={'to': {'enabled': True, 'scaleFactor': 0.8}},
                smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.4},
                dashes=True,
                label="variant"
            )
            edges.append(edge)

    def _add_flowchart_attack_chains(self, nodes: List[Node], edges: List[Edge], current_id: str,
                                   x_pos: int, y_pos: int, step_index: int):
        """Add attack chain visualization elements"""
        # Create intermediate decision point
        chain_id = f"chain_{step_index}"
        chain_node = Node(
            id=chain_id,
            label="⚡",
            size=20,
            shape='triangle',
            font={'color': 'white', 'size': 16, 'face': 'arial bold'},
            borderWidth=2,
            color={
                'border': '#ff6b35',
                'background': 'linear-gradient(135deg, #ff8a50, #ff6b35)',
                'highlight': {'border': '#e64a19', 'background': '#ff8a50'}
            },
            title=f"Attack Chain Step {step_index + 1}",
            x=x_pos + 100,
            y=y_pos + 75
        )
        nodes.append(chain_node)

        # Connect current to chain point
        edges.append(Edge(
            source=current_id,
            target=chain_id,
            color="#ff6b35",
            width=2,
            arrows={'to': {'enabled': True, 'scaleFactor': 1.0}},
            smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.5},
            label="chains to"
        ))

    def _render_hierarchical_visualization(self, path: List[str], coverage: Dict[str, Any],
                                         show_sub_techniques: bool, show_attack_chains: bool):
        """Render attack path as hierarchical tree with attack chains"""
        try:
            nodes = []
            edges = []

            # Group techniques by tactic
            tactic_groups = {}
            for node_id in path:
                if node_id in self.tactic_order:
                    tactic_groups[node_id] = []
                else:
                    # Find the tactic for this technique
                    technique_info = self._get_technique_info(node_id)
                    tactic = technique_info.get('tactic', 'unknown')
                    if tactic not in tactic_groups:
                        tactic_groups[tactic] = []
                    tactic_groups[tactic].append(node_id)

            # Create tactic nodes
            tactic_y_positions = {}
            for i, (tactic_id, techniques) in enumerate(tactic_groups.items()):
                if tactic_id in self.tactic_order:
                    tactic_info = self._get_tactic_node_info(tactic_id)
                    y_pos = i * 200
                    tactic_y_positions[tactic_id] = y_pos

                    nodes.append(Node(
                        id=tactic_id,
                        label=tactic_info['label'],
                        size=tactic_info['size'],
                        shape=tactic_info['shape'],
                        font=tactic_info['font'],
                        borderWidth=tactic_info['border_width'],
                        color=tactic_info['color'],
                        title=tactic_info['title'],
                        x=0,
                        y=y_pos
                    ))

                    # Add technique nodes under each tactic
                    for j, technique_id in enumerate(techniques):
                        technique_info = self._get_enhanced_node_info(technique_id, coverage, show_sub_techniques)

                        nodes.append(Node(
                            id=technique_id,
                            label=technique_info['label'],
                            size=technique_info['size'],
                            shape=technique_info['shape'],
                            font=technique_info['font'],
                            borderWidth=technique_info['border_width'],
                            color=technique_info['color'],
                            title=technique_info['title'],
                            x=300 + (j * 150),
                            y=y_pos
                        ))

                        # Connect technique to tactic
                        edges.append(Edge(
                            source=tactic_id,
                            target=technique_id,
                            color="#666666",
                            width=2,
                            arrows={'to': {'enabled': True, 'scaleFactor': 1.0}}
                        ))

                        # Add sub-techniques
                        if show_sub_techniques and technique_info['sub_techniques']:
                            for k, sub_tech in enumerate(technique_info['sub_techniques'][:2]):
                                sub_id = f"{technique_id}_sub_{k}"
                                sub_info = self._get_sub_technique_info(sub_tech, coverage)

                                nodes.append(Node(
                                    id=sub_id,
                                    label=sub_info['label'],
                                    size=15,
                                    shape='dot',
                                    font={'color': 'white', 'size': 8},
                                    color=sub_info['color'],
                                    title=sub_info['title'],
                                    x=300 + (j * 150) + 50,
                                    y=y_pos + 50 + (k * 30)
                                ))

                                edges.append(Edge(
                                    source=technique_id,
                                    target=sub_id,
                                    color="#999999",
                                    width=1,
                                    dashes=True
                                ))

            # Add attack chain connections between tactics
            if show_attack_chains:
                tactic_list = list(tactic_y_positions.keys())
                for i in range(len(tactic_list) - 1):
                    edges.append(Edge(
                        source=tactic_list[i],
                        target=tactic_list[i + 1],
                        color="#ff4444",
                        width=5,
                        arrows={'to': {'enabled': True, 'scaleFactor': 2.0}},
                        smooth={'enabled': True, 'type': 'curvedCW'},
                        label="⚡ Attack Chain"
                    ))

            # Hierarchical configuration with responsive sizing
            config = Config(
                width="100%",  # Responsive width
                height=800,
                directed=True,
                physics={
                    "enabled": False  # Use fixed positions
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True
                }
            )

            st.markdown("### 🌳 Hierarchical Attack Tree")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering hierarchical visualization: {e}")
            st.error(f"Error rendering hierarchical visualization: {str(e)}")

    def _render_fullscreen_visualization(self, path_data: Dict[str, Any], is_manual: bool = False):
        """Render attack path visualization in full-screen modal"""
        try:
            # Load custom CSS for full-screen visualization
            try:
                with open("static/css/fullscreen_viz.css", "r") as f:
                    css_content = f.read()
                st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)
            except FileNotFoundError:
                # Fallback inline CSS if file not found
                st.markdown("""
                <style>
                .fullscreen-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    background-color: rgba(0, 0, 0, 0.95);
                    z-index: 9999;
                    display: flex;
                    flex-direction: column;
                    padding: 20px;
                    box-sizing: border-box;
                    backdrop-filter: blur(5px);
                }
                .fullscreen-content {
                    flex: 1;
                    overflow: auto;
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    border-radius: 15px;
                    padding: 25px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                }
                </style>
                """, unsafe_allow_html=True)

            # Full-screen modal content with enhanced styling
            with st.container():
                # Enhanced header with close button and info
                st.markdown('<div class="fullscreen-header">', unsafe_allow_html=True)
                header_col1, header_col2, header_col3 = st.columns([3, 1, 1])
                with header_col1:
                    st.markdown('<h1 class="fullscreen-title">🗺️ Full-Screen Attack Path Visualization</h1>', unsafe_allow_html=True)
                with header_col2:
                    st.markdown("**Press ESC to close**", help="Keyboard shortcut for closing full-screen view")
                with header_col3:
                    close_key = "close_manual_fullscreen" if is_manual else "close_fullscreen"
                    if st.button("❌ Close", key=close_key, help="Close full-screen view (or press ESC)"):
                        if is_manual:
                            st.session_state.show_manual_fullscreen_viz = False
                        else:
                            st.session_state.show_fullscreen_viz = False
                        st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

                # Add JavaScript for keyboard shortcuts
                st.markdown("""
                <script>
                document.addEventListener('keydown', function(event) {
                    if (event.key === 'Escape') {
                        // Trigger close button click
                        const closeButton = document.querySelector('[data-testid="baseButton-secondary"]');
                        if (closeButton && closeButton.textContent.includes('Close')) {
                            closeButton.click();
                        }
                    }
                    if (event.key === 'f' || event.key === 'F') {
                        // Toggle full-screen (browser full-screen)
                        if (!document.fullscreenElement) {
                            document.documentElement.requestFullscreen();
                        } else {
                            document.exitFullscreen();
                        }
                    }
                });
                </script>
                """, unsafe_allow_html=True)

            # Enhanced visualization controls with better styling (outside the header container)
            st.markdown('<div class="control-panel">', unsafe_allow_html=True)
            st.markdown("### 🎛️ Visualization Controls")
            st.markdown("**Keyboard Shortcuts:** ESC = Close | F = Browser Full-Screen | Mouse Wheel = Zoom")
            control_col1, control_col2, control_col3, control_col4 = st.columns(4)

            with control_col1:
                layout_type = st.selectbox(
                    "Layout Style",
                    ["Mind Map", "Linear Flow", "Flowchart Diagram", "Hierarchical", "Network Graph"],
                    key=f"fullscreen_layout_{'manual' if is_manual else 'auto'}"
                )

            with control_col2:
                show_sub_techniques = st.checkbox(
                    "Show Sub-techniques",
                    value=True,
                    key=f"fullscreen_sub_tech_{'manual' if is_manual else 'auto'}"
                )

            with control_col3:
                show_attack_chains = st.checkbox(
                    "Show Attack Chains",
                    value=True,
                    key=f"fullscreen_chains_{'manual' if is_manual else 'auto'}"
                )

            with control_col4:
                enhanced_mode = st.checkbox(
                    "Enhanced Mode",
                    value=True,
                    help="Enable enhanced styling and animations",
                    key=f"fullscreen_enhanced_{'manual' if is_manual else 'auto'}"
                )

            st.markdown('</div>', unsafe_allow_html=True)  # Close control panel
            st.markdown("---")

            # Render the enhanced full-screen visualization
            if layout_type == "Mind Map":
                self._render_fullscreen_mind_map(path_data, show_sub_techniques, show_attack_chains, enhanced_mode)
            elif layout_type == "Linear Flow":
                self._render_fullscreen_linear_flow(path_data, show_sub_techniques, enhanced_mode)
            elif layout_type == "Flowchart Diagram":
                self._render_fullscreen_flowchart(path_data, show_sub_techniques, show_attack_chains, enhanced_mode)
            elif layout_type == "Hierarchical":
                self._render_fullscreen_hierarchical(path_data, show_sub_techniques, show_attack_chains, enhanced_mode)
            else:  # Network Graph
                self._render_fullscreen_network_graph(path_data, show_sub_techniques, enhanced_mode)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen visualization: {e}")
            st.error(f"Error rendering full-screen visualization: {str(e)}")

    def _render_fullscreen_mind_map(self, path_data: Dict[str, Any], show_sub_techniques: bool,
                                   show_attack_chains: bool, enhanced_mode: bool):
        """Render full-screen mind map visualization with enhanced features"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            nodes = []
            edges = []

            # Create center node (attack scenario) - larger for full screen
            center_id = "attack_scenario"
            nodes.append(Node(
                id=center_id,
                label="🎯 Attack\nScenario",
                size=80 if enhanced_mode else 60,
                shape='star',
                font={'color': 'white', 'size': 20 if enhanced_mode else 16, 'face': 'arial bold'},
                borderWidth=6 if enhanced_mode else 4,
                color={
                    'border': '#1a237e',
                    'background': 'linear-gradient(45deg, #3f51b5, #1a237e)' if enhanced_mode else '#3f51b5',
                    'highlight': {'border': '#0d47a1', 'background': '#1976d2'}
                },
                title="Central Attack Scenario"
            ))

            # Add path nodes in radial layout
            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Enhanced sizing for full screen
                size_multiplier = 1.5 if enhanced_mode else 1.2
                font_size = int(node_info['font']['size'] * 1.3) if enhanced_mode else node_info['font']['size']

                # Create main node
                nodes.append(Node(
                    id=node_id,
                    label=node_info['label'],
                    size=int(node_info['size'] * size_multiplier),
                    shape=node_info['shape'],
                    font={**node_info['font'], 'size': font_size},
                    borderWidth=node_info['border_width'] + (2 if enhanced_mode else 0),
                    color=node_info['color'],
                    title=node_info['title']
                ))

                # Connect to center
                edges.append(Edge(
                    source=center_id,
                    target=node_id,
                    color=node_info['edge_color'],
                    width=4 if enhanced_mode else 3,
                    arrows={'to': {'enabled': True, 'scaleFactor': 1.5 if enhanced_mode else 1.2}},
                    smooth={'enabled': True, 'type': 'dynamic'},
                    dashes=node_info.get('dashed', False)
                ))

                # Add sub-techniques
                if show_sub_techniques and node_info['sub_techniques']:
                    for j, sub_tech in enumerate(node_info['sub_techniques'][:3]):  # Show more in full screen
                        sub_id = f"{node_id}_sub_{j}"
                        sub_info = self._get_sub_technique_info(sub_tech, coverage)

                        nodes.append(Node(
                            id=sub_id,
                            label=sub_info['label'],
                            size=25 if enhanced_mode else 20,
                            shape='triangle',
                            font={'color': 'white', 'size': 11 if enhanced_mode else 9},
                            color=sub_info['color'],
                            title=sub_info['title']
                        ))

                        edges.append(Edge(
                            source=node_id,
                            target=sub_id,
                            color="#888888",
                            width=2 if enhanced_mode else 1,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.8}},
                            dashes=True
                        ))

                # Add attack chain connections
                if show_attack_chains and i < len(path) - 1:
                    edges.append(Edge(
                        source=node_id,
                        target=path[i + 1],
                        color="#ff6b35",
                        width=5 if enhanced_mode else 3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.5}},
                        smooth={'enabled': True, 'type': 'dynamic'},
                        label="⚡" if enhanced_mode else ""
                    ))

            # Full-screen mind map configuration with dynamic sizing
            config = Config(
                width="100%",  # Use percentage for responsive design
                height=800 if enhanced_mode else 700,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 300 if enhanced_mode else 200},
                    "barnesHut": {
                        "gravitationalConstant": -4000 if enhanced_mode else -3000,
                        "centralGravity": 0.1,
                        "springLength": 200 if enhanced_mode else 150,
                        "springConstant": 0.02,
                        "damping": 0.15
                    }
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True,
                    "navigationButtons": True if enhanced_mode else False
                },
                layout={
                    "randomSeed": 42,
                    "improvedLayout": True
                }
            )

            st.markdown("### 🧠 Enhanced Attack Path Mind Map")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen mind map: {e}")
            st.error(f"Error rendering full-screen mind map: {str(e)}")

    def _render_fullscreen_linear_flow(self, path_data: Dict[str, Any], show_sub_techniques: bool, enhanced_mode: bool):
        """Render full-screen linear flow visualization"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            nodes = []
            edges = []

            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Enhanced sizing for full screen
                size_multiplier = 1.4 if enhanced_mode else 1.2
                font_size = int(node_info['font']['size'] * 1.2) if enhanced_mode else node_info['font']['size']

                # Create main node with enhanced styling
                nodes.append(Node(
                    id=node_id,
                    label=node_info['label'],
                    size=int(node_info['size'] * size_multiplier),
                    shape=node_info['shape'],
                    font={**node_info['font'], 'size': font_size},
                    borderWidth=node_info['border_width'] + (1 if enhanced_mode else 0),
                    color=node_info['color'],
                    title=node_info['title']
                ))

                # Add sub-techniques
                if show_sub_techniques and node_info['sub_techniques']:
                    for j, sub_tech in enumerate(node_info['sub_techniques'][:3]):
                        sub_id = f"{node_id}_sub_{j}"
                        sub_info = self._get_sub_technique_info(sub_tech, coverage)

                        nodes.append(Node(
                            id=sub_id,
                            label=sub_info['label'],
                            size=22 if enhanced_mode else 18,
                            shape='triangle',
                            font={'color': 'white', 'size': 10 if enhanced_mode else 9},
                            color=sub_info['color'],
                            title=sub_info['title']
                        ))

                        edges.append(Edge(
                            source=node_id,
                            target=sub_id,
                            color="#888888",
                            width=2 if enhanced_mode else 1,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.6}},
                            dashes=True
                        ))

                # Add flow edge to next node
                if i < len(path) - 1:
                    edges.append(Edge(
                        source=node_id,
                        target=path[i + 1],
                        color=node_info['edge_color'],
                        width=5 if enhanced_mode else 4,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.8 if enhanced_mode else 1.5}},
                        smooth={'enabled': True, 'type': 'dynamic'},
                        label=f"Step {i+1}" if enhanced_mode else ""
                    ))

            # Full-screen linear flow configuration
            config = Config(
                width="100%",
                height=600 if enhanced_mode else 500,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 200 if enhanced_mode else 150},
                    "barnesHut": {
                        "gravitationalConstant": -6000 if enhanced_mode else -5000,
                        "centralGravity": 0.2,
                        "springLength": 250 if enhanced_mode else 200,
                        "springConstant": 0.03,
                        "damping": 0.12
                    }
                },
                hierarchical={
                    "enabled": True,
                    "levelSeparation": 300 if enhanced_mode else 250,
                    "nodeSpacing": 180 if enhanced_mode else 150,
                    "treeSpacing": 250 if enhanced_mode else 200,
                    "blockShifting": True,
                    "edgeMinimization": True,
                    "parentCentralization": True,
                    "direction": "LR",
                    "sortMethod": "directed"
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True,
                    "navigationButtons": True if enhanced_mode else False
                }
            )

            st.markdown("### ➡️ Enhanced Linear Attack Flow")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen linear flow: {e}")
            st.error(f"Error rendering full-screen linear flow: {str(e)}")

    def _render_fullscreen_flowchart(self, path_data: Dict[str, Any], show_sub_techniques: bool,
                                   show_attack_chains: bool, enhanced_mode: bool):
        """Render full-screen flowchart visualization with enhanced professional styling"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            nodes = []
            edges = []

            # Create enhanced start node for fullscreen
            start_node = Node(
                id="start_node",
                label="🎯 Attack\nInitiation",
                size=60 if enhanced_mode else 50,
                shape='box',
                font={'color': 'white', 'size': 18 if enhanced_mode else 14, 'face': 'arial bold'},
                borderWidth=4 if enhanced_mode else 3,
                color={
                    'border': '#1565c0',
                    'background': 'linear-gradient(135deg, #1976d2, #1565c0)' if enhanced_mode else '#1976d2',
                    'highlight': {'border': '#0d47a1', 'background': '#1976d2'}
                },
                title="Attack Initiation Point - Full Screen View",
                x=0,
                y=0
            )
            nodes.append(start_node)

            # Process path nodes with enhanced fullscreen styling
            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Enhanced positioning for fullscreen flowchart
                level = i + 1
                x_pos = 0 if level % 2 == 1 else (300 if (level // 2) % 2 == 0 else -300)
                y_pos = level * (200 if enhanced_mode else 150)

                # Create enhanced flowchart node
                enhanced_node = self._create_enhanced_flowchart_node(node_id, node_info, x_pos, y_pos, enhanced_mode)
                nodes.append(enhanced_node)

                # Enhanced connections
                if i == 0:
                    # Connect to start node with enhanced styling
                    edges.append(Edge(
                        source="start_node",
                        target=node_id,
                        color="#1976d2",
                        width=4 if enhanced_mode else 3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 2.0 if enhanced_mode else 1.5}},
                        smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.2},
                        label="Initiates Attack" if enhanced_mode else "Initiates"
                    ))
                else:
                    # Enhanced connection to previous node
                    edges.append(Edge(
                        source=path[i-1],
                        target=node_id,
                        color=self._get_flowchart_edge_color(node_info),
                        width=4 if enhanced_mode else 3,
                        arrows={'to': {'enabled': True, 'scaleFactor': 2.0 if enhanced_mode else 1.5}},
                        smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.3},
                        label=f"Attack Step {i+1}" if enhanced_mode else f"Step {i+1}"
                    ))

                # Enhanced sub-techniques for fullscreen
                if show_sub_techniques and node_info['sub_techniques']:
                    self._add_enhanced_flowchart_sub_techniques(nodes, edges, node_id, node_info, x_pos, y_pos, coverage, enhanced_mode)

                # Enhanced attack chains for fullscreen
                if show_attack_chains and i < len(path) - 1:
                    self._add_enhanced_flowchart_attack_chains(nodes, edges, node_id, x_pos, y_pos, i, enhanced_mode)

            # Enhanced end node for fullscreen
            end_node = Node(
                id="end_node",
                label="🎯 Mission\nAccomplished",
                size=60 if enhanced_mode else 50,
                shape='star',
                font={'color': 'white', 'size': 18 if enhanced_mode else 14, 'face': 'arial bold'},
                borderWidth=4 if enhanced_mode else 3,
                color={
                    'border': '#2e7d32',
                    'background': 'linear-gradient(135deg, #4caf50, #2e7d32)' if enhanced_mode else '#4caf50',
                    'highlight': {'border': '#1b5e20', 'background': '#4caf50'}
                },
                title="Attack Objective Successfully Completed",
                x=0,
                y=(len(path) + 1) * (200 if enhanced_mode else 150)
            )
            nodes.append(end_node)

            # Enhanced final connection
            if path:
                edges.append(Edge(
                    source=path[-1],
                    target="end_node",
                    color="#4caf50",
                    width=5 if enhanced_mode else 4,
                    arrows={'to': {'enabled': True, 'scaleFactor': 2.5 if enhanced_mode else 2.0}},
                    smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.2},
                    label="Mission Complete" if enhanced_mode else "Completes"
                ))

            # Enhanced fullscreen flowchart configuration
            config = Config(
                width="100%",
                height=max(800 if enhanced_mode else 700, len(path) * 150 + 300),
                directed=True,
                physics={
                    "enabled": False  # Use fixed positions for professional flowchart
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True,
                    "navigationButtons": True if enhanced_mode else False,
                    "multiselect": True if enhanced_mode else False
                },
                layout={
                    "randomSeed": 42,
                    "improvedLayout": False
                }
            )

            st.markdown("### 📊 Enhanced Professional Flowchart")
            if enhanced_mode:
                st.info("💡 **Enhanced Mode**: Professional attack path flowchart with detailed decision points and enhanced interactivity")
            else:
                st.info("💡 **Flowchart View**: Professional attack path visualization with clear decision points and flow")

            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen flowchart: {e}")
            st.error(f"Error rendering full-screen flowchart: {str(e)}")

    def _create_enhanced_flowchart_node(self, node_id: str, node_info: Dict[str, Any], x_pos: int, y_pos: int, enhanced_mode: bool) -> Node:
        """Create enhanced flowchart node for fullscreen view"""
        # Enhanced sizing for fullscreen
        size_multiplier = 1.5 if enhanced_mode else 1.2
        font_multiplier = 1.4 if enhanced_mode else 1.2

        # Determine enhanced node properties
        if node_id in self.tactic_order:
            shape = 'box'
            base_size = 55
            border_width = 5 if enhanced_mode else 4
        elif '.' in node_id:
            shape = 'diamond'
            base_size = 40
            border_width = 4 if enhanced_mode else 3
        else:
            shape = 'ellipse'
            base_size = 45
            border_width = 4 if enhanced_mode else 3

        # Enhanced color scheme
        color_scheme = node_info.get('color', {})
        if enhanced_mode and 'background' in color_scheme:
            # Add enhanced gradients for fullscreen
            if 'linear-gradient' not in str(color_scheme['background']):
                if '#4caf50' in str(color_scheme.get('border', '')):
                    color_scheme['background'] = 'linear-gradient(135deg, #4caf50, #2e7d32)'
                elif '#ff9800' in str(color_scheme.get('border', '')):
                    color_scheme['background'] = 'linear-gradient(135deg, #ff9800, #e65100)'
                elif '#f44336' in str(color_scheme.get('border', '')):
                    color_scheme['background'] = 'linear-gradient(135deg, #f44336, #b71c1c)'
                else:
                    color_scheme['background'] = 'linear-gradient(135deg, #1976d2, #1565c0)'

        return Node(
            id=node_id,
            label=node_info['label'],
            size=int(base_size * size_multiplier),
            shape=shape,
            font={
                'color': 'white',
                'size': int(node_info.get('font', {}).get('size', 12) * font_multiplier),
                'face': 'arial bold'
            },
            borderWidth=border_width,
            color=color_scheme,
            title=node_info['title'],
            x=x_pos,
            y=y_pos
        )

    def _add_enhanced_flowchart_sub_techniques(self, nodes: List[Node], edges: List[Edge], parent_id: str,
                                             node_info: Dict[str, Any], x_pos: int, y_pos: int,
                                             coverage: Dict[str, Any], enhanced_mode: bool):
        """Add enhanced sub-techniques for fullscreen flowchart"""
        sub_techniques = node_info.get('sub_techniques', [])[:4 if enhanced_mode else 3]

        for i, sub_tech in enumerate(sub_techniques):
            sub_id = f"{parent_id}_sub_{i}"
            sub_info = self._get_sub_technique_info(sub_tech, coverage)

            # Enhanced positioning for fullscreen
            sub_x = x_pos + (200 * (i - len(sub_techniques)/2 + 0.5))
            sub_y = y_pos + (120 if enhanced_mode else 100)

            # Enhanced sub-technique node
            # Extract rule count for label
            rule_text = "0"
            title_text = sub_info.get('title', '')
            if 'Rules:' in title_text:
                try:
                    rule_text = title_text.split('Rules:')[-1].split('\n')[0].strip()
                except:
                    rule_text = "0"

            sub_node = Node(
                id=sub_id,
                label=f"🔸 {sub_tech}\n({rule_text} rules)",
                size=35 if enhanced_mode else 28,
                shape='diamond',
                font={'color': 'white', 'size': 12 if enhanced_mode else 10, 'face': 'arial'},
                borderWidth=3 if enhanced_mode else 2,
                color={
                    'border': sub_info['color']['border'],
                    'background': f"linear-gradient(135deg, {sub_info['color']['background']}, {sub_info['color']['border']})" if enhanced_mode else sub_info['color']['background'],
                    'highlight': {'border': sub_info['color']['border'], 'background': sub_info['color']['background']}
                },
                title=sub_info['title'],
                x=sub_x,
                y=sub_y
            )
            nodes.append(sub_node)

            # Enhanced connection
            edge = Edge(
                source=parent_id,
                target=sub_id,
                color="#666666",
                width=3 if enhanced_mode else 2,
                arrows={'to': {'enabled': True, 'scaleFactor': 1.2 if enhanced_mode else 0.8}},
                smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.4},
                dashes=True,
                label="variant" if enhanced_mode else ""
            )
            edges.append(edge)

    def _add_enhanced_flowchart_attack_chains(self, nodes: List[Node], edges: List[Edge], current_id: str,
                                            x_pos: int, y_pos: int, step_index: int, enhanced_mode: bool):
        """Add enhanced attack chain elements for fullscreen"""
        # Enhanced chain decision point
        chain_id = f"chain_{step_index}"
        chain_node = Node(
            id=chain_id,
            label="⚡" if not enhanced_mode else "⚡\nChain",
            size=30 if enhanced_mode else 25,
            shape='triangle',
            font={'color': 'white', 'size': 18 if enhanced_mode else 16, 'face': 'arial bold'},
            borderWidth=3 if enhanced_mode else 2,
            color={
                'border': '#ff6b35',
                'background': 'linear-gradient(135deg, #ff8a50, #ff6b35)' if enhanced_mode else '#ff8a50',
                'highlight': {'border': '#e64a19', 'background': '#ff8a50'}
            },
            title=f"Enhanced Attack Chain Step {step_index + 1}",
            x=x_pos + (150 if enhanced_mode else 120),
            y=y_pos + (100 if enhanced_mode else 80)
        )
        nodes.append(chain_node)

        # Enhanced connection
        edges.append(Edge(
            source=current_id,
            target=chain_id,
            color="#ff6b35",
            width=3 if enhanced_mode else 2,
            arrows={'to': {'enabled': True, 'scaleFactor': 1.5 if enhanced_mode else 1.0}},
            smooth={'enabled': True, 'type': 'curvedCW', 'roundness': 0.5},
            label="chains to" if enhanced_mode else ""
        ))

    def _render_fullscreen_hierarchical(self, path_data: Dict[str, Any], show_sub_techniques: bool,
                                       show_attack_chains: bool, enhanced_mode: bool):
        """Render full-screen hierarchical visualization"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            nodes = []
            edges = []

            # Group techniques by tactic
            tactic_groups = {}
            for node_id in path:
                if node_id in self.tactic_order:
                    tactic_groups[node_id] = []
                else:
                    # Find the tactic for this technique
                    technique_info = self._get_technique_info(node_id)
                    tactic = technique_info.get('tactic', 'unknown')
                    if tactic not in tactic_groups:
                        tactic_groups[tactic] = []
                    tactic_groups[tactic].append(node_id)

            # Create tactic nodes with enhanced styling
            tactic_y_positions = {}
            for i, (tactic_id, techniques) in enumerate(tactic_groups.items()):
                if tactic_id in self.tactic_order:
                    tactic_info = self._get_tactic_node_info(tactic_id)
                    y_pos = i * (250 if enhanced_mode else 200)
                    tactic_y_positions[tactic_id] = y_pos

                    # Enhanced tactic node
                    nodes.append(Node(
                        id=tactic_id,
                        label=tactic_info['label'],
                        size=int(tactic_info['size'] * (1.5 if enhanced_mode else 1.2)),
                        shape=tactic_info['shape'],
                        font={**tactic_info['font'], 'size': int(tactic_info['font']['size'] * 1.2)},
                        borderWidth=tactic_info['border_width'] + (2 if enhanced_mode else 0),
                        color=tactic_info['color'],
                        title=tactic_info['title'],
                        x=0,
                        y=y_pos
                    ))

                    # Add technique nodes under each tactic
                    for j, technique_id in enumerate(techniques):
                        technique_info = self._get_enhanced_node_info(technique_id, coverage, show_sub_techniques)

                        nodes.append(Node(
                            id=technique_id,
                            label=technique_info['label'],
                            size=int(technique_info['size'] * (1.3 if enhanced_mode else 1.1)),
                            shape=technique_info['shape'],
                            font={**technique_info['font'], 'size': int(technique_info['font']['size'] * 1.1)},
                            borderWidth=technique_info['border_width'] + (1 if enhanced_mode else 0),
                            color=technique_info['color'],
                            title=technique_info['title'],
                            x=400 + (j * (180 if enhanced_mode else 150)),
                            y=y_pos
                        ))

                        # Connect technique to tactic
                        edges.append(Edge(
                            source=tactic_id,
                            target=technique_id,
                            color="#666666",
                            width=3 if enhanced_mode else 2,
                            arrows={'to': {'enabled': True, 'scaleFactor': 1.2 if enhanced_mode else 1.0}}
                        ))

            # Add attack chain connections between tactics
            if show_attack_chains:
                tactic_list = list(tactic_y_positions.keys())
                for i in range(len(tactic_list) - 1):
                    edges.append(Edge(
                        source=tactic_list[i],
                        target=tactic_list[i + 1],
                        color="#ff4444",
                        width=6 if enhanced_mode else 5,
                        arrows={'to': {'enabled': True, 'scaleFactor': 2.5 if enhanced_mode else 2.0}},
                        smooth={'enabled': True, 'type': 'curvedCW'},
                        label="⚡ Attack Chain" if enhanced_mode else "⚡"
                    ))

            # Full-screen hierarchical configuration
            config = Config(
                width="100%",
                height=900 if enhanced_mode else 800,
                directed=True,
                physics={
                    "enabled": False  # Use fixed positions
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True,
                    "navigationButtons": True if enhanced_mode else False
                }
            )

            st.markdown("### 🌳 Enhanced Hierarchical Attack Tree")
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen hierarchical visualization: {e}")
            st.error(f"Error rendering full-screen hierarchical visualization: {str(e)}")

    def _render_fullscreen_network_graph(self, path_data: Dict[str, Any], show_sub_techniques: bool, enhanced_mode: bool):
        """Render full-screen network graph visualization"""
        try:
            if 'error' in path_data:
                st.error(f"❌ {path_data['error']}")
                return

            path = path_data.get('path', [])
            coverage = path_data.get('coverage', {})

            if not path:
                st.warning("No attack path generated")
                return

            nodes = []
            edges = []

            # Create all nodes with enhanced styling
            for i, node_id in enumerate(path):
                node_info = self._get_enhanced_node_info(node_id, coverage, show_sub_techniques)

                # Enhanced sizing for full screen
                size_multiplier = 1.6 if enhanced_mode else 1.3
                font_size = int(node_info['font']['size'] * 1.3) if enhanced_mode else node_info['font']['size']

                nodes.append(Node(
                    id=node_id,
                    label=node_info['label'],
                    size=int(node_info['size'] * size_multiplier),
                    shape=node_info['shape'],
                    font={**node_info['font'], 'size': font_size},
                    borderWidth=node_info['border_width'] + (2 if enhanced_mode else 0),
                    color=node_info['color'],
                    title=node_info['title']
                ))

                # Add sub-techniques as separate nodes
                if show_sub_techniques and node_info['sub_techniques']:
                    for j, sub_tech in enumerate(node_info['sub_techniques'][:4]):  # Show more in network view
                        sub_id = f"{node_id}_sub_{j}"
                        sub_info = self._get_sub_technique_info(sub_tech, coverage)

                        nodes.append(Node(
                            id=sub_id,
                            label=sub_info['label'],
                            size=28 if enhanced_mode else 22,
                            shape='diamond',
                            font={'color': 'white', 'size': 11 if enhanced_mode else 9},
                            color=sub_info['color'],
                            title=sub_info['title']
                        ))

                        # Connect sub-technique to main technique
                        edges.append(Edge(
                            source=node_id,
                            target=sub_id,
                            color="#888888",
                            width=2 if enhanced_mode else 1,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.8}},
                            dashes=True,
                            length=100 if enhanced_mode else 80
                        ))

            # Create network connections between all path nodes
            for i in range(len(path)):
                for j in range(i + 1, len(path)):
                    # Create connections with varying strengths
                    connection_strength = max(1, 5 - abs(i - j))  # Stronger for closer nodes

                    edges.append(Edge(
                        source=path[i],
                        target=path[j],
                        color=f"rgba(100, 150, 255, {0.3 + (connection_strength * 0.1)})",
                        width=connection_strength if enhanced_mode else max(1, connection_strength - 1),
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.0}},
                        smooth={'enabled': True, 'type': 'dynamic'},
                        length=150 + (abs(i - j) * 50)  # Longer edges for distant nodes
                    ))

            # Full-screen network configuration with enhanced physics
            config = Config(
                width="100%",
                height=800 if enhanced_mode else 700,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 400 if enhanced_mode else 300},
                    "barnesHut": {
                        "gravitationalConstant": -3000 if enhanced_mode else -2500,
                        "centralGravity": 0.05,
                        "springLength": 200 if enhanced_mode else 150,
                        "springConstant": 0.04,
                        "damping": 0.1,
                        "avoidOverlap": 0.2 if enhanced_mode else 0.1
                    },
                    "repulsion": {
                        "centralGravity": 0.05,
                        "springLength": 250 if enhanced_mode else 200,
                        "springConstant": 0.03,
                        "nodeDistance": 200 if enhanced_mode else 150,
                        "damping": 0.1
                    }
                },
                interaction={
                    "hover": True,
                    "hoverConnectedEdges": True,
                    "selectConnectedEdges": True,
                    "zoomView": True,
                    "dragView": True,
                    "navigationButtons": True if enhanced_mode else False,
                    "multiselect": True if enhanced_mode else False
                },
                layout={
                    "randomSeed": 42,
                    "improvedLayout": True
                }
            )

            st.markdown("### 🕸️ Enhanced Network Graph")
            if enhanced_mode:
                st.info("💡 **Enhanced Mode**: Use mouse wheel to zoom, drag to pan, click and drag nodes to rearrange")

            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering full-screen network graph: {e}")
            st.error(f"Error rendering full-screen network graph: {str(e)}")

    def _render_path_analysis(self, path_data: Dict[str, Any]):
        """Render attack path analysis"""
        st.markdown("#### 📊 Path Analysis")
        
        path = path_data.get('path', [])
        coverage = path_data.get('coverage', {})
        
        if not path:
            return
        
        # Path statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Path Length", len(path))
        
        with col2:
            total_rules = sum(c.get('rule_count', 0) for c in coverage.values())
            st.metric("Path Rules", total_rules)
        
        with col3:
            covered_steps = sum(1 for c in coverage.values() if c.get('rule_count', 0) > 0)
            coverage_pct = (covered_steps / len(path)) * 100 if path else 0
            st.metric("Coverage", f"{coverage_pct:.1f}%")
        
        with col4:
            avg_rules = total_rules / len(path) if path else 0
            st.metric("Avg Rules/Step", f"{avg_rules:.1f}")
        
        # Detailed path breakdown
        st.markdown("#### 🔍 Path Breakdown")
        
        for i, step in enumerate(path):
            step_coverage = coverage.get(step, {})
            rule_count = step_coverage.get('rule_count', 0)
            
            with st.expander(f"Step {i+1}: {step} ({rule_count} rules)"):
                col1, col2 = st.columns(2)
                
                with col1:
                    if step in self.tactic_order:
                        st.markdown(f"**Type:** Tactic")
                        st.markdown(f"**Description:** {step.replace('-', ' ').title()}")
                    else:
                        technique_info = self._get_technique_info(step)
                        st.markdown(f"**Type:** Technique")
                        st.markdown(f"**Name:** {technique_info.get('name', 'Unknown')}")
                        st.markdown(f"**Description:** {technique_info.get('description', 'No description')[:100]}...")
                
                with col2:
                    st.markdown(f"**Rule Coverage:** {rule_count} rules")

                    if rule_count > 0:
                        rules = step_coverage.get('rules', [])
                        # Remove duplicates by title and show unique rules
                        unique_rules = []
                        seen_titles = set()
                        for rule in rules:
                            title = rule.get('title', 'Unknown Rule')
                            if title not in seen_titles:
                                unique_rules.append(rule)
                                seen_titles.add(title)

                        # Show first 3 unique rules
                        for rule in unique_rules[:3]:
                            title = rule.get('title', 'Unknown Rule')
                            confidence = rule.get('confidence', 0)
                            st.write(f"• {title} (confidence: {confidence:.2f})")

                        if len(unique_rules) > 3:
                            st.write(f"• ... and {len(unique_rules) - 3} more unique rules")
    
    def _get_techniques_by_tactic(self, platforms: List[str]) -> Dict[str, List[Dict]]:
        """Get techniques organized by tactic"""
        try:
            techniques = self.db_manager.get_mitre_techniques()
            techniques_by_tactic = {}

            for technique in techniques:
                db_tactic = technique.get('tactic', '')
                # Convert database tactic format to display format
                display_tactic = self.db_tactic_mapping.get(db_tactic, '').lower()

                if display_tactic and display_tactic in self.tactic_order:
                    # Filter by platform if specified
                    technique_platforms = json.loads(technique.get('platform', '[]'))
                    if not platforms or any(p in technique_platforms for p in platforms):
                        if display_tactic not in techniques_by_tactic:
                            techniques_by_tactic[display_tactic] = []
                        techniques_by_tactic[display_tactic].append(technique)

            return techniques_by_tactic

        except Exception as e:
            self.logger.error(f"Error getting techniques by tactic: {e}")
            return {}
    
    def _get_coverage_metrics(self) -> Dict[str, Any]:
        """Get overall coverage metrics from database - USES CENTRALIZED METHOD"""
        return self.db_manager.get_coverage_metrics()
    
    def _get_attack_scenarios(self) -> List[Dict[str, Any]]:
        """Get both predefined and custom attack scenarios"""
        # Load predefined scenarios from database or configuration
        predefined_scenarios = self._load_predefined_scenarios()

        # Get custom scenarios from database
        try:
            custom_scenarios = self.db_manager.get_custom_scenarios()

            # Calculate coverage for custom scenarios
            for scenario in custom_scenarios:
                scenario['is_custom'] = True
                scenario['coverage'] = self._calculate_scenario_coverage(scenario.get('techniques', []))

            # Combine predefined and custom scenarios
            all_scenarios = predefined_scenarios + custom_scenarios
            return all_scenarios

        except Exception as e:
            self.logger.error(f"Error loading custom scenarios: {e}")
            return predefined_scenarios

    def _calculate_scenario_coverage(self, techniques: List[str]) -> float:
        """Calculate coverage percentage for a scenario - USES CENTRALIZED METHOD"""
        return self.db_manager.calculate_scenario_coverage(techniques)

    def _select_best_path(self, paths: List[List[str]], prioritize_coverage: bool) -> List[str]:
        """Select the best attack path from available options"""
        if not paths:
            return []

        if len(paths) == 1:
            return paths[0]

        # Score paths based on criteria
        scored_paths = []
        for path in paths:
            score = 0

            # Length score (prefer shorter paths)
            length_score = max(0, 10 - len(path))
            score += length_score

            # Coverage score (if prioritizing coverage)
            if prioritize_coverage:
                coverage_score = self._calculate_path_coverage_score(path)
                score += coverage_score * 2

            # Tactic diversity score
            tactics_in_path = [step for step in path if step in self.tactic_order]
            diversity_score = len(set(tactics_in_path))
            score += diversity_score

            scored_paths.append((path, score))

        # Return path with highest score
        best_path = max(scored_paths, key=lambda x: x[1])[0]
        return best_path

    def _calculate_path_coverage_score(self, path: List[str]) -> float:
        """Calculate coverage score for a path - USES CENTRALIZED METHOD"""
        return self.db_manager.calculate_path_coverage_score(path, self.tactic_order)

    def _get_path_coverage(self, path: List[str]) -> Dict[str, Dict]:
        """Get rule coverage for each step in the path"""
        coverage = {}

        try:
            for step in path:
                if step in self.tactic_order:
                    # For tactics, get aggregate coverage
                    coverage[step] = {
                        'rule_count': 0,
                        'rules': [],
                        'type': 'tactic'
                    }
                else:
                    # For techniques, get specific rule coverage
                    rules = self._get_rules_for_technique(step)
                    coverage[step] = {
                        'rule_count': len(rules),
                        'rules': rules,
                        'type': 'technique'
                    }

            return coverage

        except Exception as e:
            self.logger.error(f"Error getting path coverage: {e}")
            return {}

    def _get_rules_for_technique(self, technique_id: str) -> List[Dict]:
        """Get SIGMA rules that detect a specific technique - USES CENTRALIZED METHOD"""
        return self.db_manager.get_rules_for_technique(technique_id)

    def _get_technique_info(self, technique_id: str) -> Dict[str, Any]:
        """Get detailed information about a technique - USES CENTRALIZED METHOD"""
        try:
            # Use the centralized method from database manager
            technique_data = self.db_manager.get_mitre_technique_details(technique_id)
            return technique_data or {}

        except Exception as e:
            self.logger.error(f"Error getting technique info for {technique_id}: {e}")
            return {}











    def _create_alternative_path(self, start_tactic: str, target_tactic: str, techniques_by_tactic: Dict) -> List[str]:
        """Create alternative attack path when direct path is not found"""
        try:
            # Find the index positions of start and target tactics
            start_idx = self.tactic_order.index(start_tactic) if start_tactic in self.tactic_order else 0
            target_idx = self.tactic_order.index(target_tactic) if target_tactic in self.tactic_order else len(self.tactic_order) - 1

            # Create a simple path through tactics
            path = []

            if start_idx <= target_idx:
                # Forward path
                for i in range(start_idx, target_idx + 1):
                    tactic = self.tactic_order[i]
                    path.append(tactic)

                    # Add a technique from this tactic if available
                    if tactic in techniques_by_tactic and techniques_by_tactic[tactic]:
                        # Pick the first technique with best coverage
                        best_technique = None
                        best_coverage = -1

                        for technique in techniques_by_tactic[tactic][:3]:  # Check first 3
                            technique_id = technique.get('technique_id')
                            if technique_id:
                                rules = self._get_rules_for_technique(technique_id)
                                if len(rules) > best_coverage:
                                    best_coverage = len(rules)
                                    best_technique = technique_id

                        if best_technique:
                            path.append(best_technique)

            return path if len(path) > 1 else []

        except Exception as e:
            self.logger.error(f"Error creating alternative path: {e}")
            return []

    def _analyze_technique_relationships(self, technique_id: str, relationship_types: List[str],
                                       depth: int = 2, platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze relationships for a given technique"""
        try:
            # Input validation
            if not technique_id:
                return {
                    'center_technique': '',
                    'nodes': [],
                    'edges': [],
                    'relationship_details': {},
                    'error': 'Technique ID is required'
                }

            if not relationship_types:
                return {
                    'center_technique': technique_id,
                    'nodes': [],
                    'edges': [],
                    'relationship_details': {},
                    'error': 'At least one relationship type must be selected'
                }

            relationships = {
                'center_technique': technique_id,
                'nodes': [],
                'edges': [],
                'relationship_details': {}
            }

            # Get center technique info
            center_technique = self._get_technique_info(technique_id)

            # Check if technique exists in database (not just fallback data)
            if (not center_technique.get('technique_id') or
                center_technique.get('name') == technique_id or  # Fallback case
                center_technique.get('tactic') == 'Unknown'):    # Another fallback indicator

                # Double-check by querying database directly
                with self.db_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
                    count = cursor.fetchone()[0]

                    if count == 0:
                        return {
                            'center_technique': technique_id,
                            'nodes': [],
                            'edges': [],
                            'relationship_details': {},
                            'error': f'Technique {technique_id} not found in database'
                        }

            relationships['nodes'].append({
                'id': technique_id,
                'label': f"{technique_id}\n{center_technique.get('name', 'Unknown')[:20]}...",
                'type': 'center',
                'technique_info': center_technique
            })

            # Find related techniques based on relationship types
            # Handle None platforms parameter
            if platforms is None:
                platforms = []

            related_techniques = set()
            relationship_counts = {}

            # Find related techniques for each relationship type and track which type found each technique
            technique_to_types = {}  # Maps technique_id to list of relationship types that found it

            for rel_type in relationship_types:
                try:
                    if rel_type == 'Same Tactic':
                        found = self._find_same_tactic_techniques(technique_id, platforms)
                    elif rel_type == 'Shared Data Sources':
                        found = self._find_shared_data_source_techniques(technique_id, platforms)
                    elif rel_type == 'Rule Overlaps':
                        found = self._find_rule_overlap_techniques(technique_id, platforms)
                    elif rel_type == 'Similar Techniques':
                        found = self._find_similar_techniques(technique_id, platforms)
                    elif rel_type == 'Prerequisites':
                        found = self._find_prerequisite_techniques(technique_id, platforms)
                    elif rel_type == 'Enables':
                        found = self._find_enabled_techniques(technique_id, platforms)
                    else:
                        self.logger.warning(f"Unknown relationship type: {rel_type}")
                        continue

                    relationship_counts[rel_type] = len(found)
                    related_techniques.update(found)

                    # Track which relationship type found each technique
                    for tech_id in found:
                        if tech_id not in technique_to_types:
                            technique_to_types[tech_id] = []
                        technique_to_types[tech_id].append(rel_type)

                except Exception as e:
                    self.logger.error(f"Error finding {rel_type} relationships: {e}")
                    relationship_counts[rel_type] = 0

            # Add related technique nodes and edges
            added_techniques = 0
            max_techniques = 20  # Limit for visualization performance

            for related_id in list(related_techniques):
                if related_id != technique_id and added_techniques < max_techniques:
                    try:
                        related_info = self._get_technique_info(related_id)

                        # Skip if technique info not found
                        if not related_info.get('technique_id'):
                            continue

                        relationships['nodes'].append({
                            'id': related_id,
                            'label': f"{related_id}\n{related_info.get('name', 'Unknown')[:15]}...",
                            'type': 'related',
                            'technique_info': related_info
                        })

                        # Add edge with the user-selected relationship type(s)
                        # Use the first relationship type that found this technique
                        user_selected_type = technique_to_types.get(related_id, ['Related'])[0]

                        relationships['edges'].append({
                            'source': technique_id,
                            'target': related_id,
                            'relationship': user_selected_type
                        })

                        added_techniques += 1

                    except Exception as e:
                        self.logger.error(f"Error processing related technique {related_id}: {e}")
                        continue

            # Add relationship statistics
            relationships['relationship_details'] = {
                'total_found': len(related_techniques),
                'displayed': added_techniques,
                'counts_by_type': relationship_counts,
                'analysis_depth': depth,
                'platforms_filtered': platforms if platforms else []
            }

            return relationships

        except Exception as e:
            self.logger.error(f"Error analyzing technique relationships: {e}")
            return {
                'center_technique': technique_id,
                'nodes': [],
                'edges': [],
                'relationship_details': {},
                'error': str(e)
            }

    def _find_same_tactic_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques in the same tactic"""
        try:
            center_technique = self._get_technique_info(technique_id)
            center_tactic = center_technique.get('tactic', '')

            if not center_tactic:
                return []

            # Get techniques in same tactic (center_tactic is already in database format)
            same_tactic_techniques = self.db_manager.get_mitre_techniques({'tactic': center_tactic})

            related_ids = []
            for technique in same_tactic_techniques:
                tech_id = technique.get('technique_id')
                if tech_id and tech_id != technique_id:
                    # Filter by platform if specified
                    if platforms:
                        tech_platforms = json.loads(technique.get('platform', '[]'))
                        if any(p in tech_platforms for p in platforms):
                            related_ids.append(tech_id)
                    else:
                        related_ids.append(tech_id)

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding same tactic techniques: {e}")
            return []

    def _find_shared_data_source_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques that share data sources"""
        try:
            center_technique = self._get_technique_info(technique_id)
            center_data_sources = json.loads(center_technique.get('data_sources', '[]'))

            if not center_data_sources:
                return []

            # Get all techniques and find those with overlapping data sources
            all_techniques = self.db_manager.get_mitre_techniques()
            related_ids = []

            for technique in all_techniques:
                tech_id = technique.get('technique_id')
                if tech_id and tech_id != technique_id:
                    tech_data_sources = json.loads(technique.get('data_sources', '[]'))

                    # Check for overlap in data sources
                    if any(ds in tech_data_sources for ds in center_data_sources):
                        # Filter by platform if specified
                        if platforms:
                            tech_platforms = json.loads(technique.get('platform', '[]'))
                            if any(p in tech_platforms for p in platforms):
                                related_ids.append(tech_id)
                        else:
                            related_ids.append(tech_id)

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding shared data source techniques: {e}")
            return []

    def _find_rule_overlap_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques that share SIGMA rules"""
        try:
            # Note: platforms parameter available for future filtering if needed
            _ = platforms  # Acknowledge parameter to avoid warnings

            # Get rules for center technique
            center_rules = self._get_rules_for_technique(technique_id)
            center_rule_ids = [rule['rule_id'] for rule in center_rules]

            if not center_rule_ids:
                return []

            related_ids = []

            # Find other techniques that share these rules
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Get techniques that share rules
                placeholders = ','.join(['?' for _ in center_rule_ids])
                query = f"""
                    SELECT DISTINCT rtm.technique_id
                    FROM rule_technique_mappings rtm
                    WHERE rtm.rule_id IN ({placeholders})
                    AND rtm.technique_id != ?
                """

                cursor.execute(query, center_rule_ids + [technique_id])
                rows = cursor.fetchall()

                for row in rows:
                    related_ids.append(row[0])

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding rule overlap techniques: {e}")
            return []

    def _find_similar_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques with similar names or descriptions"""
        try:
            center_technique = self._get_technique_info(technique_id)
            center_name = center_technique.get('name', '').lower()
            center_desc = center_technique.get('description', '').lower()

            if not center_name:
                return []

            # Extract key terms from name and description
            import re
            key_terms = set()

            # Extract words from name (excluding common words)
            name_words = re.findall(r'\b\w{4,}\b', center_name)
            key_terms.update(name_words)

            # Extract key terms from description
            desc_words = re.findall(r'\b\w{5,}\b', center_desc[:200])  # First 200 chars
            key_terms.update(desc_words[:5])  # Top 5 terms

            # Remove common words
            common_words = {'technique', 'adversary', 'adversaries', 'attack', 'system', 'process', 'file', 'data'}
            key_terms = key_terms - common_words

            if not key_terms:
                return []

            # Find techniques with similar terms
            all_techniques = self.db_manager.get_mitre_techniques()
            related_ids = []

            for technique in all_techniques:
                tech_id = technique.get('technique_id')
                if tech_id and tech_id != technique_id:
                    tech_name = technique.get('name', '').lower()
                    tech_desc = technique.get('description', '').lower()

                    # Check for term overlap
                    tech_text = f"{tech_name} {tech_desc}"
                    overlap_count = sum(1 for term in key_terms if term in tech_text)

                    if overlap_count >= 2:  # At least 2 matching terms
                        # Filter by platform if specified
                        if platforms:
                            tech_platforms = json.loads(technique.get('platform', '[]'))
                            if any(p in tech_platforms for p in platforms):
                                related_ids.append(tech_id)
                        else:
                            related_ids.append(tech_id)

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding similar techniques: {e}")
            return []

    def _find_prerequisite_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques that are prerequisites for the given technique"""
        try:
            center_technique = self._get_technique_info(technique_id)
            center_tactic = center_technique.get('tactic', '')

            if not center_tactic:
                return []

            # Map tactic to its typical prerequisites based on MITRE ATT&CK kill chain
            tactic_prerequisites = {
                'Execution': ['Initial Access'],
                'Persistence': ['Initial Access', 'Execution'],
                'Privilege Escalation': ['Initial Access', 'Execution'],
                'Defense Evasion': ['Initial Access', 'Execution'],
                'Credential Access': ['Initial Access', 'Execution', 'Privilege Escalation'],
                'Discovery': ['Initial Access', 'Execution'],
                'Lateral Movement': ['Initial Access', 'Execution', 'Credential Access'],
                'Collection': ['Initial Access', 'Execution', 'Discovery'],
                'Command and Control': ['Initial Access', 'Execution'],
                'Exfiltration': ['Initial Access', 'Execution', 'Collection'],
                'Impact': ['Initial Access', 'Execution', 'Persistence']
            }

            prerequisite_tactics = tactic_prerequisites.get(center_tactic, [])
            related_ids = []

            for prereq_tactic in prerequisite_tactics:
                prereq_techniques = self.db_manager.get_mitre_techniques({'tactic': prereq_tactic})

                for technique in prereq_techniques:
                    tech_id = technique.get('technique_id')
                    if tech_id and tech_id != technique_id:
                        # Filter by platform if specified
                        if platforms:
                            tech_platforms = json.loads(technique.get('platform', '[]'))
                            if any(p in tech_platforms for p in platforms):
                                related_ids.append(tech_id)
                        else:
                            related_ids.append(tech_id)

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding prerequisite techniques: {e}")
            return []

    def _find_enabled_techniques(self, technique_id: str, platforms: List[str]) -> List[str]:
        """Find techniques that are enabled by the given technique"""
        try:
            center_technique = self._get_technique_info(technique_id)
            center_tactic = center_technique.get('tactic', '')

            if not center_tactic:
                return []

            # Map tactic to techniques it typically enables based on MITRE ATT&CK kill chain
            tactic_enables = {
                'Initial Access': ['Execution', 'Persistence', 'Defense Evasion'],
                'Execution': ['Persistence', 'Privilege Escalation', 'Defense Evasion', 'Discovery'],
                'Persistence': ['Privilege Escalation', 'Defense Evasion'],
                'Privilege Escalation': ['Defense Evasion', 'Credential Access', 'Discovery'],
                'Defense Evasion': ['Credential Access', 'Discovery', 'Lateral Movement'],
                'Credential Access': ['Discovery', 'Lateral Movement', 'Collection'],
                'Discovery': ['Lateral Movement', 'Collection', 'Command and Control'],
                'Lateral Movement': ['Collection', 'Command and Control', 'Exfiltration'],
                'Collection': ['Command and Control', 'Exfiltration'],
                'Command and Control': ['Exfiltration', 'Impact'],
                'Exfiltration': ['Impact'],
                'Impact': []  # Impact typically doesn't enable other tactics
            }

            enabled_tactics = tactic_enables.get(center_tactic, [])
            related_ids = []

            for enabled_tactic in enabled_tactics:
                enabled_techniques = self.db_manager.get_mitre_techniques({'tactic': enabled_tactic})

                for technique in enabled_techniques:
                    tech_id = technique.get('technique_id')
                    if tech_id and tech_id != technique_id:
                        # Filter by platform if specified
                        if platforms:
                            tech_platforms = json.loads(technique.get('platform', '[]'))
                            if any(p in tech_platforms for p in platforms):
                                related_ids.append(tech_id)
                        else:
                            related_ids.append(tech_id)

            return related_ids[:10]  # Limit results

        except Exception as e:
            self.logger.error(f"Error finding enabled techniques: {e}")
            return []

    def _determine_relationship_type(self, source_id: str, target_id: str) -> str:
        """Determine the type of relationship between two techniques"""
        try:
            source_info = self._get_technique_info(source_id)
            target_info = self._get_technique_info(target_id)

            source_tactic = source_info.get('tactic', '')
            target_tactic = target_info.get('tactic', '')

            # Check if same tactic
            if source_tactic == target_tactic:
                return 'Same Tactic'

            # Check for prerequisite relationship (source enables target)
            if self._is_prerequisite_relationship(source_tactic, target_tactic):
                return 'Prerequisites'

            # Check for enables relationship (source enables target)
            if self._is_enables_relationship(source_tactic, target_tactic):
                return 'Enables'

            # Check for shared data sources
            source_data_sources = json.loads(source_info.get('data_sources', '[]'))
            target_data_sources = json.loads(target_info.get('data_sources', '[]'))

            if any(ds in target_data_sources for ds in source_data_sources):
                return 'Shared Data Sources'

            # Check for rule overlap
            source_rules = self._get_rules_for_technique(source_id)
            target_rules = self._get_rules_for_technique(target_id)

            source_rule_ids = [rule['rule_id'] for rule in source_rules]
            target_rule_ids = [rule['rule_id'] for rule in target_rules]

            if any(rule_id in target_rule_ids for rule_id in source_rule_ids):
                return 'Rule Overlap'

            # Default to similar techniques
            return 'Similar'

        except Exception as e:
            self.logger.error(f"Error determining relationship type: {e}")
            return 'Related'

    def _is_prerequisite_relationship(self, source_tactic: str, target_tactic: str) -> bool:
        """Check if source tactic is a prerequisite for target tactic"""
        prerequisite_map = {
            'Execution': ['Initial Access'],
            'Persistence': ['Initial Access', 'Execution'],
            'Privilege Escalation': ['Initial Access', 'Execution'],
            'Defense Evasion': ['Initial Access', 'Execution'],
            'Credential Access': ['Initial Access', 'Execution', 'Privilege Escalation'],
            'Discovery': ['Initial Access', 'Execution'],
            'Lateral Movement': ['Initial Access', 'Execution', 'Credential Access'],
            'Collection': ['Initial Access', 'Execution', 'Discovery'],
            'Command and Control': ['Initial Access', 'Execution'],
            'Exfiltration': ['Initial Access', 'Execution', 'Collection'],
            'Impact': ['Initial Access', 'Execution', 'Persistence']
        }

        return source_tactic in prerequisite_map.get(target_tactic, [])

    def _is_enables_relationship(self, source_tactic: str, target_tactic: str) -> bool:
        """Check if source tactic enables target tactic"""
        enables_map = {
            'Initial Access': ['Execution', 'Persistence', 'Defense Evasion'],
            'Execution': ['Persistence', 'Privilege Escalation', 'Defense Evasion', 'Discovery'],
            'Persistence': ['Privilege Escalation', 'Defense Evasion'],
            'Privilege Escalation': ['Defense Evasion', 'Credential Access', 'Discovery'],
            'Defense Evasion': ['Credential Access', 'Discovery', 'Lateral Movement'],
            'Credential Access': ['Discovery', 'Lateral Movement', 'Collection'],
            'Discovery': ['Lateral Movement', 'Collection', 'Command and Control'],
            'Lateral Movement': ['Collection', 'Command and Control', 'Exfiltration'],
            'Collection': ['Command and Control', 'Exfiltration'],
            'Command and Control': ['Exfiltration', 'Impact'],
            'Exfiltration': ['Impact'],
            'Impact': []
        }

        return target_tactic in enables_map.get(source_tactic, [])

    def _render_relationship_network(self, relationships: Dict[str, Any]):
        """Render technique relationship network"""
        try:
            if 'error' in relationships:
                st.error(f"❌ {relationships['error']}")
                return

            nodes_data = relationships.get('nodes', [])
            edges_data = relationships.get('edges', [])

            if not nodes_data:
                st.warning("No relationship data to display")
                return

            # Create nodes for agraph
            nodes = []
            for node_data in nodes_data:
                node_id = node_data['id']
                label = node_data['label']
                node_type = node_data['type']

                # Set node properties based on type
                if node_type == 'center':
                    color = self.colors['center_node']  # Pink for center node
                    size = 40
                    border_color = '#ad1457'
                else:
                    color = self.colors['related_node']  # Cyan for related nodes
                    size = 30
                    border_color = '#00838f'

                technique_info = node_data.get('technique_info', {})
                title = f"ID: {node_id}\nName: {technique_info.get('name', 'Unknown')}\nTactic: {technique_info.get('tactic', 'Unknown')}"

                nodes.append(Node(
                    id=node_id,
                    label=label,
                    size=size,
                    color={'background': color, 'border': border_color},
                    borderWidth=3,
                    font={'color': 'white', 'size': 11, 'face': 'arial'},
                    title=title
                ))

            # Create edges for agraph
            edges = []
            for edge_data in edges_data:
                source = edge_data['source']
                target = edge_data['target']
                relationship = edge_data.get('relationship', 'Related')

                edges.append(Edge(
                    source=source,
                    target=target,
                    label=relationship,
                    color="#666666"
                ))

            # Graph configuration with enhanced styling
            config = Config(
                width=800,
                height=500,
                directed=False,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 150},
                    "barnesHut": {
                        "gravitationalConstant": -2000,
                        "centralGravity": 0.1,
                        "springLength": 200,
                        "springConstant": 0.05,
                        "damping": 0.09
                    }
                },
                hierarchical=False
            )

            # Render graph
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering relationship network: {e}")
            st.error(f"Error rendering network: {str(e)}")

    def _render_relationship_details(self, relationships: Dict[str, Any]):
        """Render detailed relationship information"""
        try:
            st.markdown("#### 📋 Relationship Details")

            center_technique = relationships.get('center_technique', '')
            nodes_data = relationships.get('nodes', [])
            edges_data = relationships.get('edges', [])
            relationship_details = relationships.get('relationship_details', {})

            if not nodes_data:
                return

            # Show analysis statistics
            if relationship_details:
                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("Total Found", relationship_details.get('total_found', 0))

                with col2:
                    st.metric("Displayed", relationship_details.get('displayed', 0))

                with col3:
                    platforms = relationship_details.get('platforms_filtered', [])
                    platform_text = f"{len(platforms)} selected" if platforms else "All"
                    st.metric("Platforms", platform_text)

                with col4:
                    counts_by_type = relationship_details.get('counts_by_type', {})
                    total_types = len([k for k, v in counts_by_type.items() if v > 0])
                    st.metric("Relationship Types", total_types)

                # Show breakdown by relationship type
                if counts_by_type:
                    with st.expander("📊 Breakdown by Relationship Type"):
                        for rel_type, count in counts_by_type.items():
                            if count > 0:
                                st.write(f"• **{rel_type}**: {count} techniques")
                            else:
                                st.write(f"• **{rel_type}**: No techniques found")

                st.markdown("---")

            # Center technique info
            center_node = next((n for n in nodes_data if n['id'] == center_technique), None)
            if center_node:
                center_info = center_node.get('technique_info', {})

                with st.expander(f"🎯 Center Technique: {center_technique}", expanded=True):
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown(f"**Name:** {center_info.get('name', 'Unknown')}")
                        st.markdown(f"**Tactic:** {center_info.get('tactic', 'Unknown')}")

                        platforms = json.loads(center_info.get('platform', '[]'))
                        st.markdown(f"**Platforms:** {', '.join(platforms) if platforms else 'Unknown'}")

                    with col2:
                        # Get rule coverage
                        rules = self._get_rules_for_technique(center_technique)
                        st.markdown(f"**Rule Coverage:** {len(rules)} rules")

                        if rules:
                            st.markdown("**Top Rules:**")
                            for rule in rules[:3]:
                                st.write(f"• {rule.get('title', 'Unknown Rule')}")

            # Related techniques
            related_nodes = [n for n in nodes_data if n['type'] == 'related']

            if related_nodes:
                st.markdown("#### 🔗 Related Techniques")

                # Group by relationship type
                relationship_groups = {}
                for edge in edges_data:
                    rel_type = edge.get('relationship', 'Related')
                    if rel_type not in relationship_groups:
                        relationship_groups[rel_type] = []
                    relationship_groups[rel_type].append(edge['target'])

                for rel_type, technique_ids in relationship_groups.items():
                    with st.expander(f"{rel_type} ({len(technique_ids)} techniques)"):
                        for tech_id in technique_ids:
                            tech_node = next((n for n in related_nodes if n['id'] == tech_id), None)
                            if tech_node:
                                tech_info = tech_node.get('technique_info', {})

                                col1, col2, col3 = st.columns([2, 2, 1])

                                with col1:
                                    st.markdown(f"**{tech_id}**")
                                    st.markdown(f"{tech_info.get('name', 'Unknown')}")

                                with col2:
                                    st.markdown(f"Tactic: {tech_info.get('tactic', 'Unknown')}")

                                with col3:
                                    rules = self._get_rules_for_technique(tech_id)
                                    st.markdown(f"{len(rules)} rules")

                                st.markdown("---")

        except Exception as e:
            self.logger.error(f"Error rendering relationship details: {e}")
            st.error(f"Error rendering details: {str(e)}")

    def _render_scenario_visualization(self, scenario: Dict[str, Any]):
        """Render attack scenario visualization"""
        try:
            st.markdown(f"#### 🎭 {scenario.get('name', 'Unknown Scenario')}")

            # Scenario info
            col1, col2 = st.columns(2)

            with col1:
                st.markdown(f"**Category:** {scenario.get('category', 'Unknown')}")
                st.markdown(f"**Coverage:** {scenario.get('coverage', 0):.1f}%")
                st.markdown(f"**Type:** {'Custom' if scenario.get('is_custom') else 'Predefined'}")

            with col2:
                tactics = scenario.get('tactics', [])
                st.markdown(f"**Tactics:** {len(tactics)}")
                techniques = scenario.get('techniques', [])
                st.markdown(f"**Techniques:** {len(techniques)}")

                # Show additional info for custom scenarios
                if scenario.get('is_custom'):
                    st.markdown(f"**Author:** {scenario.get('author', 'Unknown')}")

            # Description
            st.markdown(f"**Description:** {scenario.get('description', 'No description available')}")

            # Show tags for custom scenarios
            if scenario.get('is_custom') and scenario.get('tags'):
                st.markdown(f"**Tags:** {', '.join(scenario['tags'])}")

            # Show platforms if available
            if scenario.get('platforms'):
                st.markdown(f"**Platforms:** {', '.join(scenario['platforms'])}")

            # Create scenario flow visualization
            if tactics and techniques:
                self._render_scenario_flow(scenario)

        except Exception as e:
            self.logger.error(f"Error rendering scenario visualization: {e}")
            st.error(f"Error rendering scenario: {str(e)}")

    def _render_scenario_flow(self, scenario: Dict[str, Any]):
        """Render scenario attack flow"""
        try:
            tactics = scenario.get('tactics', [])
            techniques = scenario.get('techniques', [])

            # Create flow diagram
            nodes = []
            edges = []

            # Add tactic nodes
            for i, tactic in enumerate(tactics):
                nodes.append(Node(
                    id=f"tactic_{i}",
                    label=tactic.replace('-', ' ').title(),
                    size=35,
                    color=self.colors['tactic']
                ))

                # Connect tactics in sequence
                if i > 0:
                    edges.append(Edge(
                        source=f"tactic_{i-1}",
                        target=f"tactic_{i}",
                        color="#666666"
                    ))

            # Add technique nodes
            for i, technique_id in enumerate(techniques):
                technique_info = self._get_technique_info(technique_id)
                rules = self._get_rules_for_technique(technique_id)

                # Color based on coverage
                if len(rules) >= 3:
                    color = self.colors['high_coverage']
                elif len(rules) >= 1:
                    color = self.colors['medium_coverage']
                else:
                    color = self.colors['no_coverage']

                nodes.append(Node(
                    id=technique_id,
                    label=f"{technique_id}\n({len(rules)} rules)",
                    size=25,
                    color=color,
                    title=f"Name: {technique_info.get('name', 'Unknown')}\nRules: {len(rules)}"
                ))

                # Connect technique to corresponding tactic
                if i < len(tactics):
                    edges.append(Edge(
                        source=f"tactic_{i}",
                        target=technique_id,
                        color="#999999"
                    ))

            # Graph configuration with enhanced styling
            config = Config(
                width=800,
                height=400,
                directed=True,
                physics={
                    "enabled": True,
                    "stabilization": {"iterations": 100},
                    "barnesHut": {
                        "gravitationalConstant": -5000,
                        "centralGravity": 0.2,
                        "springLength": 120,
                        "springConstant": 0.04,
                        "damping": 0.09
                    }
                },
                hierarchical={
                    "enabled": True,
                    "levelSeparation": 120,
                    "nodeSpacing": 80,
                    "treeSpacing": 150,
                    "blockShifting": True,
                    "edgeMinimization": True,
                    "parentCentralization": True,
                    "direction": "LR",
                    "sortMethod": "directed"
                }
            )

            # Render graph
            agraph(nodes=nodes, edges=edges, config=config)

        except Exception as e:
            self.logger.error(f"Error rendering scenario flow: {e}")
            st.error(f"Error rendering flow: {str(e)}")

    def _render_scenario_analysis(self, scenario: Dict[str, Any]):
        """Render scenario analysis and recommendations"""
        try:
            st.markdown("#### 📊 Scenario Analysis")

            techniques = scenario.get('techniques', [])

            if not techniques:
                st.warning("No techniques in scenario to analyze")
                return

            # Coverage analysis
            coverage_data = []
            total_rules = 0

            for technique_id in techniques:
                technique_info = self._get_technique_info(technique_id)
                rules = self._get_rules_for_technique(technique_id)

                coverage_data.append({
                    'Technique ID': technique_id,
                    'Technique Name': technique_info.get('name', 'Unknown'),
                    'Tactic': technique_info.get('tactic', 'Unknown'),
                    'Rule Count': len(rules),
                    'Coverage Status': 'Good' if len(rules) >= 3 else 'Medium' if len(rules) >= 1 else 'Poor'
                })

                total_rules += len(rules)

            # Display coverage table
            coverage_df = pd.DataFrame(coverage_data)
            st.dataframe(coverage_df, use_container_width=True)

            # Summary metrics
            col1, col2, col3 = st.columns(3)

            with col1:
                avg_coverage = total_rules / len(techniques) if techniques else 0
                st.metric("Avg Rules/Technique", f"{avg_coverage:.1f}")

            with col2:
                good_coverage = len([c for c in coverage_data if c['Coverage Status'] == 'Good'])
                st.metric("Well Covered", f"{good_coverage}/{len(techniques)}")

            with col3:
                poor_coverage = len([c for c in coverage_data if c['Coverage Status'] == 'Poor'])
                st.metric("Gaps", poor_coverage)

            # Recommendations
            if poor_coverage > 0:
                st.markdown("#### 💡 Recommendations")

                poor_techniques = [c for c in coverage_data if c['Coverage Status'] == 'Poor']

                st.warning(f"⚠️ {poor_coverage} techniques have poor detection coverage:")

                for tech in poor_techniques:
                    st.write(f"• **{tech['Technique ID']}** - {tech['Technique Name']}")

                st.info("💡 Consider developing SIGMA rules for these techniques to improve scenario coverage.")

        except Exception as e:
            self.logger.error(f"Error rendering scenario analysis: {e}")
            st.error(f"Error rendering analysis: {str(e)}")

    def _save_custom_attack_path(self, path_name: str, path_steps: List[Dict]) -> bool:
        """Save custom attack path to database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # Create custom paths table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS custom_attack_paths (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        steps TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Insert the path
                cursor.execute("""
                    INSERT OR REPLACE INTO custom_attack_paths (name, steps, updated_at)
                    VALUES (?, ?, datetime('now'))
                """, (path_name, json.dumps(path_steps)))

                return True

        except Exception as e:
            self.logger.error(f"Error saving custom attack path: {e}")
            return False

    def _load_predefined_scenarios(self) -> List[Dict[str, Any]]:
        """Load predefined attack scenarios from configuration or database"""
        try:
            # Return empty list for production - scenarios should be user-generated
            return []

        except Exception as e:
            self.logger.error(f"Error loading predefined scenarios: {e}")
            return []
