"""
Enhanced MITRE ATT&CK Technique Detail View Component
Provides comprehensive technique information with AI-enhanced analysis
"""

import streamlit as st
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import pandas as pd

class TechniqueDetailView:
    """Enhanced technique detail view with complete MITRE data and AI analysis"""
    
    def __init__(self, db_manager, llm_integration):
        self.db_manager = db_manager
        self.llm_integration = llm_integration
        self.logger = logging.getLogger(__name__)
    
    def render_technique_detail(self, technique_id: str):
        """Render comprehensive technique detail view"""
        # Get complete technique data
        technique_data = self.db_manager.get_mitre_technique_details(technique_id)
        
        if not technique_data:
            st.error(f"Technique {technique_id} not found in database.")
            return
        
        # Header with technique info
        self._render_header(technique_data)
        
        # Main content in tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 Complete MITRE Data",
            "🤖 AI Analysis", 
            "🎯 Detection Recommendations",
            "⚔️ Attack Scenarios"
        ])
        
        with tab1:
            self._render_complete_mitre_data(technique_data)
        
        with tab2:
            self._render_ai_analysis(technique_data)
        
        with tab3:
            self._render_detection_recommendations(technique_data)
        
        with tab4:
            self._render_attack_scenarios(technique_data)
    
    def _render_header(self, technique_data: Dict[str, Any]):
        """Render technique header with key information"""
        technique_id = technique_data.get('technique_id', 'Unknown')
        name = technique_data.get('name', 'Unknown')
        tactic = technique_data.get('tactic', 'Unknown')
        
        # Header with technique ID and name
        st.markdown(f"""
        <div style="background: linear-gradient(90deg, #1f4e79 0%, #2d5aa0 100%); 
                    padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <h1 style="color: white; margin: 0; font-size: 2.2em;">
                {technique_id} - {name}
            </h1>
            <p style="color: #e0e0e0; margin: 10px 0 0 0; font-size: 1.1em;">
                Tactic: {tactic}
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Quick stats
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            platforms = technique_data.get('platform', [])
            platform_count = len(platforms) if platforms else 0
            st.metric("Platforms", platform_count)
        
        with col2:
            data_sources = technique_data.get('data_sources', [])
            data_source_count = len(data_sources) if data_sources else 0
            st.metric("Data Sources", data_source_count)
        
        with col3:
            # Get related SIGMA rules count
            related_rules = self._get_related_sigma_rules(technique_id)
            st.metric("SIGMA Rules", len(related_rules))
        
        with col4:
            sub_techniques = technique_data.get('sub_techniques', [])
            sub_tech_count = len(sub_techniques) if sub_techniques else 0
            st.metric("Sub-techniques", sub_tech_count)
    
    def _render_complete_mitre_data(self, technique_data: Dict[str, Any]):
        """Render complete MITRE ATT&CK data without truncation"""
        st.markdown("### 📋 Complete MITRE ATT&CK Framework Data")
        st.markdown("*All available information from the MITRE ATT&CK framework*")
        
        # Basic Information
        with st.expander("🔍 Basic Information", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Technique ID:**")
                st.code(technique_data.get('technique_id', 'Not available'))
                
                st.markdown("**Name:**")
                st.write(technique_data.get('name', 'Not available'))
                
                st.markdown("**Tactic:**")
                st.write(technique_data.get('tactic', 'Not available'))
            
            with col2:
                st.markdown("**Last Updated:**")
                st.write(technique_data.get('updated_at', 'Not available'))
                
                st.markdown("**Created:**")
                st.write(technique_data.get('created_at', 'Not available'))
        
        # Full Description
        with st.expander("📝 Complete Description", expanded=True):
            description = technique_data.get('description', 'No description available')
            st.markdown(description)
        
        # Technical Details
        with st.expander("⚙️ Technical Details", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                # Platforms
                platforms = technique_data.get('platform', [])
                if platforms:
                    st.markdown("**Platforms:**")
                    for platform in platforms:
                        st.write(f"• {platform}")
                else:
                    st.markdown("**Platforms:** Not specified")
                
                # Permissions Required
                permissions = technique_data.get('permissions_required', [])
                if permissions:
                    st.markdown("**Permissions Required:**")
                    for perm in permissions:
                        st.write(f"• {perm}")
                
                # System Requirements
                sys_req = technique_data.get('system_requirements', [])
                if sys_req:
                    st.markdown("**System Requirements:**")
                    for req in sys_req:
                        st.write(f"• {req}")
            
            with col2:
                # Data Sources
                data_sources = technique_data.get('data_sources', [])
                if data_sources:
                    st.markdown("**Data Sources:**")
                    for source in data_sources:
                        st.write(f"• {source}")
                else:
                    st.markdown("**Data Sources:** Not specified")
                
                # Effective Permissions
                eff_perms = technique_data.get('effective_permissions', [])
                if eff_perms:
                    st.markdown("**Effective Permissions:**")
                    for perm in eff_perms:
                        st.write(f"• {perm}")
                
                # Defense Bypassed
                defense_bypassed = technique_data.get('defense_bypassed', [])
                if defense_bypassed:
                    st.markdown("**Defense Bypassed:**")
                    for defense in defense_bypassed:
                        st.write(f"• {defense}")
        
        # Detection and Mitigation
        with st.expander("🔍 Detection Information", expanded=True):
            detection = technique_data.get('detection', '')
            if detection and detection.strip():
                st.markdown("**Detection Methods:**")
                st.markdown(detection)
            else:
                st.warning("⚠️ No specific detection information available in MITRE data.")
                st.info("💡 **To fix this:** Go to Settings → Data Management → Sync MITRE Data to update with enhanced detection information extraction.")
                st.info("🤖 **Alternative:** Check the AI Analysis tab for comprehensive detection recommendations.")

        with st.expander("🛡️ Mitigation Information", expanded=True):
            mitigation = technique_data.get('mitigation', '')
            if mitigation and mitigation.strip():
                st.markdown("**Mitigation Strategies:**")
                st.markdown(mitigation)
            else:
                st.warning("⚠️ No specific mitigation information available in MITRE data.")
                st.info("💡 **To fix this:** Go to Settings → Data Management → Sync MITRE Data to update with enhanced mitigation information extraction.")
                st.info("🤖 **Alternative:** Check the AI Analysis tab for comprehensive mitigation recommendations.")
        
        # References
        with st.expander("📚 References", expanded=False):
            references = technique_data.get('technique_references', [])
            if references:
                for i, ref in enumerate(references, 1):
                    if isinstance(ref, dict):
                        source_name = ref.get('source_name', 'Unknown')
                        url = ref.get('url', '')
                        external_id = ref.get('external_id', '')
                        
                        st.markdown(f"**{i}. {source_name}**")
                        if external_id:
                            st.write(f"ID: {external_id}")
                        if url:
                            st.markdown(f"[Link]({url})")
                        st.markdown("---")
            else:
                st.info("No references available.")
        
        # Additional Technical Information
        with st.expander("🔧 Additional Technical Information", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                # Network Requirements
                network_req = technique_data.get('network_requirements', '')
                if network_req:
                    st.markdown("**Network Requirements:**")
                    st.write(network_req)
                
                # Remote Support
                remote_support = technique_data.get('remote_support', '')
                if remote_support:
                    st.markdown("**Remote Support:**")
                    st.write(remote_support)
            
            with col2:
                # Impact Type
                impact_type = technique_data.get('impact_type', '')
                if impact_type:
                    st.markdown("**Impact Type:**")
                    st.write(impact_type)
                
                # Kill Chain Phases
                kill_chain = technique_data.get('kill_chain_phases', [])
                if kill_chain:
                    st.markdown("**Kill Chain Phases:**")
                    for phase in kill_chain:
                        if isinstance(phase, dict):
                            st.write(f"• {phase.get('kill_chain_name', 'Unknown')}: {phase.get('phase_name', 'Unknown')}")
    
    def _render_ai_analysis(self, technique_data: Dict[str, Any]):
        """Render AI-enhanced technical analysis"""
        st.markdown("### 🤖 AI-Enhanced Technical Analysis")
        st.markdown("*Comprehensive analysis generated by AI based on MITRE ATT&CK data*")
        
        technique_id = technique_data.get('technique_id', 'Unknown')
        
        # Check if analysis is cached
        if f"ai_analysis_{technique_id}" not in st.session_state:
            with st.spinner("Generating comprehensive AI analysis..."):
                analysis_result = self.llm_integration.analyze_mitre_technique(technique_data)
                st.session_state[f"ai_analysis_{technique_id}"] = analysis_result
        
        analysis_result = st.session_state[f"ai_analysis_{technique_id}"]
        
        if analysis_result.get('success'):
            analysis_content = analysis_result.get('analysis', '')
            
            # Display analysis with formatting
            st.markdown(analysis_content)
            
            # Show generation timestamp
            generated_at = analysis_result.get('generated_at', '')
            if generated_at:
                st.caption(f"Analysis generated at: {generated_at}")
        else:
            st.error(f"Failed to generate AI analysis: {analysis_result.get('error', 'Unknown error')}")
            
            # Provide manual refresh option
            if st.button("🔄 Retry Analysis", key=f"retry_analysis_{technique_id}"):
                if f"ai_analysis_{technique_id}" in st.session_state:
                    del st.session_state[f"ai_analysis_{technique_id}"]
                st.rerun()
    
    def _render_detection_recommendations(self, technique_data: Dict[str, Any]):
        """Render AI-generated detection recommendations"""
        st.markdown("### 🎯 Detection Engineering Recommendations")
        st.markdown("*AI-generated detection strategies and implementation guidance*")
        
        technique_id = technique_data.get('technique_id', 'Unknown')
        
        # Check if recommendations are cached
        if f"detection_recs_{technique_id}" not in st.session_state:
            with st.spinner("Generating detection recommendations..."):
                recs_result = self.llm_integration.generate_detection_recommendations(technique_data)
                st.session_state[f"detection_recs_{technique_id}"] = recs_result
        
        recs_result = st.session_state[f"detection_recs_{technique_id}"]
        
        if recs_result.get('success'):
            recommendations = recs_result.get('recommendations', '')
            
            # Display recommendations
            st.markdown(recommendations)
            
            # Show generation timestamp
            generated_at = recs_result.get('generated_at', '')
            if generated_at:
                st.caption(f"Recommendations generated at: {generated_at}")
        else:
            st.error(f"Failed to generate detection recommendations: {recs_result.get('error', 'Unknown error')}")
            
            # Provide manual refresh option
            if st.button("🔄 Retry Recommendations", key=f"retry_recs_{technique_id}"):
                if f"detection_recs_{technique_id}" in st.session_state:
                    del st.session_state[f"detection_recs_{technique_id}"]
                st.rerun()
    
    def _render_attack_scenarios(self, technique_data: Dict[str, Any]):
        """Render AI-generated attack scenarios"""
        st.markdown("### ⚔️ Real-World Attack Scenarios")
        st.markdown("*AI-generated attack scenarios and threat intelligence*")
        
        technique_id = technique_data.get('technique_id', 'Unknown')
        
        # Check if scenarios are cached
        if f"attack_scenarios_{technique_id}" not in st.session_state:
            with st.spinner("Generating attack scenarios..."):
                scenarios_result = self.llm_integration.generate_attack_scenarios(technique_data)
                st.session_state[f"attack_scenarios_{technique_id}"] = scenarios_result
        
        scenarios_result = st.session_state[f"attack_scenarios_{technique_id}"]
        
        if scenarios_result.get('success'):
            scenarios = scenarios_result.get('scenarios', '')
            
            # Display scenarios
            st.markdown(scenarios)
            
            # Show generation timestamp
            generated_at = scenarios_result.get('generated_at', '')
            if generated_at:
                st.caption(f"Scenarios generated at: {generated_at}")
        else:
            st.error(f"Failed to generate attack scenarios: {scenarios_result.get('error', 'Unknown error')}")
            
            # Provide manual refresh option
            if st.button("🔄 Retry Scenarios", key=f"retry_scenarios_{technique_id}"):
                if f"attack_scenarios_{technique_id}" in st.session_state:
                    del st.session_state[f"attack_scenarios_{technique_id}"]
                st.rerun()
    
    def _get_related_sigma_rules(self, technique_id: str) -> List[Dict]:
        """Get SIGMA rules related to this technique - USES CENTRALIZED METHOD"""
        try:
            return self.db_manager.get_rules_for_technique(technique_id)

        except Exception as e:
            self.logger.error(f"Error getting related SIGMA rules: {e}")
            return []
