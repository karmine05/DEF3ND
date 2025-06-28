"""
SIGMA Rule Builder Component
Provides comprehensive SIGMA rule creation, editing, and validation with LLM assistance
"""

import streamlit as st
import yaml
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import re
from utils.sigma_converter import SigmaConverter

class SigmaBuilder:
    """SIGMA Rule Builder component with LLM integration"""
    
    def __init__(self, db_manager, llm_integration):
        self.db_manager = db_manager
        self.llm_integration = llm_integration
        self.logger = logging.getLogger(__name__)

        # Initialize SIGMA converter
        self.sigma_converter = SigmaConverter(llm_integration)
        
        # SIGMA rule template
        self.default_template = {
            'title': '',
            'id': '',
            'status': 'experimental',
            'description': '',
            'author': 'Security Team',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'references': [],
            'tags': [],
            'logsource': {
                'category': '',
                'product': '',
                'service': ''
            },
            'detection': {
                'selection': {},
                'condition': 'selection'
            },
            'falsepositives': [],
            'level': 'medium'
        }
        
        # Common log sources and their fields
        self.log_sources = {
            'Windows Security': {
                'category': 'security',
                'product': 'windows',
                'service': 'security',
                'common_fields': ['EventID', 'SubjectUserName', 'TargetUserName', 'ProcessName', 'CommandLine']
            },
            'Windows System': {
                'category': 'system',
                'product': 'windows',
                'service': 'system',
                'common_fields': ['EventID', 'Provider_Name', 'ProcessName', 'Image']
            },
            'Sysmon': {
                'category': 'process_creation',
                'product': 'windows',
                'service': 'sysmon',
                'common_fields': ['EventID', 'Image', 'CommandLine', 'ParentImage', 'User']
            },
            'Linux Auditd': {
                'category': 'process_creation',
                'product': 'linux',
                'service': 'auditd',
                'common_fields': ['type', 'exe', 'comm', 'uid', 'gid']
            },
            'Web Proxy': {
                'category': 'proxy',
                'product': 'proxy',
                'service': '',
                'common_fields': ['url', 'method', 'status_code', 'user_agent', 'src_ip']
            }
        }
    
    def render(self):
        """Render the SIGMA Rule Builder interface"""
        st.markdown('<h2 class="sub-header">📝 SIGMA Rule Builder</h2>', unsafe_allow_html=True)

        # Check if we should show rule details modal from Rule Library
        if 'viewing_rule' in st.session_state and st.session_state.viewing_rule:
            self._render_rule_details_modal()
            return

        # Main tabs
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "🆕 Create New Rule",
            "✏️ Edit Existing Rule",
            "🤖 AI Assistant",
            "✅ Validate & Test",
            "🔄 Converter",
            "📚 Rule Library"
        ])

        with tab1:
            self._render_create_rule()

        with tab2:
            self._render_edit_rule()

        with tab3:
            self._render_ai_assistant()

        with tab4:
            self._render_validate_test()

        with tab5:
            self._render_converter()

        with tab6:
            self._render_rule_library()

    def _render_rule_details_modal(self):
        """Render the rule details modal with full YAML content"""
        try:
            rule = st.session_state.viewing_rule

            # Modal header with close button
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"# 📄 Rule Details: {rule.get('title', 'Untitled Rule')}")
            with col2:
                if st.button("❌ Close", key="close_rule_details"):
                    st.session_state.viewing_rule = None
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
                tags = rule.get('tags', [])
                if tags:
                    st.markdown("**Tags:**")
                    for tag in tags[:5]:  # Show first 5 tags
                        st.markdown(f"• `{tag}`")
                    if len(tags) > 5:
                        st.markdown(f"• ... and {len(tags) - 5} more")
                else:
                    st.markdown("**Tags:** None")

            # Description
            if rule.get('description'):
                st.markdown("## 📝 Description")
                st.markdown(rule['description'])

            # YAML content section
            st.markdown("## 📄 YAML Content")

            if rule.get('rule_content'):
                col1, col2 = st.columns([3, 1])

                with col1:
                    # Expandable text area for easy copying
                    st.text_area(
                        "Full YAML Content (Click to select all, then Ctrl+C to copy):",
                        value=rule['rule_content'],
                        height=400,
                        key="rule_content_display"
                    )

                with col2:
                    # Show character count for reference
                    char_count = len(rule['rule_content'])
                    st.metric("Content Size", f"{char_count} chars")

                # Quick copy instructions
                st.info("💡 **Quick Copy:** Click in the text area above, select all (Ctrl+A), and copy (Ctrl+C)")
            else:
                st.warning("⚠️ No YAML content available for this rule.")

            # Action buttons
            st.markdown("---")
            st.markdown("## 🔧 Actions")

            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button("✏️ Edit Rule", key="edit_from_details"):
                    st.session_state.edit_rule_data = rule
                    st.session_state.viewing_rule = None
                    st.success("✅ Rule loaded for editing. Check the 'Edit Existing Rule' tab.")
                    st.rerun()

            with col2:
                if st.button("📋 Copy to Clipboard", key="copy_from_details"):
                    st.session_state.clipboard = rule.get('rule_content', '')
                    st.success("✅ Rule content copied! Use the text area above to manually copy.")

            with col3:
                if st.button("🔄 Convert Rule", key="convert_from_details"):
                    # Set up for conversion
                    st.session_state.convert_rule_content = rule.get('rule_content', '')
                    st.session_state.viewing_rule = None
                    st.success("✅ Rule loaded for conversion. Check the 'Converter' tab.")
                    st.rerun()

        except Exception as e:
            st.error(f"Error displaying rule details: {str(e)}")
            # Clear the session state on error
            st.session_state.viewing_rule = None

    def _render_create_rule(self):
        """Render rule creation interface"""
        st.markdown("### 🆕 Create New SIGMA Rule")
        
        # Rule creation method selection
        creation_method = st.radio(
            "How would you like to create the rule?",
            ["Manual Creation", "AI-Assisted Creation", "Template-Based", "Import from File"],
            horizontal=True
        )
        
        if creation_method == "Manual Creation":
            self._render_manual_creation()
        elif creation_method == "AI-Assisted Creation":
            self._render_ai_creation()
        elif creation_method == "Template-Based":
            self._render_template_creation()
        elif creation_method == "Import from File":
            self._render_import_creation()
    
    def _render_manual_creation(self):
        """Render manual rule creation form"""
        st.markdown("#### 📋 Manual Rule Creation")
        
        with st.form("manual_rule_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                # Basic metadata
                st.markdown("**Basic Information**")
                title = st.text_input("Rule Title*", placeholder="Suspicious PowerShell Execution")
                description = st.text_area("Description*", placeholder="Detects suspicious PowerShell command execution...")
                author = st.text_input("Author", value="Security Team")
                level = st.selectbox("Severity Level", ["low", "medium", "high", "critical"], index=1)
                status = st.selectbox("Status", ["experimental", "test", "stable"], index=0)
                
                # Tags
                st.markdown("**Tags**")
                mitre_tags = st.text_input("MITRE ATT&CK Tags", placeholder="attack.t1059.001, attack.execution")
                custom_tags = st.text_input("Custom Tags", placeholder="powershell, suspicious")
            
            with col2:
                # Log source configuration
                st.markdown("**Log Source**")
                log_source_type = st.selectbox("Log Source Type", list(self.log_sources.keys()))

                source_config = self.log_sources[log_source_type]
                category = st.text_input("Category", value=source_config['category'])
                product = st.text_input("Product", value=source_config['product'])
                service = st.text_input("Service", value=source_config['service'])
                
                # References
                st.markdown("**References**")
                references = st.text_area("References (one per line)", placeholder="https://example.com/reference1\nhttps://example.com/reference2")
            
            # Detection logic
            st.markdown("**Detection Logic**")
            
            # Selection criteria
            st.markdown("*Selection Criteria*")
            selection_fields = {}
            
            # Dynamic field addition
            if 'field_count' not in st.session_state:
                st.session_state.field_count = 1
            
            for i in range(st.session_state.field_count):
                col_field, col_operator, col_value = st.columns([2, 1, 2])
                
                with col_field:
                    field_name = st.text_input(f"Field {i+1}", key=f"field_{i}", placeholder="EventID")
                
                with col_operator:
                    operator = st.selectbox("Op", ["equals", "contains", "startswith", "endswith", "regex"], key=f"op_{i}")
                
                with col_value:
                    field_value = st.text_input(f"Value {i+1}", key=f"value_{i}", placeholder="4688")
                
                if field_name and field_value:
                    if operator == "equals":
                        selection_fields[field_name] = field_value
                    elif operator == "contains":
                        selection_fields[field_name] = f"*{field_value}*"
                    elif operator == "startswith":
                        selection_fields[field_name] = f"{field_value}*"
                    elif operator == "endswith":
                        selection_fields[field_name] = f"*{field_value}"
                    elif operator == "regex":
                        selection_fields[field_name] = f"re:{field_value}"
            
            col_add, col_remove = st.columns(2)
            with col_add:
                if st.form_submit_button("➕ Add Field"):
                    st.session_state.field_count += 1
                    st.rerun()
            
            with col_remove:
                if st.form_submit_button("➖ Remove Field") and st.session_state.field_count > 1:
                    st.session_state.field_count -= 1
                    st.rerun()
            
            # Condition
            condition = st.text_input("Condition", value="selection", placeholder="selection and not filter")
            
            # False positives
            false_positives = st.text_area("False Positives", placeholder="Administrative PowerShell usage\nLegitimate scripts")
            
            # Submit button
            submitted = st.form_submit_button("🚀 Create Rule", type="primary")
            
            if submitted:
                if title and description:
                    # Build rule data
                    rule_data = self._build_rule_data(
                        title, description, author, level, status,
                        mitre_tags, custom_tags, category, product, service,
                        selection_fields, condition, false_positives, references
                    )
                    
                    # Generate YAML
                    rule_yaml = self._generate_rule_yaml(rule_data)
                    
                    # Save rule
                    result = self._save_rule(rule_data, rule_yaml)
                    
                    if result['success']:
                        st.success(f"✅ Rule created successfully! ID: {result['rule_id']}")
                        st.code(rule_yaml, language='yaml')
                    else:
                        st.error(f"❌ Failed to create rule: {result['error']}")
                else:
                    st.error("❌ Please fill in required fields (Title and Description)")
    
    def _render_ai_creation(self):
        """Render AI-assisted rule creation"""
        st.markdown("#### 🤖 AI-Assisted Rule Creation")

        # Technique suggestion section (outside form)
        st.markdown("##### 🎯 MITRE Technique Suggestion")
        col_desc, col_suggest = st.columns([3, 1])

        with col_desc:
            suggestion_description = st.text_area(
                "Describe what you want to detect for technique suggestions",
                placeholder="I want to detect when an attacker uses PowerShell to download and execute malicious scripts...",
                height=80,
                key="suggestion_description"
            )

        with col_suggest:
            st.write("")  # Add some spacing
            st.write("")  # Add some spacing
            if st.button("🎯 Suggest Techniques", help="AI will suggest relevant MITRE techniques based on your description"):
                if suggestion_description:
                    with st.spinner("Analyzing description for MITRE techniques..."):
                        suggestions = self._suggest_mitre_techniques(suggestion_description)
                        if suggestions:
                            st.session_state.technique_suggestions = suggestions
                        else:
                            st.session_state.technique_suggestions = []
                else:
                    st.warning("Please enter a description first")

        # Display suggestions if available
        if hasattr(st.session_state, 'technique_suggestions') and st.session_state.technique_suggestions:
            st.success("💡 Suggested MITRE Techniques:")
            for tech_id, confidence in st.session_state.technique_suggestions[:3]:  # Show top 3
                st.write(f"• **{tech_id}** (confidence: {confidence:.2f})")

        st.markdown("---")

        with st.form("ai_rule_form"):
            # Natural language description
            description = st.text_area(
                "Describe what you want to detect*",
                placeholder="I want to detect when an attacker uses PowerShell to download and execute malicious scripts from the internet...",
                height=100
            )

            col1, col2 = st.columns(2)

            with col1:
                # Context information
                log_source = st.selectbox("Primary Log Source", list(self.log_sources.keys()))
                attack_technique = st.text_input("MITRE ATT&CK Technique (optional)", placeholder="T1059.001")
                severity = st.selectbox("Expected Severity", ["low", "medium", "high", "critical"], index=1)

            with col2:
                # Additional context
                environment = st.selectbox("Environment", ["Windows", "Linux", "macOS", "Cloud", "Mixed"])
                use_case = st.selectbox("Use Case", ["Threat Hunting", "Real-time Detection", "Forensic Analysis"])
                complexity = st.selectbox("Rule Complexity", ["Simple", "Moderate", "Complex"])

            # Advanced options
            with st.expander("🔧 Advanced Options"):
                include_exclusions = st.checkbox("Include common exclusions", value=True)
                optimize_performance = st.checkbox("Optimize for performance", value=True)
                add_comments = st.checkbox("Add explanatory comments", value=True)

            submitted = st.form_submit_button("🤖 Generate Rule with AI", type="primary")

            if submitted:
                if description:
                    with st.spinner("🤖 AI is generating your SIGMA rule..."):
                        # Ensure log_source is a string (handle potential list case)
                        if isinstance(log_source, list):
                            log_source_str = log_source[0] if log_source else "Windows Security"
                        else:
                            log_source_str = str(log_source)

                        # Additional safety check to ensure it's a string before calling .lower()
                        if isinstance(log_source_str, list):
                            log_source_str = str(log_source_str[0]) if log_source_str else "Windows Security"

                        # Ensure it's a string and convert to lowercase
                        log_source_final = str(log_source_str).lower()

                        # Prepare context for LLM
                        context = {
                            'log_source': log_source_final,
                            'attack_technique': attack_technique,
                            'severity': severity,
                            'environment': environment,
                            'use_case': use_case,
                            'complexity': complexity,
                            'include_exclusions': include_exclusions,
                            'optimize_performance': optimize_performance
                        }

                        # Generate rule using LLM
                        result = self.llm_integration.generate_sigma_rule(description, context)

                        if result['success']:
                            # Store the generated rule in session state for action buttons
                            st.session_state.generated_rule_content = result['rule_content']
                            st.success("✅ AI generated rule successfully!")
                        else:
                            st.error(f"❌ AI generation failed: {result['error']}")

                            if 'raw_content' in result:
                                with st.expander("🔍 Raw AI Response"):
                                    st.text(result['raw_content'])
                else:
                    st.error("❌ Please provide a description of what you want to detect")

        # Display generated rule and action buttons outside the form
        if 'generated_rule_content' in st.session_state:
            st.markdown("---")
            st.markdown("#### 📄 Generated Rule")

            # Display generated rule
            st.code(st.session_state.generated_rule_content, language='yaml')

            # Action buttons outside the form
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                if st.button("💾 Save Rule", key="save_ai_rule"):
                    # Parse and save the rule
                    save_result = self._save_ai_generated_rule(st.session_state.generated_rule_content)
                    if save_result['success']:
                        st.success(f"✅ Rule saved! ID: {save_result['rule_id']}")
                        # Clear the generated rule from session state after saving
                        del st.session_state.generated_rule_content
                        st.rerun()
                    else:
                        st.error(f"❌ Save failed: {save_result['error']}")

            with col2:
                if st.button("✏️ Edit Rule", key="edit_ai_rule"):
                    # Create a rule data object for editing
                    try:
                        rule_data = yaml.safe_load(st.session_state.generated_rule_content)
                        rule_data['rule_content'] = st.session_state.generated_rule_content
                        rule_data['rule_id'] = rule_data.get('id', str(uuid.uuid4()))
                        st.session_state.edit_rule_data = rule_data
                        # Clear the generated rule from session state
                        del st.session_state.generated_rule_content
                        st.success("✅ Rule loaded for editing. Check the 'Edit Existing Rule' tab.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error loading rule for editing: {e}")

            with col3:
                if st.button("🔄 Regenerate", key="regenerate_ai_rule"):
                    # Clear the generated rule to trigger regeneration
                    del st.session_state.generated_rule_content
                    st.rerun()

            with col4:
                if st.button("❌ Clear", key="clear_ai_rule"):
                    # Clear the generated rule
                    del st.session_state.generated_rule_content
                    st.rerun()
    
    def _render_template_creation(self):
        """Render template-based rule creation"""
        st.markdown("#### 📋 Template-Based Rule Creation")
        
        # Template categories
        template_categories = {
            "Process Execution": [
                "Suspicious Command Line",
                "Process Injection",
                "Living off the Land",
                "Encoded Commands"
            ],
            "Network Activity": [
                "DNS Tunneling",
                "Suspicious Outbound Connections",
                "Data Exfiltration",
                "C2 Communication"
            ],
            "File Operations": [
                "Suspicious File Creation",
                "File Encryption",
                "Temporary File Usage",
                "System File Modification"
            ],
            "Authentication": [
                "Failed Login Attempts",
                "Privilege Escalation",
                "Account Manipulation",
                "Suspicious Logons"
            ]
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            category = st.selectbox("Template Category", list(template_categories.keys()))
            template = st.selectbox("Template", template_categories[category])
        
        with col2:
            st.markdown("**Template Preview**")
            template_content = self._get_template_content(category, template)
            st.code(template_content, language='yaml')
        
        if st.button("📋 Use This Template"):
            st.session_state.template_rule = template_content
            st.success("✅ Template loaded! You can now customize it below.")
        
        # Template customization
        if 'template_rule' in st.session_state:
            st.markdown("#### ✏️ Customize Template")
            
            edited_rule = st.text_area(
                "Edit the rule as needed:",
                value=st.session_state.template_rule,
                height=400
            )
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("💾 Save Customized Rule"):
                    result = self._save_ai_generated_rule(edited_rule)
                    if result['success']:
                        st.success(f"✅ Rule saved! ID: {result['rule_id']}")
                    else:
                        st.error(f"❌ Save failed: {result['error']}")
            
            with col2:
                if st.button("🔄 Reset Template"):
                    del st.session_state.template_rule
                    st.rerun()
    
    def _render_import_creation(self):
        """Render rule import interface"""
        st.markdown("#### 📁 Import Rule from File")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Choose a SIGMA rule file",
            type=['yml', 'yaml'],
            help="Upload a YAML file containing a SIGMA rule"
        )
        
        if uploaded_file is not None:
            try:
                # Read file content
                rule_content = uploaded_file.read().decode('utf-8')
                
                # Display content
                st.markdown("**File Content:**")
                st.code(rule_content, language='yaml')
                
                # Validate YAML
                try:
                    rule_data = yaml.safe_load(rule_content)
                    st.success("✅ Valid YAML format")
                    
                    # Show rule metadata
                    if isinstance(rule_data, dict):
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Title", rule_data.get('title', 'N/A'))
                        
                        with col2:
                            st.metric("Level", rule_data.get('level', 'N/A'))
                        
                        with col3:
                            st.metric("Status", rule_data.get('status', 'N/A'))
                    
                    # Import options
                    st.markdown("**Import Options:**")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        mark_as_custom = st.checkbox("Mark as custom rule", value=True)
                        validate_before_import = st.checkbox("Validate before import", value=True)
                    
                    with col2:
                        overwrite_existing = st.checkbox("Overwrite if exists", value=False)
                        add_import_tag = st.checkbox("Add 'imported' tag", value=True)
                    
                    # Import button
                    if st.button("📥 Import Rule", type="primary"):
                        result = self._import_rule(
                            rule_content, 
                            mark_as_custom, 
                            validate_before_import,
                            overwrite_existing,
                            add_import_tag
                        )
                        
                        if result['success']:
                            st.success(f"✅ Rule imported successfully! ID: {result['rule_id']}")
                        else:
                            st.error(f"❌ Import failed: {result['error']}")
                
                except yaml.YAMLError as e:
                    st.error(f"❌ Invalid YAML format: {str(e)}")
                    
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")
    
    def _build_rule_data(self, title, description, author, level, status, mitre_tags, custom_tags,
                         category, product, service, selection_fields, condition, false_positives, references):
        """Build rule data dictionary from form inputs"""
        
        # Process tags
        tags = []
        if mitre_tags:
            tags.extend([tag.strip() for tag in mitre_tags.split(',') if tag.strip()])
        if custom_tags:
            tags.extend([tag.strip() for tag in custom_tags.split(',') if tag.strip()])
        tags.append('custom')  # Mark as custom rule
        
        # Process references
        ref_list = []
        if references:
            ref_list = [ref.strip() for ref in references.split('\n') if ref.strip()]
        
        # Process false positives
        fp_list = []
        if false_positives:
            fp_list = [fp.strip() for fp in false_positives.split('\n') if fp.strip()]
        
        # Generate rule ID
        rule_id = str(uuid.uuid4())
        
        return {
            'rule_id': rule_id,
            'title': title,
            'description': description,
            'author': author,
            'date': datetime.now().strftime('%Y/%m/%d'),
            'status': status,
            'level': level,
            'logsource': {
                'category': category,
                'product': product,
                'service': service
            },
            'detection': {
                'selection': selection_fields,
                'condition': condition
            },
            'falsepositives': fp_list,
            'tags': tags,
            'references': ref_list,
            'is_custom': True
        }
    
    def _generate_rule_yaml(self, rule_data):
        """Generate YAML content from rule data"""
        # Create ordered dict for proper YAML structure
        yaml_data = {
            'title': rule_data['title'],
            'id': rule_data['rule_id'],
            'status': rule_data['status'],
            'description': rule_data['description'],
            'author': rule_data['author'],
            'date': rule_data['date']
        }
        
        if rule_data.get('references'):
            yaml_data['references'] = rule_data['references']
        
        if rule_data.get('tags'):
            yaml_data['tags'] = rule_data['tags']
        
        yaml_data['logsource'] = rule_data['logsource']
        yaml_data['detection'] = rule_data['detection']
        
        if rule_data.get('falsepositives'):
            yaml_data['falsepositives'] = rule_data['falsepositives']
        
        yaml_data['level'] = rule_data['level']
        
        return yaml.dump(yaml_data, default_flow_style=False, sort_keys=False)
    
    def _save_rule(self, rule_data, rule_yaml):
        """Save rule to database"""
        try:
            # Add YAML content to rule data
            rule_data['rule_content'] = rule_yaml
            rule_data['file_path'] = f"custom/{rule_data['rule_id']}.yml"
            rule_data['source_repo'] = 'Custom Rules'

            # Save to database
            success = self.db_manager.insert_sigma_rule(rule_data)

            if success:
                # Log activity
                self.db_manager.log_activity(
                    "Rule Created",
                    f"Created custom rule: {rule_data['title']}"
                )

                return {
                    'success': True,
                    'rule_id': rule_data['rule_id']
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to save rule to database'
                }

        except Exception as e:
            self.logger.error(f"Error saving rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _save_ai_generated_rule(self, rule_content: str) -> Dict[str, Any]:
        """Save AI-generated rule to database"""
        try:
            # Parse YAML content
            rule_data = yaml.safe_load(rule_content)

            if not rule_data or not isinstance(rule_data, dict):
                return {
                    'success': False,
                    'error': 'Invalid YAML content'
                }

            # Generate rule ID if not present
            rule_id = rule_data.get('id', str(uuid.uuid4()))

            # Prepare rule data for database
            processed_rule = {
                'rule_id': rule_id,
                'title': rule_data.get('title', ''),
                'description': rule_data.get('description', ''),
                'author': rule_data.get('author', 'AI Generated'),
                'date': rule_data.get('date', datetime.now().strftime('%Y/%m/%d')),
                'status': rule_data.get('status', 'experimental'),
                'level': rule_data.get('level', 'medium'),
                'logsource': rule_data.get('logsource', {}),
                'detection': rule_data.get('detection', {}),
                'falsepositives': rule_data.get('falsepositives', []),
                'tags': rule_data.get('tags', []) + ['ai-generated', 'custom'],
                'references': rule_data.get('references', []),
                'rule_content': rule_content,
                'file_path': f"custom/{rule_id}.yml",
                'source_repo': 'Custom Rules',
                'is_custom': True
            }

            # Save to database
            success = self.db_manager.insert_sigma_rule(processed_rule)

            if success:
                # Log activity
                self.db_manager.log_activity(
                    "AI Rule Generated",
                    f"AI generated rule: {processed_rule['title']}"
                )

                return {
                    'success': True,
                    'rule_id': rule_id
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to save rule to database'
                }

        except yaml.YAMLError as e:
            return {
                'success': False,
                'error': f'Invalid YAML syntax: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Error saving AI-generated rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _get_template_content(self, category: str, template: str) -> str:
        """Get template content for rule creation"""
        from datetime import datetime
        import uuid

        current_date = datetime.now().strftime('%Y/%m/%d')
        template_id = str(uuid.uuid4())

        templates = {
            "Process Execution": {
                "Suspicious Command Line": f"""title: Suspicious Command Line Execution Template
id: {template_id}
status: experimental
description: Template for detecting suspicious command line patterns
author: Security Team
date: {current_date}
references:
    - https://attack.mitre.org/techniques/T1059/
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
    condition: selection
falsepositives:
    - Administrative scripts
    - Legitimate automation
level: medium""",

                "Process Injection": """title: [TEMPLATE] Process Injection Detection
id: [GENERATE_NEW_ID]
status: experimental
description: Template for detecting process injection techniques
author: [YOUR_NAME]
date: [CURRENT_DATE]
references:
    - [ADD_REFERENCE_URL]
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: [EVENT_ID]
        [FIELD_NAME]:
            - '[PATTERN_1]'
            - '[PATTERN_2]'
    condition: selection
falsepositives:
    - [LEGITIMATE_USE_CASE_1]
    - [LEGITIMATE_USE_CASE_2]
level: high"""
            },
            "Network Activity": {
                "DNS Tunneling": """title: [TEMPLATE] DNS Tunneling Detection
id: [GENERATE_NEW_ID]
status: experimental
description: Template for detecting DNS tunneling activity
author: [YOUR_NAME]
date: [CURRENT_DATE]
references:
    - [ADD_REFERENCE_URL]
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
    product: dns
detection:
    selection:
        [FIELD_NAME]: '[PATTERN]'
    condition: selection
falsepositives:
    - [LEGITIMATE_USE_CASE_1]
    - [LEGITIMATE_USE_CASE_2]
level: medium"""
            }
        }

        return templates.get(category, {}).get(template, "# Template not found")

    def _import_rule(self, rule_content: str, mark_as_custom: bool, validate_before_import: bool,
                    overwrite_existing: bool, add_import_tag: bool) -> Dict[str, Any]:
        """Import rule from file content"""
        try:
            # Validate YAML if requested
            if validate_before_import:
                try:
                    rule_data = yaml.safe_load(rule_content)
                    if not rule_data or not isinstance(rule_data, dict):
                        return {
                            'success': False,
                            'error': 'Invalid YAML structure'
                        }
                except yaml.YAMLError as e:
                    return {
                        'success': False,
                        'error': f'YAML validation failed: {str(e)}'
                    }
            else:
                rule_data = yaml.safe_load(rule_content)

            # Generate or use existing rule ID
            rule_id = rule_data.get('id', str(uuid.uuid4()))

            # Check if rule already exists
            existing_rules = self.db_manager.get_sigma_rules({'rule_id': rule_id})
            if existing_rules and not overwrite_existing:
                return {
                    'success': False,
                    'error': f'Rule with ID {rule_id} already exists. Enable overwrite to replace it.'
                }

            # Prepare tags
            tags = rule_data.get('tags', [])
            if add_import_tag and 'imported' not in tags:
                tags.append('imported')
            if mark_as_custom and 'custom' not in tags:
                tags.append('custom')

            # Prepare rule data
            processed_rule = {
                'rule_id': rule_id,
                'title': rule_data.get('title', ''),
                'description': rule_data.get('description', ''),
                'author': rule_data.get('author', 'Imported'),
                'date': rule_data.get('date', datetime.now().strftime('%Y/%m/%d')),
                'status': rule_data.get('status', 'experimental'),
                'level': rule_data.get('level', 'medium'),
                'logsource': rule_data.get('logsource', {}),
                'detection': rule_data.get('detection', {}),
                'falsepositives': rule_data.get('falsepositives', []),
                'tags': tags,
                'references': rule_data.get('references', []),
                'rule_content': rule_content,
                'file_path': f"imported/{rule_id}.yml",
                'source_repo': 'Imported Rules',
                'is_custom': mark_as_custom
            }

            # Save to database
            success = self.db_manager.insert_sigma_rule(processed_rule)

            if success:
                # Log activity
                self.db_manager.log_activity(
                    "Rule Imported",
                    f"Imported rule: {processed_rule['title']}"
                )

                return {
                    'success': True,
                    'rule_id': rule_id
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to save imported rule to database'
                }

        except Exception as e:
            self.logger.error(f"Error importing rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _render_edit_rule(self):
        """Render rule editing interface"""
        st.markdown("### ✏️ Edit Existing Rule")

        # Check if a rule was passed from the search engine
        if 'edit_rule_data' in st.session_state:
            rule = st.session_state.edit_rule_data
            st.session_state.editing_rule = rule
            # Clear the edit_rule_data to avoid confusion
            del st.session_state.edit_rule_data
            st.info(f"✅ Loaded rule '{rule.get('title', 'Unknown')}' for editing from search results.")

        # Rule selection
        col1, col2 = st.columns([1, 2])

        with col1:
            # Search for rule to edit
            search_term = st.text_input("Search for rule to edit", placeholder="Enter rule title or ID...")

            if search_term:
                # Find matching rules
                matching_rules = self.db_manager.get_sigma_rules({
                    'search_term': search_term
                })

                if matching_rules:
                    rule_options = [f"{rule['title']} ({rule['rule_id']})" for rule in matching_rules]
                    selected_rule_option = st.selectbox("Select rule", rule_options)

                    if selected_rule_option:
                        # Extract rule ID from selection
                        rule_id = selected_rule_option.split('(')[-1].rstrip(')')
                        selected_rule = next(r for r in matching_rules if r['rule_id'] == rule_id)

                        if st.button("📝 Edit This Rule"):
                            st.session_state.editing_rule = selected_rule
                            st.rerun()
                else:
                    st.info("No rules found matching your search.")

        with col2:
            if 'editing_rule' in st.session_state:
                rule = st.session_state.editing_rule

                st.markdown(f"**Editing:** {rule['title']}")
                st.markdown(f"**ID:** {rule['rule_id']}")
                st.markdown(f"**Current Status:** {rule.get('status', 'Unknown')}")

                # Edit rule content
                edited_content = st.text_area(
                    "Rule Content (YAML)",
                    value=rule.get('rule_content', ''),
                    height=400
                )

                col_save, col_cancel = st.columns(2)

                with col_save:
                    if st.button("💾 Save Changes", type="primary"):
                        # Save edited rule
                        result = self._save_edited_rule(rule['rule_id'], edited_content)
                        if result['success']:
                            st.success("✅ Rule updated successfully!")
                            del st.session_state.editing_rule
                            st.rerun()
                        else:
                            st.error(f"❌ Update failed: {result['error']}")

                with col_cancel:
                    if st.button("❌ Cancel"):
                        del st.session_state.editing_rule
                        st.rerun()
            else:
                st.info("👈 Search and select a rule to edit, or click 'Edit' from the search results")

    def _save_edited_rule(self, rule_id: str, rule_content: str) -> Dict[str, Any]:
        """Save edited rule content"""
        try:
            # Parse updated content
            rule_data = yaml.safe_load(rule_content)

            if not rule_data or not isinstance(rule_data, dict):
                return {
                    'success': False,
                    'error': 'Invalid YAML content'
                }

            # Prepare updated rule data
            processed_rule = {
                'rule_id': rule_id,
                'title': rule_data.get('title', ''),
                'description': rule_data.get('description', ''),
                'author': rule_data.get('author', ''),
                'date': rule_data.get('date', ''),
                'status': rule_data.get('status', 'experimental'),
                'level': rule_data.get('level', 'medium'),
                'logsource': rule_data.get('logsource', {}),
                'detection': rule_data.get('detection', {}),
                'falsepositives': rule_data.get('falsepositives', []),
                'tags': rule_data.get('tags', []),
                'references': rule_data.get('references', []),
                'rule_content': rule_content,
                'file_path': f"custom/{rule_id}.yml",
                'source_repo': 'Custom Rules',
                'is_custom': True
            }

            # Update in database
            success = self.db_manager.insert_sigma_rule(processed_rule)

            if success:
                # Log activity
                self.db_manager.log_activity(
                    "Rule Updated",
                    f"Updated rule: {processed_rule['title']}"
                )

                return {
                    'success': True,
                    'rule_id': rule_id
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to update rule in database'
                }

        except yaml.YAMLError as e:
            return {
                'success': False,
                'error': f'Invalid YAML syntax: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Error saving edited rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _render_ai_assistant(self):
        """Render AI assistant interface"""
        st.markdown("### 🤖 AI Assistant")

        # AI assistant tabs
        tab1, tab2, tab3 = st.tabs(["📝 Rule Analysis", "💡 Suggestions", "❓ Explain Rule"])

        with tab1:
            st.markdown("#### 📝 Analyze SIGMA Rule")

            rule_to_analyze = st.text_area(
                "Paste SIGMA rule to analyze",
                height=200,
                placeholder="Paste your SIGMA rule YAML content here..."
            )

            if st.button("🔍 Analyze Rule") and rule_to_analyze:
                with st.spinner("AI is analyzing the rule..."):
                    result = self.llm_integration.analyze_sigma_rule(rule_to_analyze)

                    if result['success']:
                        analysis = result['analysis']

                        col1, col2 = st.columns(2)

                        with col1:
                            if analysis.get('effectiveness_score'):
                                st.metric("Effectiveness Score", f"{analysis['effectiveness_score']}/10")

                            st.markdown("**False Positives:**")
                            for fp in analysis.get('false_positives', []):
                                st.write(f"• {fp}")

                        with col2:
                            st.markdown("**Recommendations:**")
                            for rec in analysis.get('recommendations', []):
                                st.write(f"• {rec}")

                            st.markdown("**MITRE Mappings:**")
                            for mapping in analysis.get('mitre_mappings', []):
                                st.write(f"• {mapping}")
                    else:
                        st.error(f"❌ Analysis failed: {result['error']}")

        with tab2:
            st.markdown("#### 💡 Rule Improvement Suggestions")

            rule_to_improve = st.text_area(
                "Paste SIGMA rule for improvement suggestions",
                height=200,
                placeholder="Paste your SIGMA rule YAML content here..."
            )

            context = st.text_input(
                "Additional context (optional)",
                placeholder="e.g., 'This rule has too many false positives in our environment'"
            )

            if st.button("💡 Get Suggestions") and rule_to_improve:
                with st.spinner("AI is generating improvement suggestions..."):
                    result = self.llm_integration.suggest_rule_improvements(rule_to_improve, context)

                    if result['success']:
                        st.markdown("**Improved Rule:**")
                        if result.get('improved_rule'):
                            st.code(result['improved_rule'], language='yaml')

                        st.markdown("**Suggestions:**")
                        for suggestion in result.get('suggestions', []):
                            st.write(f"• {suggestion}")
                    else:
                        st.error(f"❌ Suggestion generation failed: {result['error']}")

        with tab3:
            st.markdown("#### ❓ Explain Rule Logic")

            rule_to_explain = st.text_area(
                "Paste SIGMA rule to explain",
                height=200,
                placeholder="Paste your SIGMA rule YAML content here..."
            )

            if st.button("❓ Explain Rule") and rule_to_explain:
                with st.spinner("AI is explaining the rule..."):
                    result = self.llm_integration.explain_detection_logic(rule_to_explain)

                    if result['success']:
                        st.markdown("**Rule Explanation:**")
                        st.write(result['explanation'])

                        if result.get('summary'):
                            st.info(f"**Summary:** {result['summary']}")
                    else:
                        st.error(f"❌ Explanation failed: {result['error']}")

    def _render_validate_test(self):
        """Render rule validation and testing interface"""
        st.markdown("### ✅ Validate & Test Rules")

        # Validation tabs
        tab1, tab2, tab3 = st.tabs(["🔍 Syntax Validation", "🧪 Logic Testing", "📊 Performance Analysis"])

        with tab1:
            st.markdown("#### 🔍 SIGMA Rule Syntax Validation")

            rule_to_validate = st.text_area(
                "Paste SIGMA rule for validation",
                height=300,
                placeholder="Paste your SIGMA rule YAML content here..."
            )

            if st.button("🔍 Validate Syntax"):
                if rule_to_validate:
                    validation_result = self._validate_rule_syntax(rule_to_validate)

                    if validation_result['valid']:
                        st.success("✅ Rule syntax is valid!")

                        # Show rule structure
                        with st.expander("📋 Rule Structure"):
                            rule_data = validation_result['parsed_rule']

                            col1, col2 = st.columns(2)

                            with col1:
                                st.write(f"**Title:** {rule_data.get('title', 'N/A')}")
                                st.write(f"**Level:** {rule_data.get('level', 'N/A')}")
                                st.write(f"**Status:** {rule_data.get('status', 'N/A')}")

                            with col2:
                                st.write(f"**Author:** {rule_data.get('author', 'N/A')}")
                                st.write(f"**Date:** {rule_data.get('date', 'N/A')}")
                                tags = rule_data.get('tags', [])
                                st.write(f"**Tags:** {len(tags)} tags")
                    else:
                        st.error(f"❌ Validation failed: {validation_result['error']}")

                        # Show specific errors
                        for error in validation_result.get('errors', []):
                            st.write(f"• {error}")
                else:
                    st.warning("Please paste a SIGMA rule to validate.")

        with tab2:
            st.markdown("#### 🧪 Detection Logic Testing")

            st.info("🚧 Logic testing functionality coming soon! This will allow you to test rules against sample log data.")

            # Placeholder for future implementation
            test_data = st.text_area(
                "Sample log data (JSON format)",
                height=150,
                placeholder='{"field1": "value1", "field2": "value2", ...}'
            )

            if st.button("🧪 Test Rule Logic"):
                st.info("Logic testing will be implemented in a future version.")

        with tab3:
            st.markdown("#### 📊 Performance Analysis")

            st.info("🚧 Performance analysis functionality coming soon! This will help optimize rule performance.")

            # Placeholder for future implementation
            if st.button("📊 Analyze Performance"):
                st.info("Performance analysis will be implemented in a future version.")

    def _render_rule_library(self):
        """Render rule library interface"""
        st.markdown("### 📚 Rule Library")

        # Library tabs
        tab1, tab2, tab3 = st.tabs(["📖 Browse Rules", "⭐ Favorites", "📊 Statistics"])

        with tab1:
            st.markdown("#### 📖 Browse All Rules")

            # Filters
            col1, col2, col3 = st.columns(3)

            with col1:
                source_filter = st.selectbox(
                    "Source",
                    ["All", "SigmaHQ Main", "Threat Hunting", "Emerging Threats", "Custom Rules"]
                )

            with col2:
                level_filter = st.selectbox(
                    "Level",
                    ["All", "low", "medium", "high", "critical"]
                )

            with col3:
                status_filter = st.selectbox(
                    "Status",
                    ["All", "experimental", "test", "stable"]
                )

            # Search
            search_term = st.text_input("Search rules", placeholder="Enter keywords...")

            # Get filtered rules
            filters = {}
            if source_filter != "All":
                filters['source_repo'] = source_filter
            if level_filter != "All":
                filters['level'] = level_filter
            if status_filter != "All":
                filters['status'] = status_filter
            if search_term:
                filters['search_term'] = search_term

            rules = self.db_manager.get_sigma_rules(filters, limit=50)

            st.write(f"Found {len(rules)} rules")

            # Show message if no rules found
            if not rules:
                st.info("📝 No rules found in the database. Try syncing SIGMA rules from the Settings page or create a custom rule.")


                return

            # Display rules
            for rule in rules:
                with st.expander(f"{rule['title']} ({rule['rule_id']})"):
                    col1, col2 = st.columns([2, 1])

                    with col1:
                        st.write(f"**Description:** {rule.get('description', 'No description')[:200]}...")
                        st.write(f"**Level:** {rule.get('level', 'Unknown')}")
                        st.write(f"**Author:** {rule.get('author', 'Unknown')}")

                    with col2:
                        if st.button(f"👁️ View", key=f"view_lib_{rule['rule_id']}"):
                            st.session_state.viewing_rule = rule
                            st.rerun()

                        if st.button(f"✏️ Edit", key=f"edit_lib_{rule['rule_id']}"):
                            st.session_state.edit_rule_data = rule
                            st.success(f"✅ Rule '{rule.get('title', 'Unknown')}' loaded for editing. Check the 'Edit Existing Rule' tab.")
                            st.rerun()

                        if st.button(f"📋 Copy", key=f"copy_lib_{rule['rule_id']}"):
                            st.session_state.clipboard = rule.get('rule_content', '')
                            st.success("✅ Rule content prepared for copying! Use the 'View' button to see the full YAML content.")

        with tab2:
            st.markdown("#### ⭐ Favorite Rules")
            st.info("🚧 Favorites functionality coming soon!")

        with tab3:
            st.markdown("#### 📊 Library Statistics")

            # Get statistics
            stats = self.db_manager.get_quick_stats()

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total Rules", stats.get('sigma_rules', 0))

            with col2:
                st.metric("Custom Rules", stats.get('custom_rules', 0))

            with col3:
                st.metric("MITRE Techniques", stats.get('mitre_techniques', 0))

    def _validate_rule_syntax(self, rule_content: str) -> Dict[str, Any]:
        """Validate SIGMA rule syntax - USES CENTRALIZED METHOD"""
        result = self.db_manager.validate_sigma_rule_syntax(rule_content)
        # Adapt the result format for compatibility
        if result.get('valid') and 'rule_data' in result:
            result['parsed_rule'] = result['rule_data']
        return result

    def _render_converter(self):
        """Render SIGMA rule converter interface"""
        st.markdown("### 🔄 SIGMA Rule Converter")
        st.markdown("Convert SIGMA rules to SQL queries and Python Detection as Code (DAC) functions.")

        # Conversion method selection
        conversion_method = st.radio(
            "Select conversion method:",
            ["Select from Database", "Paste Rule Content", "Upload File"],
            horizontal=True
        )

        rule_content = None
        rule_title = "Unknown Rule"

        if conversion_method == "Select from Database":
            # Enhanced rule selection with filtering and pagination
            st.markdown("#### 🔍 Rule Selection")

            # Rule filtering options
            col1, col2, col3 = st.columns(3)

            with col1:
                # Filter by source repository
                all_rules = self.db_manager.get_sigma_rules()  # Get all rules first for filtering
                if all_rules:
                    source_repos = list(set([rule.get('source_repo', 'Unknown') for rule in all_rules]))
                    selected_repo = st.selectbox("Filter by Source:", ["All Sources"] + source_repos)
                else:
                    selected_repo = "All Sources"

            with col2:
                # Filter by rule level
                if all_rules:
                    levels = list(set([rule.get('level', 'Unknown') for rule in all_rules if rule.get('level')]))
                    selected_level = st.selectbox("Filter by Level:", ["All Levels"] + levels)
                else:
                    selected_level = "All Levels"

            with col3:
                # Search by title/description
                search_term = st.text_input("Search Rules:", placeholder="Enter keywords...")

            # Apply filters
            filters = {}
            if selected_repo != "All Sources":
                filters['source_repo'] = selected_repo
            if selected_level != "All Levels":
                filters['level'] = selected_level
            if search_term:
                filters['search_term'] = search_term

            # Get filtered rules
            if filters:
                rules = self.db_manager.get_sigma_rules(filters=filters, limit=1000)  # Increased limit
            else:
                rules = self.db_manager.get_sigma_rules(limit=1000)  # Get more rules by default

            if rules:
                st.info(f"📊 Found {len(rules)} rules matching your criteria")

                # Create rule selection dropdown with better formatting
                rule_options = {}
                for rule in rules:
                    title = rule.get('title', 'Untitled')
                    level = rule.get('level', 'unknown')
                    source = rule.get('source_repo', 'Unknown')
                    rule_id = rule.get('rule_id', '')[:8]

                    display_name = f"[{level.upper()}] {title} | {source} ({rule_id})"
                    rule_options[display_name] = rule

                selected_rule_key = st.selectbox(
                    "Select a rule to convert:",
                    list(rule_options.keys()),
                    help="Rules are formatted as: [LEVEL] Title | Source (ID)"
                )

                if selected_rule_key:
                    selected_rule = rule_options[selected_rule_key]
                    rule_content = selected_rule.get('rule_content', '')
                    rule_title = selected_rule.get('title', 'Unknown Rule')

                    # Display rule metadata
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Level", selected_rule.get('level', 'N/A'))
                    with col2:
                        st.metric("Status", selected_rule.get('status', 'N/A'))
                    with col3:
                        st.metric("Author", selected_rule.get('author', 'N/A'))
                    with col4:
                        st.metric("Source", selected_rule.get('source_repo', 'N/A'))

                    # Display rule preview
                    with st.expander("📋 Rule Preview"):
                        st.code(rule_content, language='yaml')
            else:
                if filters:
                    st.warning("⚠️ No rules found matching your filter criteria. Try adjusting the filters.")
                else:
                    st.warning("⚠️ No rules found in database. Please sync rules first or create custom rules!")

        elif conversion_method == "Paste Rule Content":
            # Check if rule content was passed from rule details modal
            initial_content = ""
            if 'convert_rule_content' in st.session_state:
                initial_content = st.session_state.convert_rule_content
                del st.session_state.convert_rule_content
                st.info("✅ Rule loaded from Rule Library for conversion!")

            rule_content = st.text_area(
                "Paste SIGMA rule content (YAML format):",
                value=initial_content,
                height=300,
                placeholder="Paste your SIGMA rule YAML content here..."
            )

            if rule_content:
                # Try to parse and get title
                try:
                    rule_data = yaml.safe_load(rule_content)
                    rule_title = rule_data.get('title', 'Pasted Rule')
                except:
                    rule_title = "Pasted Rule"

        elif conversion_method == "Upload File":
            uploaded_file = st.file_uploader(
                "Choose a SIGMA rule file",
                type=['yml', 'yaml'],
                help="Upload a YAML file containing a SIGMA rule"
            )

            if uploaded_file is not None:
                try:
                    rule_content = uploaded_file.read().decode('utf-8')

                    # Try to parse and get title
                    try:
                        rule_data = yaml.safe_load(rule_content)
                        rule_title = rule_data.get('title', uploaded_file.name)
                    except:
                        rule_title = uploaded_file.name

                    # Display content preview
                    with st.expander("📋 Uploaded Rule Preview"):
                        st.code(rule_content, language='yaml')

                except Exception as e:
                    st.error(f"❌ Error reading file: {str(e)}")

        # Conversion options and execution
        if rule_content:
            st.markdown("---")
            st.markdown("### 🔧 Conversion Options")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**SQL Conversion (AI-Powered)**")
                sql_table_name = st.text_input("Target Table Name", value="events", help="Database table name for SQL query")

                # Enhanced log source selection with custom options
                predefined_sources = [
                    "windows", "linux", "web", "sysmon", "crowdstrike_epp",
                    "windows_defender", "palo_alto", "okta", "azure_ad",
                    "aws_cloudtrail", "gcp_audit", "office365", "splunk",
                    "elastic", "suricata", "zeek", "osquery"
                ]

                log_source_option = st.radio(
                    "Log Source Type:",
                    ["Predefined", "Custom"],
                    horizontal=True,
                    help="Choose predefined source or define custom mapping"
                )

                if log_source_option == "Predefined":
                    sql_log_source = st.selectbox(
                        "Select Log Source:",
                        predefined_sources,
                        help="Predefined field mappings for common log sources"
                    )

                    # Show supported fields for selected log source
                    with st.expander(f"📋 Supported Fields for {sql_log_source.title()}"):
                        if sql_log_source in self.sigma_converter.field_mappings:
                            mappings = self.sigma_converter.field_mappings[sql_log_source]
                            st.markdown("**Field Mappings:**")
                            for sigma_field, db_field in mappings.items():
                                st.text(f"• {sigma_field} → {db_field}")
                        else:
                            st.info("Using default field mappings (fields will be converted to lowercase)")
                else:
                    sql_log_source = st.text_input(
                        "Custom Log Source:",
                        value="custom",
                        help="Enter custom log source name (will use default field mappings)"
                    )

                    # Option to define custom field mappings
                    with st.expander("🔧 Custom Field Mappings (Optional)"):
                        st.markdown("Define custom field mappings for your log source:")
                        custom_mappings = st.text_area(
                            "Field Mappings (JSON format):",
                            placeholder='{\n  "EventID": "event_id",\n  "ProcessName": "process_name",\n  "CommandLine": "command_line"\n}',
                            help="JSON object mapping SIGMA fields to your database columns"
                        )

                        if custom_mappings:
                            try:
                                parsed_mappings = json.loads(custom_mappings)
                                st.success(f"✅ Custom mappings loaded: {len(parsed_mappings)} fields")
                                # Store custom mappings in session state for use in conversion
                                st.session_state.custom_field_mappings = parsed_mappings
                            except json.JSONDecodeError as e:
                                st.error(f"❌ Invalid JSON format: {e}")
                        else:
                            # Clear custom mappings if empty
                            if 'custom_field_mappings' in st.session_state:
                                del st.session_state.custom_field_mappings

            with col2:
                st.markdown("**Python DAC Conversion (AI-Powered)**")
                python_function_name = st.text_input("Function Name", value="", help="Leave empty for auto-generation")
                st.info("ℹ️ Both SQL and Python conversions now use AI by default with traditional fallback")

            # Conversion buttons
            st.markdown("---")
            st.markdown("### 🚀 Convert Rule")

            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button("🤖 Convert to SQL (AI)", type="primary"):
                    with st.spinner("🤖 Converting to SQL with AI..."):
                        # Always use LLM for SQL conversion
                        custom_mappings = st.session_state.get('custom_field_mappings', None)

                        context = {
                            'target_table': sql_table_name,
                            'log_source_type': sql_log_source,
                            'custom_field_mappings': custom_mappings,
                            'include_comments': True,
                            'optimize_performance': True,
                            'include_metadata': True
                        }

                        llm_result = self.sigma_converter.convert_with_llm(rule_content, 'sql', context)

                        if llm_result['success']:
                            st.success("✅ AI SQL conversion successful!")
                            st.markdown("**Generated SQL Query (AI-powered):**")
                            st.code(llm_result['converted_code'], language='sql')

                            # Copy button
                            if st.button("📋 Copy SQL", key="copy_sql"):
                                st.success("SQL copied to clipboard! (Use Ctrl+C to copy from the code block above)")
                        else:
                            st.error(f"❌ AI SQL conversion failed: {llm_result['error']}")

                            # Fallback to traditional conversion if LLM fails
                            st.info("🔄 Trying traditional conversion as fallback...")
                            fallback_result = self.sigma_converter.convert_to_sql(
                                rule_content,
                                target_table=sql_table_name,
                                log_source_type=sql_log_source,
                                custom_field_mappings=custom_mappings
                            )

                            if fallback_result['success']:
                                st.success("✅ Traditional SQL conversion successful!")
                                st.markdown("**Generated SQL Query (Traditional):**")
                                st.code(fallback_result['sql_query'], language='sql')

                                # Copy button for fallback
                                if st.button("📋 Copy SQL", key="copy_sql_fallback"):
                                    st.success("SQL copied to clipboard! (Use Ctrl+C to copy from the code block above)")
                            else:
                                st.error(f"❌ Traditional conversion also failed: {fallback_result['error']}")
                                st.error("❌ Both AI and traditional SQL conversion methods failed.")

            with col2:
                if st.button("🤖 Convert to Python DAC (AI)", type="primary"):
                    with st.spinner("🤖 Converting to Python with AI..."):
                        # Always use LLM for Python DAC conversion
                        context = {
                            'function_name': python_function_name if python_function_name else None,
                            'include_type_hints': True,
                            'include_error_handling': True,
                            'include_documentation': True
                        }

                        llm_result = self.sigma_converter.convert_with_llm(rule_content, 'python', context)

                        if llm_result['success']:
                            st.success("✅ AI Python conversion successful!")
                            st.markdown("**Generated Python Function (AI-powered):**")
                            st.code(llm_result['converted_code'], language='python')

                            # Copy button
                            if st.button("📋 Copy Python", key="copy_python"):
                                st.success("Python code copied to clipboard! (Use Ctrl+C to copy from the code block above)")
                        else:
                            st.error(f"❌ AI Python conversion failed: {llm_result['error']}")

                            # Fallback to traditional conversion if LLM fails
                            st.info("🔄 Trying traditional conversion as fallback...")
                            fallback_result = self.sigma_converter.convert_to_python_dac(
                                rule_content,
                                function_name=python_function_name if python_function_name else None
                            )

                            if fallback_result['success']:
                                st.success("✅ Traditional Python conversion successful!")
                                st.markdown("**Generated Python Function (Traditional):**")
                                st.code(fallback_result['python_function'], language='python')

                                # Copy button for fallback
                                if st.button("📋 Copy Python", key="copy_python_fallback"):
                                    st.success("Python code copied to clipboard! (Use Ctrl+C to copy from the code block above)")
                            else:
                                st.error(f"❌ Traditional conversion also failed: {fallback_result['error']}")
                                st.error("❌ Both AI and traditional Python conversion methods failed.")

            with col3:
                if st.button("🤖 Convert Both (AI)", type="secondary"):
                    with st.spinner("🤖 Converting to both formats with AI..."):
                        # Get custom field mappings if available
                        custom_mappings = st.session_state.get('custom_field_mappings', None)

                        # SQL conversion (AI-powered)
                        sql_context = {
                            'target_table': sql_table_name,
                            'log_source_type': sql_log_source,
                            'custom_field_mappings': custom_mappings,
                            'include_comments': True,
                            'optimize_performance': True,
                            'include_metadata': True
                        }
                        sql_result = self.sigma_converter.convert_with_llm(rule_content, 'sql', sql_context)

                        # Python conversion (AI-powered)
                        python_context = {
                            'function_name': python_function_name if python_function_name else None,
                            'include_type_hints': True,
                            'include_error_handling': True,
                            'include_documentation': True
                        }
                        python_result = self.sigma_converter.convert_with_llm(rule_content, 'python', python_context)

                        # Display results
                        if sql_result['success'] or python_result['success']:
                            st.success("✅ AI conversion completed!")

                            if sql_result['success']:
                                st.markdown("**SQL Query (AI-powered):**")
                                st.code(sql_result['converted_code'], language='sql')
                            else:
                                # Fallback to traditional SQL conversion
                                st.info("🔄 Trying traditional SQL conversion as fallback...")
                                sql_fallback = self.sigma_converter.convert_to_sql(
                                    rule_content,
                                    target_table=sql_table_name,
                                    log_source_type=sql_log_source,
                                    custom_field_mappings=custom_mappings
                                )
                                if sql_fallback['success']:
                                    st.success("✅ Traditional SQL conversion successful!")
                                    st.markdown("**SQL Query (Traditional):**")
                                    st.code(sql_fallback['sql_query'], language='sql')

                            if python_result['success']:
                                st.markdown("**Python Function (AI-powered):**")
                                st.code(python_result['converted_code'], language='python')
                            else:
                                # Fallback to traditional Python conversion
                                st.info("🔄 Trying traditional Python conversion as fallback...")
                                python_fallback = self.sigma_converter.convert_to_python_dac(
                                    rule_content,
                                    function_name=python_function_name if python_function_name else None
                                )
                                if python_fallback['success']:
                                    st.success("✅ Traditional Python conversion successful!")
                                    st.markdown("**Python Function (Traditional):**")
                                    st.code(python_fallback['python_function'], language='python')
                        else:
                            st.error("❌ Both AI conversions failed")
                            if not sql_result['success']:
                                st.error(f"SQL Error: {sql_result['error']}")
                            if not python_result['success']:
                                st.error(f"Python Error: {python_result['error']}")

                            # Try traditional fallbacks for both
                            st.info("🔄 Trying traditional conversions as fallback...")

                            sql_fallback = self.sigma_converter.convert_to_sql(
                                rule_content,
                                target_table=sql_table_name,
                                log_source_type=sql_log_source,
                                custom_field_mappings=custom_mappings
                            )

                            python_fallback = self.sigma_converter.convert_to_python_dac(
                                rule_content,
                                function_name=python_function_name if python_function_name else None
                            )

                            if sql_fallback['success'] or python_fallback['success']:
                                st.success("✅ Traditional conversion completed!")

                                if sql_fallback['success']:
                                    st.markdown("**SQL Query (Traditional):**")
                                    st.code(sql_fallback['sql_query'], language='sql')

                                if python_fallback['success']:
                                    st.markdown("**Python Function (Traditional):**")
                                    st.code(python_fallback['python_function'], language='python')
                            else:
                                st.error("❌ All conversion methods failed for both formats")
        else:
            st.info("👆 Please select or provide a SIGMA rule to convert.")

    def _suggest_mitre_techniques(self, description: str) -> List[tuple]:
        """Suggest MITRE ATT&CK techniques based on description using dynamic identification"""
        try:
            # Use the dynamic technique identification from LLM integration
            # This provides much better accuracy than hardcoded mappings

            # Get the primary technique suggestion
            primary_technique = self.llm_integration._identify_technique_from_description(description)

            suggestions = []

            if primary_technique:
                # Add the primary suggestion with high confidence
                suggestions.append((primary_technique, 0.95))

                # Get related techniques for additional suggestions
                related_techniques = self._get_related_techniques(primary_technique, description)
                suggestions.extend(related_techniques)
            else:
                # Fallback to basic keyword matching if dynamic identification fails
                suggestions = self._fallback_technique_suggestions(description)

            # Remove duplicates and sort by confidence
            seen = set()
            unique_suggestions = []
            for tech_id, confidence in suggestions:
                if tech_id not in seen:
                    seen.add(tech_id)
                    unique_suggestions.append((tech_id, confidence))

            unique_suggestions.sort(key=lambda x: x[1], reverse=True)
            return unique_suggestions[:5]  # Return top 5 matches

        except Exception as e:
            self.logger.error(f"Error suggesting MITRE techniques: {e}")
            return []

    def _get_related_techniques(self, primary_technique: str, description: str) -> List[tuple]:
        """Get techniques related to the primary identified technique"""
        try:
            related = []

            # Get all techniques from database
            all_techniques = self.db_manager.get_mitre_techniques()

            # Find the primary technique data
            primary_data = None
            for tech in all_techniques:
                if tech.get('technique_id') == primary_technique:
                    primary_data = tech
                    break

            if not primary_data:
                return related

            primary_tactic = primary_data.get('tactic', '')

            # Find techniques in the same tactic with lower confidence
            for tech in all_techniques:
                tech_id = tech.get('technique_id', '')
                if tech_id != primary_technique and tech.get('tactic') == primary_tactic:
                    # Add with lower confidence
                    related.append((tech_id, 0.3))
                    if len(related) >= 3:  # Limit to 3 related techniques
                        break

            return related

        except Exception as e:
            self.logger.error(f"Error getting related techniques: {e}")
            return []

    def _fallback_technique_suggestions(self, description: str) -> List[tuple]:
        """Fallback technique suggestions using basic keyword matching"""
        try:
            description_lower = description.lower()
            suggestions = []

            # Basic keyword mappings as fallback only
            basic_mappings = {
                'powershell': [('T1059.001', 0.7)],
                'command': [('T1059', 0.6)],
                'script': [('T1059', 0.6)],
                'credential': [('T1003', 0.6)],
                'process': [('T1055', 0.5)],
                'registry': [('T1112', 0.5)],
                'network': [('T1071', 0.5)],
                'file': [('T1005', 0.5)]
            }

            for keyword, mappings in basic_mappings.items():
                if keyword in description_lower:
                    suggestions.extend(mappings)

            return suggestions

        except Exception as e:
            self.logger.error(f"Error in fallback technique suggestions: {e}")
            return []
