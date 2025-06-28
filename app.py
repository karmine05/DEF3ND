"""
SIGMA Detection Engineering Platform
Main Streamlit Application

A comprehensive detection engineering platform featuring:
- MITRE ATT&CK Explorer
- SIGMA Rule Builder with LLM assistance
- Advanced detection search engine
- Attack path mapping and visualization
"""

import streamlit as st
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

from components.mitre_explorer import MitreExplorer
from components.sigma_builder import SigmaBuilder
from components.search_engine import SearchEngine
from components.attack_mapper import AttackMapper
from utils.database_manager import DatabaseManager
from utils.sigma_sync import SigmaSync
from utils.llm_integration import LLMIntegration
import config

# Page configuration
st.set_page_config(
    page_title="SIGMA Detection Engineering Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #ff7f0e;
        margin-bottom: 1rem;
    }
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 1rem 0;
    }
    .sidebar .sidebar-content {
        background-color: #f8f9fa;
    }
</style>
""", unsafe_allow_html=True)

def initialize_app():
    """Initialize application components and database"""
    if 'initialized' not in st.session_state:
        with st.spinner("Initializing SIGMA Detection Platform..."):
            # Initialize database
            db_manager = DatabaseManager()
            db_manager.initialize_database()
            
            # Initialize components
            st.session_state.db_manager = db_manager
            st.session_state.sigma_sync = SigmaSync(db_manager)
            st.session_state.llm_integration = LLMIntegration(db_manager=db_manager)
            st.session_state.mitre_explorer = MitreExplorer(db_manager, st.session_state.llm_integration)
            st.session_state.sigma_builder = SigmaBuilder(db_manager, st.session_state.llm_integration)
            st.session_state.search_engine = SearchEngine(db_manager)
            st.session_state.attack_mapper = AttackMapper(db_manager)
            
            st.session_state.initialized = True
        st.success("✅ Platform initialized successfully!")

def main():
    """Main application function"""
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ SIGMA Detection Engineering Platform</h1>', unsafe_allow_html=True)
    
    # Initialize app
    initialize_app()
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### 🔧 Navigation")

        # Available pages
        available_pages = [
            "🏠 Dashboard",
            "🎯 MITRE ATT&CK Explorer",
            "📝 SIGMA Rule Builder",
            "🔍 Detection Search Engine",
            "🗺️ Attack Path Mapper",
            "⚙️ Settings & Sync"
        ]

        # Initialize current page in session state if not exists
        if 'current_page' not in st.session_state:
            st.session_state.current_page = "🏠 Dashboard"

        # Get the current page index
        try:
            current_index = available_pages.index(st.session_state.current_page)
        except ValueError:
            current_index = 0
            st.session_state.current_page = available_pages[0]

        # Use the selectbox for navigation
        page = st.selectbox(
            "Select Module",
            available_pages,
            index=current_index,
            key="navigation_selectbox"
        )

        # Update session state if page changed via selectbox
        if page != st.session_state.current_page:
            st.session_state.current_page = page

        # Use the current page from session state
        page = st.session_state.current_page
        
        st.markdown("---")
        
        # Quick stats
        if 'db_manager' in st.session_state:
            stats = st.session_state.db_manager.get_quick_stats()
            st.markdown("### 📊 Quick Stats")
            st.metric("SIGMA Rules", stats.get('sigma_rules', 0))
            st.metric("MITRE Techniques", stats.get('mitre_techniques', 0))
            st.metric("Custom Rules", stats.get('custom_rules', 0))
    
    # Main content area
    if page == "🏠 Dashboard":
        show_dashboard()
    elif page == "🎯 MITRE ATT&CK Explorer":
        st.session_state.mitre_explorer.render()
    elif page == "📝 SIGMA Rule Builder":
        st.session_state.sigma_builder.render()
    elif page == "🔍 Detection Search Engine":
        st.session_state.search_engine.render()
    elif page == "🗺️ Attack Path Mapper":
        st.session_state.attack_mapper.render()
    elif page == "⚙️ Settings & Sync":
        show_settings()

def show_dashboard():
    """Display main dashboard"""
    st.markdown('<h2 class="sub-header">📊 Platform Dashboard</h2>', unsafe_allow_html=True)
    
    # Enhanced overview metrics
    col1, col2, col3, col4 = st.columns(4)

    if 'db_manager' in st.session_state:
        stats = st.session_state.db_manager.get_detailed_stats()

        with col1:
            st.metric(
                "Total SIGMA Rules",
                stats.get('sigma_rules', 0),
                delta=stats.get('new_rules_this_week', 0)
            )

        with col2:
            st.metric(
                "MITRE Techniques",
                stats.get('mitre_techniques', 0),
                delta=f"{stats.get('complete_data_percentage', 0):.1f}% complete data"
            )

        with col3:
            st.metric(
                "Detection Coverage",
                f"{stats.get('detection_data_percentage', 0):.1f}%",
                delta=f"{stats.get('techniques_with_detection', 0)} techniques"
            )

        with col4:
            st.metric(
                "Mitigation Coverage",
                f"{stats.get('mitigation_data_percentage', 0):.1f}%",
                delta=f"{stats.get('techniques_with_mitigation', 0)} techniques"
            )

        # Additional enhanced metrics row
        st.markdown("---")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Custom Rules",
                stats.get('custom_rules', 0),
                delta=stats.get('new_custom_rules', 0)
            )

        with col2:
            st.metric(
                "High-Confidence Mappings",
                stats.get('high_confidence_mappings', 0),
                delta="Quality mappings"
            )

        with col3:
            st.metric(
                "Complete MITRE Data",
                stats.get('techniques_with_complete_data', 0),
                delta=f"{stats.get('complete_data_percentage', 0):.1f}%"
            )

        with col4:
            st.metric(
                "Last Sync",
                stats.get('last_sync', 'Never'),
                delta=None
            )
    
    # Recent activity and quick actions
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🚀 Quick Actions")
        if st.button("🔄 Sync SIGMA Rules", use_container_width=True, key="sync_sigma_rules_btn"):
            with st.spinner("Syncing SIGMA rules..."):
                result = st.session_state.sigma_sync.sync_all_rules()
                if result['success']:
                    st.success(f"✅ Synced {result['count']} rules successfully!")
                    # Force refresh to update stats
                    st.rerun()
                else:
                    st.error(f"❌ Sync failed: {result['error']}")
        
        if st.button("🎯 Update MITRE Data", use_container_width=True, key="update_mitre_data_btn"):
            with st.spinner("Updating MITRE ATT&CK data..."):
                try:
                    st.info("🔄 Starting MITRE data update...")
                    result = st.session_state.mitre_explorer.update_mitre_data()
                    st.info(f"📊 Update result: {result}")

                    if result.get('success'):
                        st.success(f"✅ MITRE data updated successfully! Updated {result.get('count', 0)} techniques.")
                        if result.get('mappings_processed', 0) > 0:
                            st.info(f"🔗 Processed {result['mappings_processed']} rule-technique mappings.")
                        # Force refresh to update stats
                        st.rerun()
                    else:
                        st.error(f"❌ Update failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    st.error(f"❌ Update failed with exception: {str(e)}")
                    st.exception(e)
        
        if st.button("📝 Create New Rule", use_container_width=True, key="create_new_rule_btn"):
            # Clear any existing edit data and navigate to SIGMA Rule Builder
            if 'edit_rule_data' in st.session_state:
                del st.session_state.edit_rule_data
            st.session_state.current_page = "📝 SIGMA Rule Builder"
            st.success("✅ Navigate to SIGMA Rule Builder to create a new rule.")
            st.info("💡 Go to the 'SIGMA Rule Builder' page in the sidebar.")
    
    with col2:
        st.markdown("### 📈 Recent Activity")
        if 'db_manager' in st.session_state:
            recent_activity = st.session_state.db_manager.get_recent_activity()
            for activity in recent_activity[:5]:
                st.write(f"• {activity['action']} - {activity['timestamp']}")

def show_settings():
    """Display settings and sync options"""
    st.markdown('<h2 class="sub-header">⚙️ Settings & Configuration</h2>', unsafe_allow_html=True)
    
    # Sync settings
    st.markdown("### 🔄 Synchronization Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.checkbox("Enable automatic weekly sync", value=True, help="Automatically sync SIGMA rules weekly")
        st.selectbox("Sync day", ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"], help="Day of the week to perform sync")
        st.time_input("Sync time", help="Time of day to perform sync")
    
    with col2:
        st.markdown("### 📊 Database Status")
        if 'db_manager' in st.session_state:
            db_info = st.session_state.db_manager.get_database_info()
            st.write(f"Database size: {db_info.get('size', 'Unknown')}")
            st.write(f"Total tables: {db_info.get('tables', 0)}")
            st.write(f"Last backup: {db_info.get('last_backup', 'Never')}")

            # Database statistics
            st.markdown("#### 📊 Database Statistics")
            current_stats = st.session_state.db_manager.get_quick_stats()
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("SIGMA Rules", current_stats.get('sigma_rules', 0))
            with col2:
                st.metric("MITRE Techniques", current_stats.get('mitre_techniques', 0))
            with col3:
                st.metric("Custom Rules", current_stats.get('custom_rules', 0))

            if st.button("🔄 Refresh Stats", key="refresh_stats_btn"):
                st.rerun()
    
    # LLM settings
    st.markdown("### 🤖 LLM Configuration")

    ollama_host = st.text_input("Ollama Host", value=config.DEFAULT_OLLAMA_HOST)

    # Get available models from Ollama
    available_models = st.session_state.llm_integration.get_available_models(ollama_host)
    if available_models:
        ollama_model = st.selectbox("Ollama Model", available_models,
                                  index=0 if config.DEFAULT_OLLAMA_MODEL not in available_models
                                  else available_models.index(config.DEFAULT_OLLAMA_MODEL))
    else:
        ollama_model = st.text_input("Ollama Model", value=config.DEFAULT_OLLAMA_MODEL)


    
    # Manual sync options
    st.markdown("### 🔧 Manual Operations")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Force Sync All", use_container_width=True):
            with st.spinner("Force syncing all data..."):
                # Force sync SIGMA rules and MITRE data
                sigma_result = st.session_state.sigma_sync.sync_all_rules()
                mitre_result = st.session_state.mitre_explorer.update_mitre_data()

                if sigma_result['success'] and mitre_result['success']:
                    st.success("✅ Force sync completed!")
                    st.rerun()
                else:
                    st.error("❌ Force sync failed!")

    with col2:
        if st.button("Clear Cache", use_container_width=True):
            with st.spinner("Clearing cache..."):
                # Clear application cache
                for key in list(st.session_state.keys()):
                    if key.startswith('cache_'):
                        del st.session_state[key]
                st.success("✅ Cache cleared!")

    with col3:
        if st.button("Backup Database", use_container_width=True):
            with st.spinner("Creating backup..."):
                # Create database backup
                backup_result = st.session_state.db_manager.create_backup()
                if backup_result['success']:
                    st.success(f"✅ Backup created: {backup_result['filename']}")
                else:
                    st.error(f"❌ Backup failed: {backup_result['error']}")

if __name__ == "__main__":
    main()
