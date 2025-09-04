#!/usr/bin/env python3
"""
Debug UI Components for Multi-Audit YMYL Tool
Shows individual audit results for debugging
"""

import streamlit as st
from datetime import datetime
from typing import Dict, Any

def show_debug_results(analysis_result: Dict[str, Any], word_bytes: bytes):
    """
    Show debug results with individual audit reports + final merged report
    
    Args:
        analysis_result: Debug analysis results containing individual + merged reports
        word_bytes: Word document bytes for download
    """
    
    if not analysis_result.get('debug_mode'):
        st.error("❌ Not a debug analysis result")
        return
    
    st.success("✅ **Debug Analysis Complete!**")
    
    # Show summary statistics
    _show_debug_statistics(analysis_result)
    
    # Download section
    _show_debug_download_section(word_bytes, analysis_result)
    
    # Individual audit reports
    _show_individual_audit_reports(analysis_result)
    
    # Final merged report
    _show_final_merged_report(analysis_result)
    
    # Raw data inspection
    _show_raw_data_inspection(analysis_result)

def _show_debug_statistics(analysis_result: Dict[str, Any]):
    """Show debug statistics overview"""
    
    st.markdown("### 📊 Debug Statistics")
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Successful Audits", 
            f"{analysis_result.get('successful_audits', 0)}/5"
        )
    
    with col2:
        st.metric(
            "Total Violations Found", 
            analysis_result.get('total_violations_found', 0)
        )
    
    with col3:
        st.metric(
            "Unique After Deduplication", 
            analysis_result.get('unique_violations', 0)
        )
    
    with col4:
        dedup_ratio = 0
        if analysis_result.get('total_violations_found', 0) > 0:
            dedup_ratio = (1 - analysis_result.get('unique_violations', 0) / analysis_result.get('total_violations_found', 1)) * 100
        st.metric(
            "Deduplication %", 
            f"{dedup_ratio:.1f}%"
        )
    
    # Detailed debug info
    debug_info = analysis_result.get('debug_info', {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Total Execution Time", 
            f"{debug_info.get('total_execution_time', 0):.2f}s"
        )
    
    with col2:
        st.metric(
            "Average Audit Time", 
            f"{debug_info.get('average_audit_time', 0):.2f}s"
        )
    
    with col3:
        st.metric(
            "Content Size", 
            f"{debug_info.get('content_size', 0):,} chars"
        )
    
    # Show failed audits if any
    failed_audits = analysis_result.get('failed_audits', [])
    if failed_audits:
        st.warning(f"⚠️ {len(failed_audits)} audit(s) failed:")
        for failed in failed_audits:
            st.text(f"• Audit #{failed.get('audit_number', 'Unknown')}: {failed.get('error', 'Unknown error')}")

def _show_debug_download_section(word_bytes: bytes, analysis_result: Dict[str, Any]):
    """Show download section with debug info"""
    
    st.markdown("### 📄 Download Reports")
    
    # Download final merged report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ymyl_debug_report_{timestamp}.docx"
    
    col1, col2 = st.columns(2)
    
    with col1:
        if word_bytes:
            st.download_button(
                label="📄 Download Final Merged Report",
                data=word_bytes,
                file_name=filename,
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                type="primary",
                use_container_width=True,
                key=f"download_merged_{timestamp}"
            )
    
    with col2:
        if st.button("🔄 Run New Analysis", use_container_width=True, key=f"new_debug_analysis_{timestamp}"):
            # Clear debug results
            keys_to_clear = [k for k in st.session_state.keys() if 'debug_analysis' in k]
            for key in keys_to_clear:
                del st.session_state[key]
            st.rerun()
    
    st.info("💡 **Tip**: The Word document contains the final merged report. Individual audit reports are shown below for debugging.")

def _show_individual_audit_reports(analysis_result: Dict[str, Any]):
    """Show individual audit reports in expandable sections"""
    
    st.markdown("### 🔍 Individual Audit Reports")
    
    individual_reports = analysis_result.get('individual_reports', {})
    individual_raw_results = analysis_result.get('individual_raw_results', [])
    
    if not individual_reports:
        st.warning("⚠️ No individual reports available")
        return
    
    # Create tabs for each audit
    audit_numbers = sorted([int(k.split('_')[1]) for k in individual_reports.keys()])
    tab_labels = [f"Audit #{num}" for num in audit_numbers]
    
    if len(tab_labels) > 0:
        tabs = st.tabs(tab_labels)
        
        for i, audit_num in enumerate(audit_numbers):
            with tabs[i]:
                audit_key = f'audit_{audit_num}'
                report = individual_reports.get(audit_key, '')
                
                # Find corresponding raw result
                raw_result = next((r for r in individual_raw_results if r.get('audit_number') == audit_num), None)
                
                # Show audit metadata
                if raw_result:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Processing Time", f"{raw_result.get('processing_time', 0):.2f}s")
                    with col2:
                        st.metric("Response Length", f"{raw_result.get('response_length', 0):,} chars")
                    with col3:
                        st.metric("Thread ID", raw_result.get('thread_id', 'N/A')[-8:] if raw_result.get('thread_id') else 'N/A')
                
                # Show individual report
                if report:
                    st.markdown("#### 📄 Individual Report")
                    st.markdown(report)
                else:
                    st.error(f"❌ No report available for Audit #{audit_num}")
                
                # Show raw response in expander
                if raw_result and raw_result.get('raw_response'):
                    with st.expander(f"🤖 Raw AI Response - Audit #{audit_num}"):
                        st.text_area(
                            f"Raw response from Audit #{audit_num}:",
                            value=raw_result['raw_response'],
                            height=300,
                            key=f"raw_response_{audit_num}"
                        )
                
                # Show parsed violations
                if raw_result and raw_result.get('ai_response'):
                    with st.expander(f"📋 Parsed Violations - Audit #{audit_num}"):
                        violations_count = 0
                        for section in raw_result['ai_response']:
                            violations = section.get('violations', [])
                            if violations != "no violation found" and violations:
                                violations_count += len(violations)
                        
                        st.info(f"Found {violations_count} violations in this audit")
                        st.json(raw_result['ai_response'])

def _show_final_merged_report(analysis_result: Dict[str, Any]):
    """Show final merged report"""
    
    st.markdown("### 🎯 Final Merged Report")
    
    merged_report = analysis_result.get('report', '')
    
    if merged_report:
        st.markdown(merged_report)
    else:
        st.error("❌ No merged report available")

def _show_raw_data_inspection(analysis_result: Dict[str, Any]):
    """Show raw data for deep debugging"""
    
    st.markdown("### 🔬 Raw Data Inspection")
    
    with st.expander("🎯 Deduplication Analysis"):
        st.markdown("**Before vs After Deduplication:**")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Raw Violations (All Audits)", analysis_result.get('total_violations_found', 0))
        with col2:
            st.metric("Unique Violations (After Dedup)", analysis_result.get('unique_violations', 0))
        
        # Show which audits found what
        individual_raw_results = analysis_result.get('individual_raw_results', [])
        
        st.markdown("**Violations per Audit:**")
        for result in individual_raw_results:
            audit_num = result.get('audit_number', 'Unknown')
            violations_count = 0
            
            for section in result.get('ai_response', []):
                violations = section.get('violations', [])
                if violations != "no violation found" and violations:
                    violations_count += len(violations)
            
            st.text(f"Audit #{audit_num}: {violations_count} violations")
    
    with st.expander("📊 Full Analysis Result (JSON)"):
        # Remove raw responses to avoid clutter
        clean_result = analysis_result.copy()
        if 'individual_raw_results' in clean_result:
            for result in clean_result['individual_raw_results']:
                if 'raw_response' in result:
                    result['raw_response'] = f"[{len(result['raw_response'])} characters - hidden for brevity]"
        
        st.json(clean_result)
    
    with st.expander("⚙️ Debug Configuration"):
        debug_info = analysis_result.get('debug_info', {})
        
        st.markdown("**System Information:**")
        st.text(f"Assistant Used: {debug_info.get('assistant_used', 'Unknown')}")
        st.text(f"Content Size: {debug_info.get('content_size', 0):,} characters")
        st.text(f"Total Execution Time: {debug_info.get('total_execution_time', 0):.2f} seconds")
        st.text(f"Average Audit Time: {debug_info.get('average_audit_time', 0):.2f} seconds")
        
        # Performance analysis
        if debug_info.get('total_execution_time', 0) > 0:
            efficiency = debug_info.get('average_audit_time', 0) / debug_info.get('total_execution_time', 1) * 100
            st.text(f"Parallel Efficiency: {efficiency:.1f}% (lower is better - indicates good parallelization)")

def show_debug_comparison_analysis(analysis_result: Dict[str, Any]):
    """Show comparison analysis between individual audits"""
    
    st.markdown("### 🔬 Audit Comparison Analysis")
    
    individual_raw_results = analysis_result.get('individual_raw_results', [])
    
    if len(individual_raw_results) < 2:
        st.warning("⚠️ Need at least 2 successful audits for comparison")
        return
    
    # Collect all violations from all audits with source tracking
    all_violations_with_source = []
    
    for result in individual_raw_results:
        audit_num = result.get('audit_number', 'Unknown')
        
        for section in result.get('ai_response', []):
            violations = section.get('violations', [])
            if violations != "no violation found" and violations:
                for violation in violations:
                    violation_copy = violation.copy()
                    violation_copy['_source_audit'] = audit_num
                    all_violations_with_source.append(violation_copy)
    
    # Group violations by problematic text for comparison
    violation_groups = {}
    for violation in all_violations_with_source:
        key = violation.get('problematic_text', '').strip().lower()
        if key:
            if key not in violation_groups:
                violation_groups[key] = []
            violation_groups[key].append(violation)
    
    # Show overlaps
    st.markdown("#### 🎯 Violation Overlaps Between Audits")
    
    overlapping_violations = {k: v for k, v in violation_groups.items() if len(v) > 1}
    unique_violations = {k: v for k, v in violation_groups.items() if len(v) == 1}
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Overlapping Issues", len(overlapping_violations))
    with col2:
        st.metric("Unique Issues", len(unique_violations))
    
    # Show overlapping violations
    if overlapping_violations:
        st.markdown("**🔄 Issues Found by Multiple Audits:**")
        
        for i, (text, violations) in enumerate(list(overlapping_violations.items())[:10], 1):  # Limit to 10 for display
            audits_found_by = [v.get('_source_audit', 'Unknown') for v in violations]
            severities = [v.get('severity', 'medium') for v in violations]
            
            st.markdown(f"**{i}. Found by Audits: {', '.join([f'#{a}' for a in sorted(audits_found_by)])}**")
            st.text(f"Text: {text[:100]}{'...' if len(text) > 100 else ''}")
            st.text(f"Severities: {', '.join(severities)}")
            st.markdown("---")
    
    # Show audit agreement statistics
    st.markdown("#### 📈 Audit Agreement Statistics")
    
    total_issues = len(violation_groups)
    if total_issues > 0:
        overlap_percentage = len(overlapping_violations) / total_issues * 100
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Unique Issues", total_issues)
        with col2:
            st.metric("Issues with Agreement", len(overlapping_violations))
        with col3:
            st.metric("Agreement Rate", f"{overlap_percentage:.1f}%")