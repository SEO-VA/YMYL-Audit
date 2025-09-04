#!/usr/bin/env python3
"""
AI Analysis module for YMYL Audit Tool - 5 PARALLEL AUDITS VERSION
Handles OpenAI Assistant API calls with 5 parallel audits + deduplication
Includes optional debug mode for admin users
"""

import asyncio
import time
import json
from typing import Dict, Any, Optional, List
from openai import OpenAI
from config.settings import get_ai_settings
from utils.helpers import safe_log

class YMYLAnalyzer:
    """Handles AI analysis using OpenAI Assistant API with 5 parallel audits"""
    
    def __init__(self):
        """Initialize the analyzer"""
        self.settings = get_ai_settings()
        self.client = OpenAI(api_key=self.settings['api_key'])
        self.timeout = self.settings['timeout']

    async def analyze_content(self, json_content: str, casino_mode: bool = False, debug_mode: bool = False) -> Dict[str, Any]:
        """
        Analyze content for YMYL compliance using 5 parallel audits
        
        Args:
            json_content: Structured JSON content to analyze
            casino_mode: Whether to use casino-specific analysis
            debug_mode: Whether to return individual audit reports (admin feature)
            
        Returns:
            Dictionary with analysis results (+ debug info if debug_mode=True)
        """
        try:
            safe_log(f"Starting 5 parallel AI audits (casino_mode: {casino_mode}, debug_mode: {debug_mode})")

            # Select appropriate assistant for audits (not deduplication)
            assistant_id = (self.settings['casino_assistant_id'] if casino_mode
                          else self.settings['regular_assistant_id'])

            safe_log(f"Using assistant: {assistant_id} for 5 parallel calls")

            # Validate content size
            content_size = len(json_content)
            max_size = self.settings['max_content_size']
            if content_size > max_size:
                return {
                    'success': False,
                    'error': f'Content too large: {content_size:,} chars (max: {max_size:,})'
                }

            # Run 5 parallel audits
            return await self._run_parallel_audits(json_content, assistant_id, casino_mode, debug_mode)

        except Exception as e:
            error_msg = f"Multi-audit analysis error: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    async def _run_parallel_audits(self, content: str, assistant_id: str, casino_mode: bool, debug_mode: bool) -> Dict[str, Any]:
        """Run 5 parallel audits and return results with optional debug info"""
        try:
            safe_log("Creating 5 parallel audit tasks")

            # Create 5 identical parallel tasks
            tasks = [
                self._process_with_assistant(content, assistant_id, audit_number=i+1)
                for i in range(5)
            ]

            # Wait for all 5 to complete
            start_time = time.time()
            audit_results = await asyncio.gather(*tasks, return_exceptions=True)
            total_time = time.time() - start_time

            safe_log(f"All 5 audits completed in {total_time:.2f} seconds")

            # Process results
            successful_results = []
            failed_results = []
            individual_reports = {}

            for i, result in enumerate(audit_results):
                audit_num = i + 1
                if isinstance(result, Exception):
                    safe_log(f"Audit {audit_num} failed: {str(result)}")
                    failed_results.append({
                        'audit_number': audit_num,
                        'error': str(result)
                    })
                elif result.get('success'):
                    successful_results.append(result)
                    # Generate individual report if debug mode
                    if debug_mode:
                        individual_reports[f'audit_{audit_num}'] = self._create_individual_report(result, audit_num)
                else:
                    error_msg = result.get('error', 'Unknown error')
                    safe_log(f"Audit {audit_num} returned error: {error_msg}")
                    failed_results.append({
                        'audit_number': audit_num,
                        'error': error_msg
                    })

            if len(successful_results) == 0:
                return {
                    'success': False,
                    'error': 'All 5 audits failed',
                    'failed_audits': failed_results
                }

            safe_log(f"Successfully completed {len(successful_results)}/5 audits")

            # Create merged result using deduplicator assistant
            merged_result = await self._merge_audit_results_by_position(successful_results, total_time, casino_mode)

            # Build return data
            result_data = {
                'success': True,
                'report': merged_result['report'],
                'ai_response': merged_result['ai_response'],
                'processing_time': merged_result['processing_time'],
                'total_violations_found': merged_result['total_violations_found'],
                'unique_violations': merged_result['unique_violations']
            }

            # Add debug info if requested
            if debug_mode:
                result_data.update({
                    'debug_mode': True,
                    'individual_reports': individual_reports,
                    'individual_raw_results': successful_results,
                    'total_audits_attempted': 5,
                    'successful_audits': len(successful_results),
                    'failed_audits': failed_results,
                    'debug_info': {
                        'total_execution_time': total_time,
                        'average_audit_time': sum(r.get('processing_time', 0) for r in successful_results) / len(successful_results),
                        'content_size': len(content),
                        'assistant_used': assistant_id,
                        'deduplicator_assistant_id': self.settings['deduplicator_assistant_id']
                    }
                })

            return result_data

        except Exception as e:
            error_msg = f"Parallel audit execution error: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    async def _merge_audit_results_by_position(self, audit_results: List[Dict[str, Any]], total_time: float, casino_mode: bool) -> Dict[str, Any]:
        """
        Merge audit results by content position, then deduplicate with dedicated deduplicator assistant
        """
        total_processing_time = 0
        audit_count = len(audit_results)

        safe_log(f"Merging results by content position from {audit_count} audits")

        # Step 1: Get section names from first audit only
        first_audit = audit_results[0]
        section_structure = {}

        for section in first_audit.get('ai_response', []):
            position_key = section.get('big_chunk_index', 1)
            section_name = section.get('content_name', f'Section {position_key}')

            section_structure[position_key] = {
                'content_name': section_name,
                'violations': []
            }

        safe_log(f"Section structure from first audit: {len(section_structure)} sections")

        # Step 2: Collect ALL violations from ALL audits by position - WITH SAFETY CHECKS
        total_violations_before = 0

        for result in audit_results:
            total_processing_time += result.get('processing_time', 0)
            ai_response = result.get('ai_response', [])

            for section in ai_response:
                position_key = section.get('big_chunk_index', 1)
                violations = section.get('violations', [])

                if position_key not in section_structure:
                    section_structure[position_key] = {
                        'content_name': f'Section {position_key}',
                        'violations': []
                    }

                # SAFETY CHECK: Only process valid violations
                if violations != "no violation found" and violations:
                    # Ensure violations is a list and contains only dict objects
                    if isinstance(violations, list):
                        valid_violations = []
                        for violation in violations:
                            if isinstance(violation, dict):  # SAFETY CHECK: Only process dict violations
                                # Create a copy to avoid modifying original
                                violation_copy = violation.copy()
                                violation_copy['_audit_source'] = result.get('audit_number', 0)
                                violation_copy['_original_section_name'] = section.get('content_name', '')
                                valid_violations.append(violation_copy)
                            else:
                                safe_log(f"Skipping non-dict violation in audit {result.get('audit_number')}: {repr(violation)}")
                        
                        section_structure[position_key]['violations'].extend(valid_violations)
                        total_violations_before += len(valid_violations)
                    else:
                        safe_log(f"Skipping non-list violations in audit {result.get('audit_number')}: {repr(violations)}")

        safe_log(f"Total violations collected: {total_violations_before}")

        # Step 3: Prepare sections for deduplication assistant
        sections_for_deduplication = []
        for position_key in sorted(section_structure.keys()):
            section_data = section_structure[position_key]
            sections_for_deduplication.append({
                'big_chunk_index': position_key,
                'content_name': section_data['content_name'],
                'violations': section_data['violations'] if section_data['violations'] else "no violation found"
            })

        safe_log(f"Prepared {len(sections_for_deduplication)} sections for DEDUPLICATION ASSISTANT")

        # Step 4: Use DEDUPLICATOR assistant (not the audit assistant)
        try:
            assistant_id = self.settings['deduplicator_assistant_id']
            dedup_json = json.dumps(sections_for_deduplication, indent=2, ensure_ascii=False)

            safe_log(f"Sending {len(dedup_json):,} chars to DEDUPLICATOR ASSISTANT (ID: {assistant_id})")
            safe_log(f"DEDUPLICATOR will process {total_violations_before} violations across {len(sections_for_deduplication)} sections")
            safe_log("NOTE: Deduplication takes longer as it analyzes and merges all violations from 5 audits")

            dedup_result = await self._process_with_assistant(dedup_json, assistant_id, audit_number=99)

            if not dedup_result.get('success'):
                error_msg = dedup_result.get('error', 'Unknown deduplication error')
                safe_log(f"Deduplication failed: {error_msg}")
                return self._fallback_merge_results(sections_for_deduplication, total_processing_time, audit_count, total_violations_before)

            # Step 5: Get deduplicated sections
            deduplicated_sections = dedup_result.get('ai_response', [])
            final_violation_count = 0

            for section in deduplicated_sections:
                violations = section.get('violations', [])
                if violations != "no violation found" and violations:
                    final_violation_count += len(violations)

            safe_log(f"Deduplication complete: {total_violations_before} → {final_violation_count} violations")

            # Step 6: Generate report
            markdown_report = self._convert_to_clean_markdown(deduplicated_sections)

            return {
                'success': True,
                'report': markdown_report,
                'ai_response': deduplicated_sections,
                'processing_time': total_processing_time / audit_count,
                'total_audits': audit_count,
                'total_violations_found': total_violations_before,
                'unique_violations': final_violation_count,
                'deduplication_time': dedup_result.get('processing_time', 0)
            }

        except Exception as e:
            safe_log(f"Deduplication error: {str(e)}, using fallback")
            return self._fallback_merge_results(sections_for_deduplication, total_processing_time, audit_count, total_violations_before)

    def _fallback_merge_results(self, sections: List[Dict[str, Any]], total_processing_time: float, audit_count: int, total_violations_before: int) -> Dict[str, Any]:
        """Fallback to basic deduplication if assistant fails"""
        safe_log("Using fallback basic deduplication")

        fallback_sections = []
        final_violation_count = 0

        for section in sections:
            violations = section.get('violations', [])

            if violations != "no violation found" and violations:
                unique_violations = self._deduplicate_violations(violations)
                final_violation_count += len(unique_violations)

                fallback_sections.append({
                    'big_chunk_index': section.get('big_chunk_index', 1),
                    'content_name': section.get('content_name', 'Content Analysis'),
                    'violations': unique_violations
                })
            else:
                fallback_sections.append({
                    'big_chunk_index': section.get('big_chunk_index', 1),
                    'content_name': section.get('content_name', 'Content Analysis'),
                    'violations': "no violation found"
                })

        markdown_report = self._convert_to_clean_markdown(fallback_sections)

        return {
            'success': True,
            'report': markdown_report,
            'ai_response': fallback_sections,
            'processing_time': total_processing_time / audit_count,
            'total_audits': audit_count,
            'total_violations_found': total_violations_before,
            'unique_violations': final_violation_count
        }

    def _deduplicate_violations(self, all_violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Basic deduplication with safety checks"""
        seen_violations = {}
        unique_violations = []
        
        for violation in all_violations:
            # SAFETY CHECK: Only process dict violations
            if not isinstance(violation, dict):
                safe_log(f"Skipping non-dict violation in deduplication: {repr(violation)}")
                continue
                
            problematic_text = violation.get('problematic_text', '').strip().lower()
            violation_type = violation.get('violation_type', '').strip().lower()
            
            if not problematic_text and not violation_type:
                continue
                
            key = (problematic_text, violation_type)
            
            if key not in seen_violations:
                seen_violations[key] = violation
                unique_violations.append(violation)
            else:
                existing = seen_violations[key]
                merged_violation = self._merge_duplicate_violations(existing, violation)
                idx = unique_violations.index(existing)
                unique_violations[idx] = merged_violation
                seen_violations[key] = merged_violation
                
        return unique_violations

    def _merge_duplicate_violations(self, existing: Dict[str, Any], duplicate: Dict[str, Any]) -> Dict[str, Any]:
        """Merge duplicate violations with safety checks"""
        # SAFETY CHECKS
        if not isinstance(existing, dict) or not isinstance(duplicate, dict):
            return existing if isinstance(existing, dict) else duplicate
            
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        existing_sev = severity_order.get(existing.get('severity', 'medium'), 2)
        dup_sev = severity_order.get(duplicate.get('severity', 'medium'), 2)
        
        base_violation = duplicate.copy() if dup_sev > existing_sev else existing.copy()
        other_violation = existing if dup_sev > existing_sev else duplicate

        # Merge audit sources
        base_source = base_violation.get('_audit_source')
        other_source = other_violation.get('_audit_source')
        
        # Handle different source types safely
        base_sources = [base_source] if not isinstance(base_source, list) else base_source
        other_sources = [other_source] if not isinstance(other_source, list) else other_source
        
        # Filter out None values and merge
        all_sources = [s for s in base_sources + other_sources if s is not None]
        base_violation['_audit_source'] = list(set(all_sources))

        # Merge explanations (keep longer one)
        if len(other_violation.get('explanation', '')) > len(base_violation.get('explanation', '')) * 1.5:
            base_violation['explanation'] = other_violation['explanation']
            
        # Merge suggested rewrites
        if not base_violation.get('suggested_rewrite') and other_violation.get('suggested_rewrite'):
            base_violation['suggested_rewrite'] = other_violation['suggested_rewrite']

        return base_violation

    def _convert_to_clean_markdown(self, ai_response: list) -> str:
        """Convert AI response to clean markdown with safety checks"""
        try:
            if not isinstance(ai_response, list):
                return "❌ **Error**: Invalid AI response format"
            
            report_parts = []
            from datetime import datetime
            report_parts.append(f"""# YMYL Compliance Multi-Audit Report
**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Analysis Type:** 5 Parallel AI Audits + Deduplication
---
""")
            
            sections_with_violations = 0
            total_violations = 0
            
            for section in ai_response:
                try:
                    chunk_index = section.get('big_chunk_index', 'Unknown')
                    content_name = section.get('content_name', f'Section {chunk_index}')
                    violations = section.get('violations', [])
                    
                    if violations == "no violation found" or not violations:
                        report_parts.append(f"## {content_name}\n\n✅ **No violations found in this section.**\n\n")
                        continue
                    
                    report_parts.append(f"## {content_name}\n\n")
                    sections_with_violations += 1
                    
                    # Process violations with safety checks
                    if isinstance(violations, list):
                        for i, violation in enumerate(violations, 1):
                            if not isinstance(violation, dict):
                                safe_log(f"Skipping non-dict violation in markdown: {repr(violation)}")
                                continue
                                
                            total_violations += 1
                            
                            severity_emoji = {
                                "critical": "🔴",
                                "high": "🟠",
                                "medium": "🟡",
                                "low": "🔵"
                            }.get(violation.get("severity", "medium"), "🟡")
                            
                            violation_lines = [
                                f"**{severity_emoji} Violation {i}**",
                                f"- **Issue:** {violation.get('violation_type', 'Unknown violation')}",
                                f"- **Problematic Text:** \"{violation.get('problematic_text', 'N/A')}\"",
                            ]
                            
                            if violation.get('translation'):
                                translation = violation.get('translation', '').strip()
                                if translation:
                                    violation_lines.append(f"- **Translation:** \"{translation}\"")
                            
                            violation_lines.extend([
                                f"- **Explanation:** {violation.get('explanation', 'No explanation provided')}",
                                f"- **Guideline Reference:** Section {violation.get('guideline_section', 'N/A')} (Page {violation.get('page_number', 'N/A')})",
                                f"- **Severity:** {violation.get('severity', 'medium').title()}",
                                f"- **Suggested Fix:** \"{violation.get('suggested_rewrite', 'No suggestion provided')}\""
                            ])
                            
                            if violation.get('rewrite_translation'):
                                rewrite_translation = violation.get('rewrite_translation', '').strip()
                                if rewrite_translation:
                                    violation_lines.append(f"- **Suggested Fix (Translation):** \"{rewrite_translation}\"")
                            
                            violation_text = "\n".join(violation_lines) + "\n\n"
                            report_parts.append(violation_text)
                    
                    report_parts.append("\n")
                    
                except Exception as e:
                    safe_log(f"Error processing section: {e}")
                    continue
            
            if sections_with_violations == 0:
                report_parts.append("✅ **No violations found across all content sections.**\n\n")
            
            report_parts.append(f"""## 📈 Multi-Audit Analysis Summary
**Sections with Violations:** {sections_with_violations}
**Total Violations:** {total_violations}
**Analysis Method:** 5 Parallel AI Audits + Smart Deduplication
""")
            
            return ''.join(report_parts)
            
        except Exception as e:
            safe_log(f"Error converting to markdown: {e}")
            return f"❌ **Error**: {str(e)}"

    def _create_individual_report(self, audit_result: Dict[str, Any], audit_number: int) -> str:
        """Create individual report with safety checks (for debug mode)"""
        try:
            ai_response = audit_result.get('ai_response', [])
            processing_time = audit_result.get('processing_time', 0)
            
            report_parts = []
            from datetime import datetime
            report_parts.append(f"""# Individual Audit #{audit_number} Report
**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Processing Time:** {processing_time:.2f} seconds
**Thread ID:** {audit_result.get('thread_id', 'N/A')}
---
""")
            
            total_violations = 0
            for section in ai_response:
                try:
                    content_name = section.get('content_name', f'Section {section.get("big_chunk_index", "Unknown")}')
                    violations = section.get('violations', [])
                    
                    if violations == "no violation found" or not violations:
                        report_parts.append(f"## {content_name}\n\n✅ **No violations found in this section.**\n\n")
                        continue
                    
                    report_parts.append(f"## {content_name}\n\n")
                    
                    if isinstance(violations, list):
                        for i, violation in enumerate(violations, 1):
                            if not isinstance(violation, dict):
                                continue
                                
                            total_violations += 1
                            
                            severity_emoji = {
                                "critical": "🔴",
                                "high": "🟠", 
                                "medium": "🟡",
                                "low": "🔵"
                            }.get(violation.get("severity", "medium"), "🟡")
                            
                            violation_lines = [
                                f"**{severity_emoji} Violation {i}**",
                                f"- **Issue:** {violation.get('violation_type', 'Unknown violation')}",
                                f"- **Problematic Text:** \"{violation.get('problematic_text', 'N/A')}\"",
                                f"- **Explanation:** {violation.get('explanation', 'No explanation provided')}",
                                f"- **Severity:** {violation.get('severity', 'medium').title()}",
                                f"- **Suggested Fix:** \"{violation.get('suggested_rewrite', 'No suggestion provided')}\""
                            ]
                            
                            violation_text = "\n".join(violation_lines) + "\n\n"
                            report_parts.append(violation_text)
                            
                except Exception as e:
                    safe_log(f"Error in individual report: {e}")
                    continue
            
            report_parts.append(f"""## 📈 Audit #{audit_number} Summary
**Total Violations Found:** {total_violations}
**Processing Time:** {processing_time:.2f} seconds
**Status:** Completed Successfully
""")
            
            return ''.join(report_parts)
            
        except Exception as e:
            safe_log(f"Error creating individual report: {e}")
            return f"❌ **Error**: {str(e)}"

    async def _process_with_assistant(self, content: str, assistant_id: str, audit_number: int) -> Dict[str, Any]:
        """Process content using OpenAI Assistant API with enhanced logging"""
        try:
            # Better logging for deduplicator vs regular audits
            if audit_number == 99:
                safe_log("Starting DEDUPLICATION ASSISTANT processing...")
            else:
                safe_log(f"Starting audit #{audit_number}")
            
            thread = self.client.beta.threads.create()
            thread_id = thread.id
            self.client.beta.threads.messages.create(thread_id=thread_id, role="user", content=content)
            run = self.client.beta.threads.runs.create(thread_id=thread_id, assistant_id=assistant_id)
            run_id = run.id
            start_time = time.time()
            
            # Progress logging for deduplicator (since it takes longer)
            last_log_time = start_time
            
            while run.status in ['queued', 'in_progress']:
                current_time = time.time()
                
                # Log progress every 15 seconds for deduplicator
                if audit_number == 99 and (current_time - last_log_time) > 15:
                    elapsed = current_time - start_time
                    safe_log(f"DEDUPLICATOR still processing... ({elapsed:.0f}s elapsed, status: {run.status})")
                    last_log_time = current_time
                
                if current_time - start_time > self.timeout:
                    if audit_number == 99:
                        error_msg = f"DEDUPLICATOR timeout after {self.timeout} seconds"
                    else:
                        error_msg = f"Audit #{audit_number} timeout after {self.timeout} seconds"
                    safe_log(error_msg)
                    return {'success': False, 'error': error_msg}
                    
                await asyncio.sleep(2)
                run = self.client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)
            
            processing_time = time.time() - start_time
            
            if audit_number == 99:
                safe_log(f"DEDUPLICATION ASSISTANT completed in {processing_time:.2f} seconds with status: {run.status}")
            else:
                safe_log(f"Audit #{audit_number} completed in {processing_time:.2f} seconds with status: {run.status}")
            
            if run.status == 'completed':
                return await self._extract_response(thread_id, processing_time, audit_number)
            elif run.status == 'failed':
                if audit_number == 99:
                    error_msg = f"DEDUPLICATION ASSISTANT failed: {getattr(run, 'last_error', 'Unknown error')}"
                else:
                    error_msg = f"Audit #{audit_number} failed: {getattr(run, 'last_error', 'Unknown error')}"
                safe_log(error_msg)
                return {'success': False, 'error': error_msg}
            else:
                if audit_number == 99:
                    error_msg = f"DEDUPLICATION ASSISTANT unexpected status: {run.status}"
                else:
                    error_msg = f"Audit #{audit_number} unexpected status: {run.status}"
                safe_log(error_msg)
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            if audit_number == 99:
                error_msg = f"DEDUPLICATION ASSISTANT API error: {str(e)}"
            else:
                error_msg = f"Audit #{audit_number} API error: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    async def _extract_response(self, thread_id: str, processing_time: float, audit_number: int) -> Dict[str, Any]:
        """Extract response from assistant with enhanced logging"""
        try:
            messages = self.client.beta.threads.messages.list(thread_id=thread_id)
            if not messages.data:
                if audit_number == 99:
                    return {'success': False, 'error': 'DEDUPLICATION ASSISTANT: No response'}
                else:
                    return {'success': False, 'error': f'Audit #{audit_number}: No response'}
            
            assistant_message = messages.data[0]
            if not assistant_message.content:
                if audit_number == 99:
                    return {'success': False, 'error': 'DEDUPLICATION ASSISTANT: Empty response'}
                else:
                    return {'success': False, 'error': f'Audit #{audit_number}: Empty response'}
            
            response_content = assistant_message.content[0].text.value
            if not response_content or not response_content.strip():
                if audit_number == 99:
                    return {'success': False, 'error': 'DEDUPLICATION ASSISTANT: Empty content'}
                else:
                    return {'success': False, 'error': f'Audit #{audit_number}: Empty content'}
            
            ai_data = self._parse_ai_response(response_content, audit_number)
            if ai_data is None:
                if audit_number == 99:
                    return {'success': False, 'error': 'DEDUPLICATION ASSISTANT: Could not parse response'}
                else:
                    return {'success': False, 'error': f'Audit #{audit_number}: Could not parse response'}
            
            return {
                'success': True,
                'ai_response': ai_data,
                'processing_time': processing_time,
                'response_length': len(response_content),
                'thread_id': thread_id,
                'audit_number': audit_number,
                'raw_response': response_content
            }
            
        except Exception as e:
            safe_log(f"Extract error: {str(e)}")
            return {'success': False, 'error': str(e)}

    def _parse_ai_response(self, response_content: str, audit_number: int) -> Optional[list]:
        """Parse AI response with multiple strategies"""
        import re
        
        # Strategy 1: Direct JSON parsing
        try:
            ai_data = json.loads(response_content.strip())
            if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                return ai_data
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON array
        json_pattern = r'\[[\s\S]*?\]'
        for match in re.findall(json_pattern, response_content):
            try:
                ai_data = json.loads(match)
                if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                    return ai_data
            except json.JSONDecodeError:
                continue
        
        # Strategy 3: Extract from code blocks
        code_block_pattern = r'```(?:json)?\s*(\[[\s\S]*?\])\s*```'
        for match in re.findall(code_block_pattern, response_content):
            try:
                ai_data = json.loads(match)
                if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                    return ai_data
            except json.JSONDecodeError:
                continue
        
        return None

    def _validate_response_structure(self, ai_data: list) -> bool:
        """Validate response structure"""
        if not isinstance(ai_data, list) or len(ai_data) == 0:
            return False
        
        sample_size = min(3, len(ai_data))
        valid_items = 0
        
        for item in ai_data[:sample_size]:
            if self._validate_single_item(item):
                valid_items += 1
        
        return valid_items >= sample_size * 0.5

    def _validate_single_item(self, item: dict) -> bool:
        """Validate single item structure"""
        if not isinstance(item, dict):
            return False
        
        required_keys = {'big_chunk_index', 'content_name', 'violations'}
        if not required_keys.issubset(set(item.keys())):
            return False
        
        if not isinstance(item.get('big_chunk_index'), int):
            return False
        
        if not isinstance(item.get('content_name'), str):
            return False
        
        violations = item.get('violations')
        if not (violations == "no violation found" or isinstance(violations, list)):
            return False
        
        return True


# Convenience function for external use (maintains backward compatibility)
async def analyze_content(json_content: str, casino_mode: bool = False, debug_mode: bool = False) -> Dict[str, Any]:
    """
    Analyze content for YMYL compliance using 5 parallel audits
    
    Args:
        json_content: Structured JSON content to analyze
        casino_mode: Whether to use casino-specific analysis
        debug_mode: Whether to return individual audit reports (admin feature)
        
    Returns:
        Dictionary with analysis results (+ debug info if debug_mode=True)
    """
    analyzer = YMYLAnalyzer()
    return await analyzer.analyze_content(json_content, casino_mode, debug_mode)