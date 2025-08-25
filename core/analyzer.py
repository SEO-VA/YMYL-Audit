#!/usr/bin/env python3
"""
AI Analysis module for YMYL Audit Tool
Handles OpenAI Assistant API calls for YMYL compliance analysis
"""

import asyncio
import time
import json
from typing import Dict, Any, Optional
from openai import OpenAI
from config.settings import get_ai_settings
from utils.helpers import safe_log

class YMYLAnalyzer:
    """Handles AI analysis using OpenAI Assistant API"""
    
    def __init__(self):
        """Initialize the analyzer"""
        self.settings = get_ai_settings()
        self.client = OpenAI(api_key=self.settings['api_key'])
        self.timeout = self.settings['timeout']

    async def analyze_content(self, json_content: str, casino_mode: bool = False) -> Dict[str, Any]:
        """
        Analyze content for YMYL compliance
        
        Args:
            json_content: Structured JSON content to analyze
            casino_mode: Whether to use casino-specific analysis
            
        Returns:
            Dictionary with analysis results
        """
        try:
            safe_log(f"Starting AI analysis (casino_mode: {casino_mode})")
            
            # Select appropriate assistant
            assistant_id = (self.settings['casino_assistant_id'] if casino_mode 
                          else self.settings['regular_assistant_id'])
            
            safe_log(f"Using assistant: {assistant_id}")
            
            # Validate content size
            content_size = len(json_content)
            max_size = self.settings['max_content_size']
            
            if content_size > max_size:
                return {
                    'success': False,
                    'error': f'Content too large: {content_size:,} chars (max: {max_size:,})'
                }
            
            # Process with Assistant API
            return await self._process_with_assistant(json_content, assistant_id)
            
        except Exception as e:
            error_msg = f"AI analysis error: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    async def _process_with_assistant(self, content: str, assistant_id: str) -> Dict[str, Any]:
        """Process content using OpenAI Assistant API"""
        try:
            # Create thread
            thread = self.client.beta.threads.create()
            thread_id = thread.id
            safe_log(f"Created thread: {thread_id}")
            
            # Add message
            self.client.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=content
            )
            safe_log(f"Added content to thread ({len(content):,} characters)")
            
            # Create and run assistant
            run = self.client.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=assistant_id
            )
            run_id = run.id
            safe_log(f"Started run: {run_id}")
            
            # Poll for completion
            start_time = time.time()
            
            while run.status in ['queued', 'in_progress']:
                if time.time() - start_time > self.timeout:
                    error_msg = f"Analysis timeout after {self.timeout} seconds"
                    safe_log(error_msg)
                    return {'success': False, 'error': error_msg}
                
                await asyncio.sleep(2)  # Poll every 2 seconds
                run = self.client.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run_id
                )
            
            processing_time = time.time() - start_time
            safe_log(f"Analysis completed in {processing_time:.2f} seconds with status: {run.status}")
            
            # Handle completion
            if run.status == 'completed':
                return await self._extract_response(thread_id, processing_time)
            elif run.status == 'failed':
                error_msg = f"Assistant run failed: {getattr(run, 'last_error', 'Unknown error')}"
                safe_log(error_msg)
                return {'success': False, 'error': error_msg}
            else:
                error_msg = f"Unexpected run status: {run.status}"
                safe_log(error_msg)
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            error_msg = f"Assistant API error: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    async def _extract_response(self, thread_id: str, processing_time: float) -> Dict[str, Any]:
        """Extract and process AI response"""
        try:
            # Get messages
            messages = self.client.beta.threads.messages.list(thread_id=thread_id)
            
            if not messages.data:
                return {'success': False, 'error': 'No response from assistant'}
            
            # Get assistant's response
            assistant_message = messages.data[0]
            
            if not assistant_message.content:
                return {'success': False, 'error': 'Empty response from assistant'}
            
            # Extract text content
            response_content = assistant_message.content[0].text.value
            
            if not response_content or not response_content.strip():
                return {'success': False, 'error': 'Assistant returned empty content'}
            
            safe_log(f"Raw AI response length: {len(response_content)}")
            
            # Parse AI response
            ai_data = self._parse_ai_response(response_content)
            
            if ai_data is None:
                return {
                    'success': False,
                    'error': f'Could not parse AI response. Preview: {response_content[:200]}...'
                }
            
            # Convert to markdown report
            markdown_report = self._convert_to_markdown(ai_data)
            
            safe_log(f"Successfully processed AI response")
            
            return {
                'success': True,
                'report': markdown_report,
                'ai_response': ai_data,
                'processing_time': processing_time,
                'response_length': len(response_content),
                'thread_id': thread_id
            }
            
        except Exception as e:
            error_msg = f"Error extracting response: {str(e)}"
            safe_log(error_msg)
            return {'success': False, 'error': error_msg}

    def _parse_ai_response(self, response_content: str) -> Optional[list]:
        """Parse JSON from AI response with multiple strategies"""
        import re
        
        # Strategy 1: Direct JSON parsing
        try:
            ai_data = json.loads(response_content.strip())
            if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                safe_log("Successfully parsed as direct JSON array")
                return ai_data
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON array from text
        json_pattern = r'\[[\s\S]*?\]'
        json_matches = re.findall(json_pattern, response_content)
        
        for match in json_matches:
            try:
                ai_data = json.loads(match)
                if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                    safe_log("Successfully extracted JSON array from text")
                    return ai_data
            except json.JSONDecodeError:
                continue
        
        # Strategy 3: Extract from code blocks
        code_block_pattern = r'```(?:json)?\s*(\[[\s\S]*?\])\s*```'
        code_matches = re.findall(code_block_pattern, response_content)
        
        for match in code_matches:
            try:
                ai_data = json.loads(match)
                if isinstance(ai_data, list) and self._validate_response_structure(ai_data):
                    safe_log("Successfully extracted JSON array from code block")
                    return ai_data
            except json.JSONDecodeError:
                continue
        
        safe_log("All JSON extraction strategies failed")
        return None

    def _validate_response_structure(self, ai_data: list) -> bool:
        """Validate AI response structure"""
        if not isinstance(ai_data, list) or len(ai_data) == 0:
            return False
        
        # Check sample items for required structure
        sample_size = min(3, len(ai_data))
        valid_items = 0
        
        for item in ai_data[:sample_size]:
            if self._validate_single_item(item):
                valid_items += 1
        
        return valid_items >= sample_size * 0.5

    def _validate_single_item(self, item: dict) -> bool:
        """Validate a single item structure"""
        if not isinstance(item, dict):
            return False
        
        required_keys = {'big_chunk_index', 'content_name', 'violations'}
        item_keys = set(item.keys())
        
        # Check required keys
        if not required_keys.issubset(item_keys):
            return False
        
        # Validate types
        if not isinstance(item.get('big_chunk_index'), int):
            return False
        
        if not isinstance(item.get('content_name'), str):
            return False
        
        violations = item.get('violations')
        if not (violations == "no violation found" or isinstance(violations, list)):
            return False
        
        return True

    def _convert_to_markdown(self, ai_response: list) -> str:
        """Convert AI response to markdown report, including translation fields but excluding chunk_language"""
        try:
            if not isinstance(ai_response, list):
                return "❌ **Error**: Invalid AI response format"
            
            report_parts = []
            
            # Add header
            from datetime import datetime
            report_parts.append(f"""# YMYL Compliance Audit Report

**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Analysis Type:** AI Assistant Analysis

---

""")
            
            # Process sections
            sections_with_violations = 0
            total_violations = 0
            
            for section in ai_response:
                try:
                    chunk_index = section.get('big_chunk_index', 'Unknown')
                    content_name = section.get('content_name', f'Section {chunk_index}')
                    violations = section.get('violations', [])
                    
                    # Handle no violations
                    if violations == "no violation found" or not violations:
                        report_parts.append(f"## {content_name}\n\n✅ **No violations found in this section.**\n\n")
                        continue
                    
                    # Section with violations
                    report_parts.append(f"## {content_name}\n\n")
                    sections_with_violations += 1
                    
                    # Process violations
                    for i, violation in enumerate(violations, 1):
                        total_violations += 1
                        
                        severity_emoji = {
                            "critical": "🔴",
                            "high": "🟠",
                            "medium": "🟡",
                            "low": "🔵"
                        }.get(violation.get("severity", "medium"), "🟡")
                        
                        # Get basic violation fields
                        violation_type = str(violation.get('violation_type', 'Unknown violation'))
                        problematic_text = str(violation.get('problematic_text', 'N/A'))
                        explanation = str(violation.get('explanation', 'No explanation provided'))
                        suggested_rewrite = str(violation.get('suggested_rewrite', 'No suggestion provided'))
                        
                        # Build violation text - start with core fields
                        violation_lines = [
                            f"**{severity_emoji} Violation {i}**",
                            f"- **Issue:** {violation_type}",
                            f"- **Problematic Text:** \"{problematic_text}\"",
                        ]
                        
                        # Add translation of problematic text if available
                        if violation.get('translation'):
                            translation = str(violation.get('translation', ''))
                            if translation and translation.strip():
                                violation_lines.append(f"- **Translation:** \"{translation}\"")
                        
                        # Continue with standard fields
                        violation_lines.extend([
                            f"- **Explanation:** {explanation}",
                            f"- **Guideline Reference:** Section {violation.get('guideline_section', 'N/A')} (Page {violation.get('page_number', 'N/A')})",
                            f"- **Severity:** {violation.get('severity', 'medium').title()}",
                            f"- **Suggested Fix:** \"{suggested_rewrite}\""
                        ])
                        
                        # Add translation of suggested fix if available
                        if violation.get('rewrite_translation'):
                            rewrite_translation = str(violation.get('rewrite_translation', ''))
                            if rewrite_translation and rewrite_translation.strip():
                                violation_lines.append(f"- **Suggested Fix (Translation):** \"{rewrite_translation}\"")
                        
                        # Note: chunk_language field is intentionally excluded from the report
                        
                        # Join all violation lines and add to report
                        violation_text = "\n".join(violation_lines) + "\n\n"
                        report_parts.append(violation_text)
                    
                    report_parts.append("\n")
                    
                except Exception as e:
                    safe_log(f"Error processing section {section.get('big_chunk_index', 'Unknown')}: {e}")
                    continue
            
            # Add summary
            if sections_with_violations == 0:
                report_parts.append("✅ **No violations found across all content sections.**\n\n")
            
            report_parts.append(f"""## 📈 Analysis Summary

**Sections with Violations:** {sections_with_violations}
**Total Violations:** {total_violations}
**Analysis Method:** OpenAI Assistant API

""")
            
            return ''.join(report_parts)
            
        except Exception as e:
            safe_log(f"Error converting AI response to markdown: {e}")
            return f"❌ **Error**: Failed to process AI response - {str(e)}"


# Convenience function for external use
async def analyze_content(json_content: str, casino_mode: bool = False) -> Dict[str, Any]:
    """
    Analyze content for YMYL compliance
    
    Args:
        json_content: Structured JSON content to analyze
        casino_mode: Whether to use casino-specific analysis
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = YMYLAnalyzer()
    return await analyzer.analyze_content(json_content, casino_mode)