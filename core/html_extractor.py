#!/usr/bin/env python3
"""
HTML Content Extractor for YMYL Audit Tool - FULLY REFACTORED VERSION
Implements all fixes from the comprehensive plan to eliminate duplicates and improve structure
"""

import json
import re
from bs4 import BeautifulSoup
from typing import Tuple, Optional, List, Dict, Set
from utils.helpers import safe_log

class HTMLContentExtractor:
    """Extracts structured content directly from HTML strings with comprehensive fixes"""
    
    def __init__(self):
        """Initialize HTML extractor"""
        self.processed_elements: Set[str] = set()  # Content-based hashing
        self.current_h2_section = None
        self.big_chunks = []
        safe_log("HTMLContentExtractor initialized with comprehensive fixes")
    
    def extract_content(self, html_content: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Extract structured content from HTML string with all fixes applied
        
        Args:
            html_content: HTML content as string
            
        Returns:
            tuple: (success, organized_json_content, error_message)
        """
        try:
            safe_log(f"Starting comprehensive HTML content extraction ({len(html_content):,} characters)")
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Preprocessing: Remove noise elements
            self._preprocess_soup(soup)
            
            # Reset state
            self.processed_elements.clear()
            self.big_chunks = []
            self.current_h2_section = None
            
            # Extract content using direct chunking approach
            self._extract_with_direct_chunking(soup)
            
            # Create final JSON structure
            organized_content = self._create_final_json()
            
            safe_log(f"HTML extraction successful: {len(organized_content):,} characters, {len(self.big_chunks)} chunks")
            return True, organized_content, None
            
        except Exception as e:
            error_msg = f"HTML parsing error: {str(e)}"
            safe_log(error_msg)
            return False, None, error_msg
    
    def _preprocess_soup(self, soup: BeautifulSoup):
        """Remove noise elements before extraction"""
        for tag in soup(['script', 'style', 'nav', 'footer', 'aside', 'header']):
            tag.decompose()
        
        # Remove comments
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment.extract()
    
    def _get_element_id(self, element) -> str:
        """Create content-based hash for reliable deduplication"""
        if element is None:
            return ""
        
        text_content = element.get_text()[:100].strip()
        children_count = len(list(element.children))
        return f"{element.name}:{hash((text_content, children_count))}"
    
    def _is_already_processed(self, element) -> bool:
        """Check if element was already processed"""
        element_id = self._get_element_id(element)
        return element_id in self.processed_elements
    
    def _mark_as_processed(self, element):
        """Mark element as processed"""
        element_id = self._get_element_id(element)
        self.processed_elements.add(element_id)
    
    def _is_inside_processed_container(self, element) -> bool:
        """Check if element is inside an already processed container"""
        parent_containers = ['table', 'ul', 'ol', 'dl']
        for container in parent_containers:
            if element.find_parent(container):
                parent = element.find_parent(container)
                if self._is_already_processed(parent):
                    return True
        return False
    
    def _extract_with_direct_chunking(self, soup: BeautifulSoup):
        """Extract content and organize into chunks directly"""
        
        # Create pre-H2 chunk for content before first H2
        pre_h2_content = []
        current_chunk_content = []
        chunk_index = 1
        
        # Find main content area
        main_area = soup.find('article') or soup.find('main') or soup.find('body') or soup
        
        # Process all elements in document order
        for element in main_area.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'table', 'ul', 'ol', 'dl', 'section', 'div']):
            
            # Skip if already processed or inside processed container
            if self._is_already_processed(element) or self._is_inside_processed_container(element):
                continue
            
            formatted_content = self._format_element_comprehensive(element)
            
            if not formatted_content:
                continue
            
            # Handle H2 sections
            if formatted_content.startswith('H2:'):
                # Save previous chunk
                if current_chunk_content:
                    self.big_chunks.append({
                        "big_chunk_index": chunk_index,
                        "small_chunks": current_chunk_content.copy()
                    })
                    chunk_index += 1
                elif pre_h2_content:
                    # Save pre-H2 content as first chunk
                    self.big_chunks.append({
                        "big_chunk_index": chunk_index,
                        "small_chunks": pre_h2_content.copy()
                    })
                    chunk_index += 1
                
                # Start new H2 section
                current_chunk_content = [formatted_content]
                self.current_h2_section = formatted_content
                
            else:
                # Add to appropriate section
                if self.current_h2_section is None:
                    pre_h2_content.append(formatted_content)
                else:
                    current_chunk_content.append(formatted_content)
        
        # Add final chunk
        if current_chunk_content:
            self.big_chunks.append({
                "big_chunk_index": chunk_index,
                "small_chunks": current_chunk_content
            })
        elif pre_h2_content:
            self.big_chunks.append({
                "big_chunk_index": 1,
                "small_chunks": pre_h2_content
            })
        
        # Handle special sections (FAQ, Author)
        self._extract_special_sections(soup)
    
    def _format_element_comprehensive(self, element) -> Optional[str]:
        """Format element with comprehensive fixes"""
        
        if self._is_already_processed(element):
            return None
        
        tag_name = element.name.lower()
        
        # Detect and handle warning blocks first
        if self._is_warning_block(element):
            return self._format_warning_block(element)
        
        # Handle headings
        if tag_name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            return self._format_heading(element)
        
        # Handle tables
        elif tag_name == 'table':
            return self._format_table_comprehensive(element)
        
        # Handle lists
        elif tag_name in ['ul', 'ol']:
            return self._format_list_comprehensive(element)
        
        # Handle definition lists
        elif tag_name == 'dl':
            return self._format_definition_list_comprehensive(element)
        
        # Handle paragraphs
        elif tag_name == 'p':
            return self._format_paragraph(element)
        
        # Handle divs that might contain structured content
        elif tag_name in ['div', 'section']:
            return self._format_container(element)
        
        return None
    
    def _is_warning_block(self, element) -> bool:
        """Detect warning blocks by content and structure"""
        text = element.get_text().strip()
        
        # Check for warning patterns
        warning_patterns = [
            r'⚠️.*WARNING.*⚠️',
            r'ADDICTION RISK WARNING',
            r'BONUS RISK WARNING', 
            r'FINANCIAL RISK WARNING',
        ]
        
        for pattern in warning_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        # Check CSS classes
        classes = element.get('class', [])
        warning_classes = ['warning', 'risk-alert', 'disclaimer', 'alert']
        if any(cls in classes for cls in warning_classes):
            return True
        
        return False
    
    def _format_warning_block(self, element) -> str:
        """Format warning blocks as single WARNING entry"""
        self._mark_as_processed(element)
        
        # Mark all children as processed to prevent duplicate extraction
        for child in element.find_all():
            self._mark_as_processed(child)
        
        text = self._clean_text_preserve_structure(element.get_text())
        
        # Extract warning type
        if '⚠️' in text and 'WARNING' in text:
            warning_match = re.search(r'⚠️[^⚠️]*WARNING[^⚠️]*⚠️', text)
            if warning_match:
                warning_type = warning_match.group()
                remaining_text = text.replace(warning_match.group(), '').strip()
                return f"WARNING: {warning_type} // {remaining_text}"
        
        return f"WARNING: {text}"
    
    def _format_heading(self, element) -> str:
        """Format headings with duplicate prefix fix"""
        self._mark_as_processed(element)
        
        tag_name = element.name.upper()
        text = self._clean_text_preserve_structure(element.get_text())
        
        # Fix double prefix issue
        if text.startswith(f"{tag_name}:"):
            text = text[len(tag_name)+1:].strip()
        
        return f"{tag_name}: {text}"
    
    def _format_table_comprehensive(self, element) -> str:
        """Format tables comprehensively to prevent content leakage"""
        self._mark_as_processed(element)
        
        # Mark ALL table children as processed to prevent downstream extraction
        for child in element.find_all():
            self._mark_as_processed(child)
        
        rows = []
        headers = []
        
        # Get headers
        header_row = element.find('tr')
        if header_row and header_row.find('th'):
            headers = [self._clean_text_preserve_structure(th.get_text()) 
                      for th in header_row.find_all('th')]
        
        # Process data rows
        data_rows = element.find_all('tr')
        start_idx = 1 if headers else 0
        
        for tr in data_rows[start_idx:]:
            cells = [self._clean_text_preserve_structure(td.get_text()) 
                    for td in tr.find_all(['td', 'th'])]
            
            if cells and any(cell.strip() for cell in cells):
                if headers and len(cells) == len(headers):
                    # Pair headers with values
                    paired = [f"{h}: {v}" for h, v in zip(headers, cells) if v.strip()]
                    if paired:
                        rows.append(" | ".join(paired))
                else:
                    # No headers, just join cells
                    non_empty_cells = [cell for cell in cells if cell.strip()]
                    if non_empty_cells:
                        rows.append(" | ".join(non_empty_cells))
        
        if rows:
            return f"TABLE: {' // '.join(rows)}"
        return None
    
    def _format_list_comprehensive(self, element) -> str:
        """Format lists with comprehensive child processing"""
        self._mark_as_processed(element)
        
        # Mark all list children as processed
        for child in element.find_all():
            self._mark_as_processed(child)
        
        items = []
        list_type = "ORDERED" if element.name == 'ol' else "UNORDERED"
        
        for li in element.find_all('li', recursive=False):
            text = self._clean_text_preserve_structure(li.get_text())
            if text:
                items.append(text)
        
        if items:
            return f"{list_type}_LIST: {' // '.join(items)}"
        return None
    
    def _format_definition_list_comprehensive(self, element) -> str:
        """Format definition lists as FAQ or structured content"""
        self._mark_as_processed(element)
        
        # Mark all children as processed
        for child in element.find_all():
            self._mark_as_processed(child)
        
        definitions = []
        current_term = None
        
        for elem in element.find_all(['dt', 'dd']):
            if elem.name == 'dt':
                current_term = self._clean_text_preserve_structure(elem.get_text())
            elif elem.name == 'dd' and current_term:
                definition = self._clean_text_preserve_structure(elem.get_text())
                if definition:
                    definitions.append(f"{current_term}: {definition}")
                current_term = None
        
        if definitions:
            # Check if this looks like FAQ
            if any('?' in defn for defn in definitions):
                return f"FAQ: {' // '.join(definitions)}"
            else:
                return f"DEFINITION_LIST: {' // '.join(definitions)}"
        return None
    
    def _format_paragraph(self, element) -> Optional[str]:
        """Format paragraphs with container awareness"""
        
        # Skip if inside processed containers
        if self._is_inside_processed_container(element):
            return None
        
        self._mark_as_processed(element)
        
        text = self._clean_text_preserve_structure(element.get_text())
        if not text:
            return None
        
        # Check for special paragraph types
        classes = element.get('class', [])
        if 'lead' in classes:
            return f"LEAD: {text}"
        
        return f"CONTENT: {text}"
    
    def _format_container(self, element) -> Optional[str]:
        """Format div/section containers if they contain unique content"""
        
        # Skip if inside processed containers or already processed
        if self._is_inside_processed_container(element) or self._is_already_processed(element):
            return None
        
        # Only process containers with specific semantic meaning
        classes = element.get('class', [])
        data_qa = element.get('data-qa', '')
        
        if 'faq' in classes or 'templateFAQ' in data_qa:
            self._mark_as_processed(element)
            for child in element.find_all():
                self._mark_as_processed(child)
            
            text = self._clean_text_preserve_structure(element.get_text())
            return f"FAQ: {text}"
        
        return None
    
    def _clean_text_preserve_structure(self, text: str) -> str:
        """Clean text while preserving meaningful structure"""
        if not text:
            return ""
        
        # Fix line break artifacts but preserve meaningful breaks
        text = re.sub(r'\n+', ' ', text)  # Replace newlines with spaces
        text = re.sub(r'\s+', ' ', text)  # Collapse multiple spaces
        text = text.strip()
        
        return text
    
    def _extract_special_sections(self, soup: BeautifulSoup):
        """Extract special sections like FAQ and Author info"""
        
        # Extract FAQ section
        faq_section = soup.find('section', attrs={'data-qa': 'templateFAQ'})
        if faq_section and not self._is_already_processed(faq_section):
            self._mark_as_processed(faq_section)
            text = self._clean_text_preserve_structure(faq_section.get_text())
            if text and self.big_chunks:
                # Add to last chunk or create new one
                self.big_chunks[-1]["small_chunks"].append(f"FAQ: {text}")
        
        # Extract author section
        author_section = soup.find('section', attrs={'data-qa': 'templateAuthorCard'})
        if author_section and not self._is_already_processed(author_section):
            self._mark_as_processed(author_section)
            text = self._clean_text_preserve_structure(author_section.get_text())
            if text and self.big_chunks:
                self.big_chunks[-1]["small_chunks"].append(f"AUTHOR: {text}")
    
    def _create_final_json(self) -> str:
        """Create final JSON structure"""
        
        # Ensure we have at least one chunk
        if not self.big_chunks:
            self.big_chunks = [{
                "big_chunk_index": 1,
                "small_chunks": ["CONTENT: No content extracted"]
            }]
        
        # Final deduplication pass
        for chunk in self.big_chunks:
            chunk["small_chunks"] = self._deduplicate_content(chunk["small_chunks"])
        
        result = {
            "big_chunks": self.big_chunks
        }
        
        safe_log(f"Created final JSON with {len(self.big_chunks)} chunks")
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    def _deduplicate_content(self, content_list: List[str]) -> List[str]:
        """Final deduplication of content within a chunk"""
        seen = set()
        deduplicated = []
        
        for content in content_list:
            if not content or not content.strip():
                continue
            
            # Normalize for comparison
            normalized = content.strip().lower()
            
            # Skip exact duplicates
            if normalized not in seen:
                seen.add(normalized)
                deduplicated.append(content.strip())
        
        return deduplicated


# Convenience function for external use
def extract_html_content(html_content: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Convenience function for extracting content from HTML string
    
    Args:
        html_content: HTML content as string
        
    Returns:
        tuple: (success, organized_json_content, error_message)
    """
    extractor = HTMLContentExtractor()
    return extractor.extract_content(html_content)
