#!/usr/bin/env python3
"""
Content extraction module for YMYL Audit Tool
Extracts structured content from URLs and organizes into H2-based chunks
"""

import requests
from bs4 import BeautifulSoup
from typing import Tuple, Optional, List, Dict, Any
from config.settings import get_request_settings
from utils.helpers import safe_log

class ContentExtractor:
    """Extracts and structures content from web pages"""
    
    def __init__(self):
        """Initialize the content extractor"""
        settings = get_request_settings()
        self.timeout = settings['timeout']
        self.user_agent = settings['user_agent']
        self.max_content_length = settings['max_content_length']
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent
        })

    def extract_content(self, url: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Extract structured content from URL
        
        Args:
            url: URL to extract content from
            
        Returns:
            tuple: (success, content, error_message)
        """
        try:
            safe_log(f"Starting content extraction from: {url}")
            
            # Fetch page
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Check content length
            content_length = len(response.content)
            if content_length > self.max_content_length:
                error_msg = f"Content too large: {content_length:,} bytes (max: {self.max_content_length:,})"
                safe_log(error_msg)
                return False, None, error_msg
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract structured content
            content_parts = self._extract_structured_content(soup)
            
            # Organize into H2-based chunks
            organized_content = self._organize_by_h2(content_parts)
            
            safe_log(f"Content extraction successful: {len(organized_content):,} characters")
            return True, organized_content, None
            
        except requests.exceptions.Timeout:
            error_msg = f"Request timeout after {self.timeout} seconds"
            safe_log(error_msg)
            return False, None, error_msg
            
        except requests.exceptions.ConnectionError:
            error_msg = "Connection error - unable to reach website"
            safe_log(error_msg)
            return False, None, error_msg
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error: {e.response.status_code}"
            safe_log(error_msg)
            return False, None, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            safe_log(error_msg)
            return False, None, error_msg

    def _extract_structured_content(self, soup: BeautifulSoup) -> List[str]:
        """Extract structured content with semantic prefixes"""
        content_parts = []
        
        # Extract H1
        h1 = soup.find('h1')
        if h1:
            text = h1.get_text(separator='\n', strip=True)
            if text:
                content_parts.append(f"H1: {text}")
        
        # Extract subtitle
        subtitle = soup.find('span', class_=['sub-title', 'd-block'])
        if subtitle:
            text = subtitle.get_text(separator='\n', strip=True)
            if text:
                content_parts.append(f"SUBTITLE: {text}")
        
        # Extract lead paragraph
        lead = soup.find('p', class_='lead')
        if lead:
            text = lead.get_text(separator='\n', strip=True)
            if text:
                content_parts.append(f"LEAD: {text}")
        
        # Extract article content
        article = soup.find('article')
        if article:
            # Remove tab-content sections
            for tab_content in article.find_all('div', class_='tab-content'):
                tab_content.decompose()
            
            # Process elements in order
            for element in article.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'table', 'ul', 'ol', 'dl']):
                formatted_content = self._format_element(element)
                if formatted_content:
                    content_parts.append(formatted_content)
        
        # Extract FAQ section
        faq_section = soup.find('section', attrs={'data-qa': 'templateFAQ'})
        if faq_section:
            text = faq_section.get_text(separator='\n', strip=True)
            if text:
                content_parts.append(f"FAQ: {text}")
        
        # Extract author section
        author_section = soup.find('section', attrs={'data-qa': 'templateAuthorCard'})
        if author_section:
            text = author_section.get_text(separator='\n', strip=True)
            if text:
                content_parts.append(f"AUTHOR: {text}")
        
        # Filter empty parts
        content_parts = [part for part in content_parts if part and part.strip()]
        
        safe_log(f"Extracted {len(content_parts)} content elements")
        return content_parts

    def _format_element(self, element) -> Optional[str]:
        """Format individual HTML elements with appropriate prefixes"""
        tag_name = element.name.lower()
        text = element.get_text(separator='\n', strip=True)
        
        if not text:
            return None
        
        # Handle headings
        if tag_name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            return f"{tag_name.upper()}: {text}"
        
        # Handle paragraphs
        elif tag_name == 'p':
            element_classes = element.get('class', [])
            if 'lead' in element_classes:
                return f"LEAD: {text}"
            else:
                return f"CONTENT: {text}"
        
        # Handle tables
        elif tag_name == 'table':
            return self._format_table(element)
        
        # Handle lists
        elif tag_name in ['ul', 'ol']:
            return self._format_list(element)
        
        # Handle definition lists
        elif tag_name == 'dl':
            return self._format_definition_list(element)
        
        return None

    def _format_table(self, table) -> Optional[str]:
        """Format table with header-aware structure"""
        rows = []
        headers = []
        
        # Try to identify headers
        header_row = table.find('tr')
        if header_row and header_row.find('th'):
            headers = [th.get_text(strip=True) for th in header_row.find_all('th')]
        
        # Process data rows
        data_rows = table.find_all('tr')
        start_idx = 1 if headers else 0
        
        for tr in data_rows[start_idx:]:
            cells = [td.get_text(strip=True) for td in tr.find_all(['td', 'th'])]
            if cells and any(cell for cell in cells):
                if headers and len(cells) == len(headers):
                    paired = [f"{h}: {v}" for h, v in zip(headers, cells) if v.strip()]
                    if paired:
                        rows.append(" | ".join(paired))
                else:
                    non_empty_cells = [cell for cell in cells if cell.strip()]
                    if non_empty_cells:
                        rows.append(" | ".join(non_empty_cells))
        
        if rows:
            return f"TABLE: {' // '.join(rows)}"
        return None

    def _format_list(self, list_element) -> Optional[str]:
        """Format lists with type preservation"""
        items = []
        list_type = "ORDERED" if list_element.name == 'ol' else "UNORDERED"
        
        for li in list_element.find_all('li', recursive=False):
            text = li.get_text(separator=' ', strip=True)
            if text:
                items.append(text)
        
        if items:
            return f"{list_type}_LIST: {' // '.join(items)}"
        return None

    def _format_definition_list(self, dl_element) -> Optional[str]:
        """Format definition lists as term: definition pairs"""
        definitions = []
        current_term = None
        
        for element in dl_element.find_all(['dt', 'dd']):
            if element.name == 'dt':
                current_term = element.get_text(strip=True)
            elif element.name == 'dd' and current_term:
                definition = element.get_text(separator=' ', strip=True)
                if definition:
                    definitions.append(f"{current_term}: {definition}")
                current_term = None
        
        if definitions:
            return f"DEFINITION_LIST: {' // '.join(definitions)}"
        return None

    def _organize_by_h2(self, content_parts: List[str]) -> str:
        """
        Organize content into H2-based chunks for AI processing
        
        Args:
            content_parts: List of structured content strings
            
        Returns:
            JSON string formatted for AI analysis
        """
        import json
        
        big_chunks = []
        current_chunk = []
        chunk_index = 1
        
        for part in content_parts:
            # Start new chunk on H2
            if part.startswith('H2:'):
                # Save previous chunk if it exists
                if current_chunk:
                    big_chunks.append({
                        "big_chunk_index": chunk_index,
                        "small_chunks": current_chunk.copy()
                    })
                    chunk_index += 1
                
                # Start new chunk
                current_chunk = [part]
            else:
                # Add to current chunk
                current_chunk.append(part)
        
        # Add final chunk
        if current_chunk:
            big_chunks.append({
                "big_chunk_index": chunk_index,
                "small_chunks": current_chunk
            })
        
        # If no chunks created, put everything in one chunk
        if not big_chunks and content_parts:
            big_chunks = [{
                "big_chunk_index": 1,
                "small_chunks": content_parts
            }]
        
        # Create final JSON structure
        result = {
            "big_chunks": big_chunks
        }
        
        safe_log(f"Organized content into {len(big_chunks)} chunks")
        return json.dumps(result, indent=2, ensure_ascii=False)


def extract_url_content(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Convenience function for extracting content from URL
    
    Args:
        url: URL to extract content from
        
    Returns:
        tuple: (success, organized_json_content, error_message)
    """
    extractor = ContentExtractor()
    return extractor.extract_content(url)
