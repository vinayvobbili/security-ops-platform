"""
Excel Formatting Utilities

Provides consistent professional formatting for Excel reports across the application.
"""

import logging
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Border, Side, Alignment, NamedStyle

logger = logging.getLogger(__name__)


def apply_professional_formatting(file_path, column_widths=None, wrap_columns=None, date_columns=None):
    """
    Apply professional formatting to Excel files including:
    - Bold white headers on blue background
    - Zebra striping (alternating row colors)
    - Text wrapping for specified columns
    - Date formatting for specified columns
    - Cell borders throughout
    - Frozen header row
    - Auto-filter
    
    Args:
        file_path: Path to Excel file
        column_widths: Dict mapping column names (lowercase) to widths
        wrap_columns: Set of column names (lowercase) that should wrap text
        date_columns: Set of column names (lowercase) that contain dates
    """
    try:
        # Default column widths
        default_column_widths = {
            'hostname': 25,
            'host_id': 20,
            'current_tags': 80,
            'invalid_tags': 60,
            'last_seen': 20,
            'status': 15,
            'cs_host_category': 20,
            'snow_environment': 15,
            'snow_lifecyclestatus': 20,
            'comment': 50,
            'environment': 15,
            'platform': 15,
            'tags': 60,
            'device_id': 20,
            'first_seen': 20,
            'local_ip': 15,
            'external_ip': 15,
            'os_version': 30,
            'kernel_version': 30,
            'system_manufacturer': 20,
            'system_product_name': 25,
        }
        
        # Use provided column widths or defaults
        if column_widths:
            default_column_widths.update(column_widths)
        column_widths = default_column_widths
        
        # Default wrap columns
        default_wrap_columns = {'current_tags', 'invalid_tags', 'comment', 'tags'}
        if wrap_columns:
            default_wrap_columns.update(wrap_columns)
        wrap_columns = default_wrap_columns
        
        # Default date columns
        default_date_columns = {'last_seen', 'first_seen'}
        if date_columns:
            default_date_columns.update(date_columns)
        date_columns = default_date_columns
        
        workbook = load_workbook(file_path)
        worksheet = workbook.active
        
        # Get header row to map column names to letters
        header_row = list(worksheet.iter_rows(min_row=1, max_row=1, values_only=True))[0]
        
        # Define styles
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'), 
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        wrap_alignment = Alignment(wrap_text=True, vertical='top')
        
        # Zebra stripe colors
        light_fill = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")
        
        # Create date style
        date_style = NamedStyle(name='date_style', number_format='MM/DD/YYYY HH:MM')
        
        # Format headers
        for col_idx, header in enumerate(header_row, 1):
            col_letter = worksheet.cell(row=1, column=col_idx).column_letter
            cell = worksheet.cell(row=1, column=col_idx)
            
            # Set column width
            if header and header.lower() in column_widths:
                worksheet.column_dimensions[col_letter].width = column_widths[header.lower()]
            else:
                worksheet.column_dimensions[col_letter].width = 15
            
            # Format header cell
            cell.font = header_font
            cell.fill = header_fill
            cell.border = thin_border
        
        # Format data rows
        for row_idx in range(2, worksheet.max_row + 1):
            # Zebra striping - every other row
            is_alternate_row = (row_idx % 2 == 0)
            
            for col_idx, header in enumerate(header_row, 1):
                cell = worksheet.cell(row=row_idx, column=col_idx)
                
                # Add borders to all cells
                cell.border = thin_border
                
                # Zebra striping
                if is_alternate_row:
                    cell.fill = light_fill
                
                # Text wrapping for long content columns
                if header and header.lower() in wrap_columns:
                    cell.alignment = wrap_alignment
                
                # Date formatting
                if header and header.lower() in date_columns and cell.value:
                    cell.style = date_style
        
        # Freeze the header row
        worksheet.freeze_panes = 'A2'
        
        # Add autofilter to the data range
        if worksheet.max_row > 1:  # Only add filter if there's data beyond headers
            worksheet.auto_filter.ref = f"A1:{worksheet.cell(row=worksheet.max_row, column=worksheet.max_column).coordinate}"
        
        workbook.save(file_path)
        logger.info(f"Applied professional formatting to {file_path}")
        
    except Exception as e:
        logger.warning(f"Could not format Excel file {file_path}: {e}")