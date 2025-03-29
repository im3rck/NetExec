# -*- coding: utf-8 -*-
from io import BytesIO
from os import makedirs
from os.path import join, abspath
import re
import traceback # For detailed error reporting
from nxc.paths import NXC_PATH # For saving output

# Note: Removed imports: argparse, glob, collections, datetime, sys, pytz
# Note: Removed Colors class

class NXCModule:
    # Module integrating Program 2's detailed parsing logic for remote execution
    name = "notepad_parser"
    description = "Extracts/Reconstructs content from remote Windows Notepad tab state binary files using detailed parsing."
    supported_protocols = ["smb"]
    opsec_safe = True # Considered safer than Program 1 as it avoids taskkill
    multiple_hosts = True
    # False positives list from Program 1 - useful for filtering directories
    false_positive_dirs = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        # Verbosity can be checked using context.log.level (e.g., logging.DEBUG)
        # We'll use context.log.debug for verbose output similar to Program 2's -vv

    def options(self, context, module_options):
        """No specific options for this module yet."""
        pass

    # --- Helper Functions adapted from Program 2 ---
    # (Made into methods or kept as static/helper functions if appropriate)
    # (Replaced print with context.log.debug for verbose/trace logging)
    # (Removed color codes)

    @staticmethod
    def hex_dump(data, bytes_per_line=16):
        # Useful for debugging if needed, called within debug logs
        output = []; hex_part = ''; text_part = ''
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]; hex_part = ' '.join(f'{b:02X}' for b in chunk)
            text_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            output.append(f'{i:08X}: {hex_part.ljust(bytes_per_line * 3)}  {text_part}')
        return '\n'.join(output)

    @staticmethod
    def decode_utf16le(data):
        try:
            text = data.decode('utf-16le', errors='ignore')
            return text.rstrip('\x00')
        except Exception as e:
            # Log error via context when called if needed
            return f"[UTF-16LE Decode Error: {e}]"

    def find_text_start(self, data, initial_offset=0, min_length=2):
        is_debug = self.context.log.level == 10 # logging.DEBUG
        if initial_offset + (min_length * 2) > len(data):
            if is_debug: self.context.log.debug(f"      [find_text_start: Data too short from offset {initial_offset}]")
            return -1
        for offset in range(initial_offset, len(data) - (min_length * 2) + 1):
            is_potential_start = True
            for i in range(min_length):
                char_byte_offset = offset + i * 2
                if char_byte_offset + 1 >= len(data): is_potential_start = False; break
                low_byte = data[char_byte_offset]; high_byte = data[char_byte_offset + 1]
                is_valid_char = (32 <= low_byte <= 126 or low_byte in (0x09, 0x0a, 0x0d)) and high_byte == 0x00
                if not is_valid_char: is_potential_start = False; break
            if is_potential_start:
                if is_debug: self.context.log.debug(f"      [find_text_start: Found plausible start at offset {offset}]")
                return offset
        if is_debug: self.context.log.debug(f"      [find_text_start: No plausible start found from offset {initial_offset}]")
        return -1

    @staticmethod
    def clean_segment_text(text):
        cleaned = text.strip();
        while cleaned and (ord(cleaned[-1]) < 32 or ord(cleaned[-1]) == 127):
            cleaned = cleaned[:-1]
        return cleaned

    @staticmethod
    def extract_ascii_strings(data, min_length=4):
        strings = []; current_string = ""
        for byte in data:
            if 32 <= byte <= 126 or byte in (ord('\n'), ord('\r'), ord('\t')):
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length: strings.append(current_string)
                current_string = ""
        if len(current_string) >= min_length: strings.append(current_string)
        # Return as a single string with newlines, easier to log/save
        return "\n".join(strings)

    def find_pattern_at(self, data_slice, index):
        """Checks for ADD/DELETE patterns. Debug prints are handled by context.log.debug."""
        slice_len = len(data_slice)
        is_debug = self.context.log.level == 10 # logging.DEBUG

        if is_debug: # Debug Print only if level is DEBUG
            try:
                debug_bytes_len = min(4, slice_len - index)
                debug_bytes = data_slice[index:index+debug_bytes_len]
                self.context.log.debug(f"    [DEBUG find_pattern_at] Index={index:03d} (0x{index:02X}), Checking Bytes: {debug_bytes.hex(' ').upper()}")
            except Exception as e:
                 self.context.log.debug(f"    [DEBUG find_pattern_at] Index={index:03d} (0x{index:02X}), Error slicing: {e}")

        # Check ADD
        if index + 4 <= slice_len:
            pos, b1, b2, char = data_slice[index:index+4]
            is_add_match = (b1 == 0x00 and b2 == 0x01)
            if is_debug: self.context.log.debug(f"        ADD Check: Bytes={pos:02X} {b1:02X} {b2:02X} {char:02X} -> Match? {is_add_match}")
            if is_add_match:
                if is_debug: self.context.log.debug(f"        -> ADD MATCH FOUND!")
                return ('add', pos, char, 4)

        # Check DELETE
        if index + 3 <= slice_len:
            pos, b1, b2 = data_slice[index:index+3]
            is_del_match = (b1 == 0x01 and b2 == 0x00)
            if is_debug: self.context.log.debug(f"        DEL Check: Bytes={pos:02X} {b1:02X} {b2:02X} -> Match? {is_del_match}")
            if is_del_match:
                if is_debug: self.context.log.debug(f"        -> DEL MATCH FOUND!")
                return ('delete', pos, None, 3)

        if is_debug: self.context.log.debug(f"        -> NO MATCH.")
        return None

    def parse_operations_PATTERN(self, data_slice, base_text_length=0):
        """UNIFIED PARSER adapted for nxc. Returns list of operations."""
        found_ops_relative_temp = []
        current_index = 0
        slice_len = len(data_slice)
        is_debug = self.context.log.level == 10 # logging.DEBUG

        if is_debug: self.context.log.debug(f"\n--- Parsing Operations (ALWAYS ADVANCE 1 Mode) ---")

        while current_index < slice_len:
            result = self.find_pattern_at(data_slice, current_index) # Pass level implicitly via self.context
            if result:
                op_type, pos, char_code, length = result
                found_ops_relative_temp.append({'index': current_index, 'type': op_type, 'pos': pos, 'char': char_code})
                if is_debug: self.context.log.debug(f"  Slice Idx={current_index:03d}: RECORDING potential pattern: Type={op_type}, Pos=0x{pos:02X}, Length={length}")
            current_index += 1

        if is_debug: self.context.log.debug(f"--- Pattern Scan Complete (ALWAYS ADVANCE 1 Mode) ---")
        final_ops_relative = [(op['index'], op['type'], op['pos'], op['char']) for op in found_ops_relative_temp]
        final_ops_relative.sort(key=lambda x: x[0]) # Sort by original index in slice

        # Debug print the list
        if is_debug:
            self.context.log.debug(f"\n--- Final Pattern Operations List (ALWAYS ADVANCE 1, Unfiltered) ---")
            if not final_ops_relative: self.context.log.debug("   (None)")
            else:
                max_ops_to_print_parser = 100; op_count = 0
                for op in final_ops_relative:
                    op_type_str = f"{op[1]:<6}" # No color here
                    self.context.log.debug(f"   ({op[0]:03d}, {op_type_str}, Pos=0x{op[2]:02X}, CharCode={f'0x{op[3]:02X}' if op[3] is not None else 'None'})")
                    op_count += 1
                    if op_count >= max_ops_to_print_parser:
                        self.context.log.debug(f"      ... (parser list truncated, {len(final_ops_relative) - max_ops_to_print_parser} more)")
                        break
        return final_ops_relative

    def apply_edits_PATTERN(self, operations, initial_text=""):
        """UNIFIED APPLY LOGIC adapted for nxc. Returns final reconstructed text."""
        text_list = list(initial_text)
        deleted_chars_list = [] # Collect deleted characters
        is_debug = self.context.log.level == 10 # logging.DEBUG
        is_info = self.context.log.level <= 20 # logging.INFO or lower

        # Sort operations by their original file index (important!)
        operations.sort(key=lambda op: op[0])

        if is_debug:
            self.context.log.debug(f"\n--- Applying Edits (INSERT/SHIFT Mode - Detailed Trace) ---")
            self.context.log.debug(f"   Initial Text ({len(initial_text)} chars): {repr(initial_text)}")
            if operations:
                self.context.log.debug(f"    Operations to Apply ({len(operations)}):")
                # (Limited debug printing of ops list as in original)
                max_ops_to_print = 50; op_count = 0
                for op_index, op_type, op_pos, op_char_code in operations:
                    op_char_repr = f'0x{op_char_code:02X}' if op_char_code is not None else 'None'
                    self.context.log.debug(f"     - OrigIdx={op_index:03d}, Type={op_type:<6}, Pos=0x{op_pos:02X}, CharCode={op_char_repr}")
                    op_count += 1
                    if op_count >= max_ops_to_print: self.context.log.debug(f"     ... (list truncated)"); break
            else:
                 self.context.log.debug(f"    Operations to Apply: (None)")
            self.context.log.debug(f"--- Beginning Detailed Edit Application ---")

        if not operations: return initial_text

        # Main application loop
        for index, op_type, position, char_code in operations:
            char = None
            if op_type == 'add' and char_code is not None:
                try:
                    char_bytes = bytes([char_code]); char = char_bytes.decode('utf-8', errors='replace')
                    # Make non-printable chars visible for logging if needed
                    if not char.isprintable() and char not in ('\n', '\r', '\t', ' '): char = '.' # Use '.' for non-printable
                except Exception: char = '.' # Default representation on error

            # Per-Operation Detailed Log (Level DEBUG)
            if is_debug:
                current_len = len(text_list)
                self.context.log.debug(f"    Op @ Idx {index:03d}: {op_type}, Pos=0x{position:02X}, Char='{repr(char)[1:-1] if char else 'N/A'}' ({f'0x{char_code:02X}' if char_code is not None else 'N/A'}), Len={current_len}")

            # Apply Operation (INSERT/SHIFT logic)
            try:
                if op_type == 'add':
                    insert_pos = max(0, min(position, len(text_list)))
                    if char is not None:
                        text_list.insert(insert_pos, char)
                        if is_debug: self.context.log.debug(f"     -> Inserted AT index {insert_pos}. New len={len(text_list)}")
                    elif is_debug: self.context.log.debug(f"     -> Add op with None char skipped.")

                elif op_type == 'delete':
                    delete_pos = position
                    if 0 <= delete_pos < len(text_list):
                        char_to_delete = text_list[delete_pos]
                        deleted_chars_list.append(char_to_delete) # Collect deleted char
                        if is_debug:
                             deleted_char_repr = repr(char_to_delete)
                             self.context.log.debug(f"     Deleted char: {deleted_char_repr} (from index {delete_pos})")
                        text_list.pop(delete_pos) # Perform deletion
                        if is_debug: self.context.log.debug(f"     -> List len after delete: {len(text_list)}")
                    elif is_debug:
                        self.context.log.debug(f"     Delete pos {delete_pos} out of bounds (len={len(text_list)}). Skipped.")
            except Exception as e:
                self.context.log.error(f"     ERROR applying op: {e}")
                self.context.log.debug(f"     [Error applying operation {op_type} at index {index}: {e}]\n{traceback.format_exc(limit=1)}")

        final_text = "".join(text_list)

        # Summary Log (Level INFO or DEBUG) - Log initial/deleted/final
        if is_info: # Show summary if logging level is INFO or DEBUG
             self.context.log.info(f"  --- Edit Summary ---")
             self.context.log.info(f"    Initial Text ({len(initial_text)} chars): {repr(initial_text)}")
             deleted_chars_raw = "".join(deleted_chars_list)
             # Reverse deleted chars and format for readability (like original script)
             reversed_deleted_chars = deleted_chars_raw[::-1]
             formatted_deleted_output = reversed_deleted_chars.replace('\r', '\n').strip()
             self.context.log.info(f"    Deleted Characters ({len(deleted_chars_raw)} chars):")
             if formatted_deleted_output:
                 for line in formatted_deleted_output.splitlines():
                     self.context.log.info(f"      {line}")
             elif deleted_chars_raw: self.context.log.info(f"      (Whitespace only)")
             else: self.context.log.info(f"      (None)")
             self.context.log.info(f"    Final Text ({len(final_text)} chars): {repr(final_text)}")

        if is_debug: self.context.log.debug(f"--- Applying Edits Complete (INSERT/SHIFT Mode) ---")

        return final_text

    def extract_text_via_pattern_fallback(self, data_bytes, source_description=""):
        """Applies the UNIFIED pattern parser and apply logic as a fallback."""
        is_debug = self.context.log.level == 10
        if is_debug: self.context.log.debug(f"  [Pattern Fallback called for {source_description} - Using UNIFIED Logic]")
        if not data_bytes or len(data_bytes) < 2: return ""

        # Assuming fallback always parses from start of data slice provided
        start_index = 0 # Adjust if needed, original used 2, but seems context dependent
        if start_index >= len(data_bytes): return ""
        data_to_parse = data_bytes[start_index:]
        original_offset = start_index # Offset relative to the *start of data_bytes*

        # Base text length is 0 for fallback, initial_text is empty string
        operations_relative = self.parse_operations_PATTERN(data_to_parse, base_text_length=0)

        # Adjust relative indices to be absolute within the data_bytes slice
        operations = [(rel_idx + original_offset, op_type, op_pos, op_char) for rel_idx, op_type, op_pos, op_char in operations_relative]

        final_text = self.apply_edits_PATTERN(operations, initial_text="")
        return final_text

    # --- File Processing Logic adapted for nxc ---

    def process_saved_file(self, data, remote_file_path):
        """Processes saved files using UNIFIED Logic for nxc."""
        self.context.log.info(f"Processing Saved File: C:\\{remote_file_path}")
        is_debug = self.context.log.level == 10
        if is_debug: # Show hex dump only if debug
            self.context.log.debug("\nHex Dump (first 256 bytes):\n" + self.hex_dump(data[:256]))
            if len(data)>256: self.context.log.debug("...")

        # --- Extract File Path (from binary data) ---
        file_path_start_offset = 5; max_path_scan_len = 512; scan_end_offset = min(file_path_start_offset + max_path_scan_len, len(data))
        file_path_in_bin = "[Path Extraction Error]"; valid_path_bytes = bytearray()
        # (Path extraction logic from Program 2 - unchanged except logging)
        if file_path_start_offset < len(data) -1:
            try:
                idx = file_path_start_offset
                while idx < scan_end_offset - 1:
                    low, high = data[idx:idx+2]
                    if low == 0 and high == 0: break # Null terminator
                    if high != 0: # Expecting UTF-16LE (high byte 0x00)
                       if is_debug: self.context.log.debug(f"  [Path Extractor: Non-zero high byte 0x{high:02X} at {idx+1}]")
                       break # Stop if format unexpected
                    valid_path_bytes.extend([low, high]); idx += 2
                if not valid_path_bytes: file_path_in_bin = "[Path Extraction Failed]"
                else: file_path_in_bin = self.decode_utf16le(valid_path_bytes)
            except Exception as e:
                file_path_in_bin = f"[Path Extraction Error: {e}]"
                self.context.log.error(f"  Error extracting path from binary: {e}")
                if is_debug: self.context.log.debug(f"  [Path Extractor: Exception: {e}]\n{traceback.format_exc(limit=1)}")
        else:
             self.context.log.warning(f"  [Warning: Not enough data in binary to extract file path]")
        self.context.log.info(f"  File Path Found in Binary: {file_path_in_bin}")
        self.context.log.info("-" * 40)

        # --- Extract Base Text ---
        if is_debug: self.context.log.debug("--- Searching for Initial Content Block (02 01 01...) ---")
        base_text = ""; end_base_text_idx = -1; base_text_marker = b'\x02\x01\x01'; base_text_found = False
        # (Base text extraction logic from Program 2 - unchanged except logging)
        try:
            marker_idx = data.find(base_text_marker)
            if marker_idx != -1:
                len_byte_idx = marker_idx + len(base_text_marker)
                if len_byte_idx < len(data):
                    length = data[len_byte_idx]; start_text_idx = len_byte_idx + 1; end_text_idx_calc = start_text_idx + length * 2
                    if end_text_idx_calc <= len(data):
                        base_text = self.decode_utf16le(data[start_text_idx : end_text_idx_calc])
                        end_base_text_idx = end_text_idx_calc; base_text_found = True
                        if is_debug: self.context.log.debug(f"    [Info: Base Text Found: len={length}, data@[{start_text_idx}:{end_text_idx_calc}], raw='{repr(base_text)}']")
            if not base_text_found:
                if is_debug: self.context.log.debug("    [Info: Base text marker not found or data incomplete]")
        except Exception as e:
             self.context.log.error(f"  Error extracting base text: {e}")
             if is_debug: self.context.log.debug(f"  [Base Text Error: {e}]")

        base_text_len = len(base_text)
        if base_text_found: self.context.log.info(f"  Initial Base Text ({base_text_len} chars):\n{base_text.replace('\r', '\\n')}") # Log base text clearly
        else: self.context.log.warning("  [No Initial Base Text Found]"); end_base_text_idx = 2 if end_base_text_idx == -1 else end_base_text_idx # Ensure we have a valid index
        self.context.log.info("-" * 40)

        # --- Parse & Apply Operations using UNIFIED parser ---
        if is_debug: self.context.log.debug(f"--- Parsing ADD/DELETE Operations (Scanning from index {end_base_text_idx}) ---")
        final_reconstructed_text = "[Error]"; error_occurred = False
        try:
            data_to_parse_ops = data[end_base_text_idx:] if end_base_text_idx < len(data) else b''
            original_offset = end_base_text_idx # This is the offset in the original file data

            if not data_to_parse_ops:
                if is_debug: self.context.log.debug("    [Info: No data after base text. Using base text.]")
                final_reconstructed_text = base_text
            else:
                # Parse ops relative to the start of data_to_parse_ops
                operations_relative = self.parse_operations_PATTERN(data_to_parse_ops, base_text_length=base_text_len)
                # Convert relative indices to absolute indices within the original file data
                operations = [(rel_idx + original_offset, op_type, op_pos, op_char) for rel_idx, op_type, op_pos, op_char in operations_relative]
                # Apply edits using absolute indices and the initial base text
                final_reconstructed_text = self.apply_edits_PATTERN(operations, initial_text=base_text)
        except Exception as pattern_error:
            self.context.log.error(f"  Error during saved file op parsing/application: {pattern_error}")
            self.context.log.debug(f"{traceback.format_exc()}")
            final_reconstructed_text = f"[Error: {pattern_error}]"; error_occurred = True

        # --- Return Final Result ---
        if error_occurred:
            self.context.log.error(f"  Final Reconstructed Content: {final_reconstructed_text}")
            return None # Indicate error
        else:
            # Final text is logged inside apply_edits_PATTERN if log level allows
            # Log the final result clearly here as well
            self.context.log.highlight("--- Final Reconstructed Content (Saved File) ---")
            # Log potentially multi-line content line by line for clarity in nxc log
            for line in final_reconstructed_text.replace('\r', '').split('\n'):
                 self.context.log.highlight(line if line else " ") # Ensure blank lines show
            self.context.log.info("-" * 40)
            return final_reconstructed_text


    def process_unsaved_file(self, data, remote_file_path):
        """Processes unsaved files using heuristics and fallbacks for nxc."""
        self.context.log.info(f"Processing Unsaved File: C:\\{remote_file_path}")
        is_debug = self.context.log.level == 10
        if is_debug: # Show hex dump only if debug
            self.context.log.debug("\nHex Dump (first 256 bytes):\n" + self.hex_dump(data[:256]))
            if len(data)>256: self.context.log.debug("...")

        primary_extracted_text = ""; ascii_fallback_text = ""; pattern_fallback_text = "";
        primary_method_success = False

        # --- Primary Method (UTF-16LE Heuristics) ---
        if is_debug: self.context.log.debug("--- Attempting Primary Method (UTF-16LE Heuristics) ---")
        text_start_offset = self.find_text_start(data, 0) # Pass self for context
        separator_offset = -1
        try: separator_offset = data.rfind(b'\x01')
        except Exception as e:
            if is_debug: self.context.log.debug(f"    [Warning: data.rfind(b'\\x01') failed: {e}]")

        if separator_offset != -1 and text_start_offset != -1 and text_start_offset < separator_offset:
            text_data = data[text_start_offset:separator_offset]
            if is_debug: self.context.log.debug(f"    [Primary Method: Found start={text_start_offset}, separator={separator_offset}. Decoding {len(text_data)} bytes.]")
            decoded_text = self.decode_utf16le(text_data); cleaned_text = self.clean_segment_text(decoded_text)
            if cleaned_text:
                primary_method_success = True; primary_extracted_text = cleaned_text
                self.context.log.info("--- File Content (UTF-16LE Section - Primary Method) ---")
                for line in cleaned_text.replace('\r', '').split('\n'):
                   self.context.log.info(line if line else " ")
            else: self.context.log.warning("[Primary Method: UTF-16LE decoding yielded empty result. Trying fallbacks.]");
        else: # Log warnings if primary skipped
             if is_debug: self.context.log.debug("    [Primary Method: Heuristics failed. Trying fallbacks.]")
             # Specific warnings based on why it failed
             if separator_offset == -1 and text_start_offset == -1: self.context.log.warning("[Warning: Text start and 0x01 separator not found. Primary UTF-16LE skipped.]")
             elif separator_offset == -1: self.context.log.warning("[Warning: 0x01 separator not found. Primary UTF-16LE skipped.]")
             elif text_start_offset == -1: self.context.log.warning("[Warning: UTF-16LE text start not found. Primary UTF-16LE skipped.]")
             elif text_start_offset >= separator_offset: self.context.log.warning(f"[Warning: Text start ({text_start_offset}) >= separator ({separator_offset}). Primary UTF-16LE skipped.]")

        # --- ASCII Fallback ---
        if not primary_method_success:
            if is_debug: self.context.log.debug(f"\n--- Applying ASCII Fallback to Full File Data ---")
            try:
                ascii_fallback_text = self.extract_ascii_strings(data)
                if ascii_fallback_text:
                    self.context.log.info("--- Fallback Extracted File Content (ASCII Strings) ---")
                    for line in ascii_fallback_text.replace('\r', '').split('\n'):
                       self.context.log.info(line if line else " ")
                elif is_debug: self.context.log.debug("   [No Content Extracted (ASCII Fallback)]")
            except Exception as ascii_error:
                self.context.log.error(f"  ASCII Fallback Error: {ascii_error}")
                if is_debug: self.context.log.debug(traceback.format_exc(limit=1))

        # --- Use UNIFIED Pattern PARSER Fallback ---
        # This runs regardless of previous success to see if it finds more/different data
        if is_debug: self.context.log.debug(f"\n--- Applying PATTERN PARSER Fallback (UNIFIED Logic) ---")
        pattern_error_occurred = False
        try:
            # Pass the full data, as context might be anywhere
            pattern_fallback_text = self.extract_text_via_pattern_fallback(data, f"C:\\{remote_file_path}")
        except Exception as pattern_error:
            self.context.log.error(f"  Pattern Parser Fallback Error: {pattern_error}")
            self.context.log.debug(f"Traceback:\n{traceback.format_exc()}")
            pattern_error_occurred = True; pattern_fallback_text = f"[Error: {pattern_error}]"

        # --- Decide Final Output for Unsaved Files ---
        final_text_unsaved = None
        if primary_method_success:
            final_text_unsaved = primary_extracted_text
            # Optionally log if pattern fallback found something different/additional?
            if pattern_fallback_text and pattern_fallback_text != primary_extracted_text and not pattern_error_occurred:
                 self.context.log.info("--- Additional Content Found via Pattern Fallback ---")
                 for line in pattern_fallback_text.replace('\r', '').split('\n'):
                     self.context.log.info(line if line else " ")

        elif ascii_fallback_text: # If primary failed, but ASCII worked
            final_text_unsaved = ascii_fallback_text
            if pattern_fallback_text and pattern_fallback_text != ascii_fallback_text and not pattern_error_occurred:
                 self.context.log.info("--- Additional/Different Content Found via Pattern Fallback ---")
                 for line in pattern_fallback_text.replace('\r', '').split('\n'):
                     self.context.log.info(line if line else " ")

        elif pattern_fallback_text and not pattern_error_occurred: # If only pattern fallback worked
            final_text_unsaved = pattern_fallback_text
            self.context.log.highlight("--- Final Extracted Content (PATTERN PARSER Fallback - Unsaved File) ---")
            for line in pattern_fallback_text.replace('\r', '').split('\n'):
                self.context.log.highlight(line if line else " ")

        elif pattern_error_occurred:
             self.context.log.error(f"  Final Result (Unsaved): Error occurred during pattern fallback: {pattern_fallback_text}")
        else:
            self.context.log.info("  No meaningful content extracted from this unsaved file using any method.")

        self.context.log.info("-" * 40)
        return final_text_unsaved # Return the best result found


    # --- Main Execution Logic ---
    def on_admin_login(self, context, connection):
        context.log.display("Searching for Notepad tab state files using detailed parser...")
        users_dir = "C$\\Users"
        output_dir = join(NXC_PATH, "modules", self.name, connection.hostname)
        makedirs(output_dir, exist_ok=True)
        found_count = 0

        try:
            user_dirs = connection.conn.listPath(users_dir, "*")
        except Exception as e:
            context.log.error(f"Could not list users directory {users_dir.replace('$',':')}: {e}")
            return

        for user_dir in user_dirs:
            if not user_dir.is_directory() or user_dir.get_longname() in self.false_positive_dirs:
                continue

            username = user_dir.get_longname()
            context.log.info(f"Checking user: {username}")
            notepad_dir_relative = f"Users\\{username}\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState"
            notepad_dir_unc = f"{users_dir[:-1]}{notepad_dir_relative}" # For listing

            try:
                tab_state_files = connection.conn.listPath(notepad_dir_unc, "*.bin")
                if not tab_state_files:
                    context.log.info(f"  No .bin files found in TabState for {username}")
                    continue

                for file_info in tab_state_files:
                    filename = file_info.get_longname()
                    if filename in [".", ".."] or not filename.endswith(".bin"): # Basic checks
                        continue

                    # Filter out history files like .0.bin, .1.bin (as per Program 2 logic)
                    if re.match(r'.*\.\d+\.bin$', filename):
                        context.log.debug(f"  Skipping history file: {filename}")
                        continue

                    remote_file_path = f"{notepad_dir_relative}\\{filename}"
                    remote_file_path_unc = f"{notepad_dir_unc}\\{filename}"
                    context.log.info(f"  Found potential file: C:\\{remote_file_path}")

                    file_content_bytes = None
                    buf = BytesIO()
                    try:
                        connection.conn.getFile("C$", remote_file_path, buf.write)
                        buf.seek(0)
                        file_content_bytes = buf.read()
                        context.log.debug(f"  Successfully read {len(file_content_bytes)} bytes from C:\\{remote_file_path}")
                    except Exception as e:
                        if "STATUS_SHARING_VIOLATION" in str(e):
                            context.log.warning(f"  Cannot read file C:\\{remote_file_path}: File is locked by Notepad. Skipping. (No taskkill attempted)")
                        else:
                            context.log.error(f"  Error reading file C:\\{remote_file_path}: {e}")
                        continue # Skip this file on error

                    if not file_content_bytes or len(file_content_bytes) < 4:
                         context.log.warning(f"  File C:\\{remote_file_path} is empty or too short. Skipping.")
                         continue

                    # --- Determine file type and process using adapted Program 2 logic ---
                    is_saved = (file_content_bytes[3] == 1)
                    reconstructed_text = None
                    try:
                        if is_saved:
                            reconstructed_text = self.process_saved_file(file_content_bytes, remote_file_path)
                        else:
                            reconstructed_text = self.process_unsaved_file(file_content_bytes, remote_file_path)
                    except Exception as processing_error:
                         context.log.error(f"  Unexpected error processing file C:\\{remote_file_path}: {processing_error}")
                         context.log.debug(traceback.format_exc())
                         continue # Skip file on processing error

                    # --- Log and Save Result ---
                    if reconstructed_text is not None: # Check if processing returned valid text (not None on error)
                        found_count += 1
                        # Logging is handled within the processing functions mostly
                        # Save the result
                        try:
                            # Create a filename safe for local FS
                            safe_filename = f"{connection.hostname}_{username}_{filename.replace('.bin','')}_parsed.txt"
                            output_path = abspath(join(output_dir, safe_filename))
                            with open(output_path, "w", encoding='utf-8') as f:
                                f.write(f"Source: C:\\{remote_file_path}\n")
                                if is_saved:
                                    f.write(f"Type: Saved (Reconstructed)\n\n")
                                else:
                                    f.write(f"Type: Unsaved (Extracted)\n\n")
                                f.write(reconstructed_text)
                            context.log.success(f"Reconstructed content saved to: {output_path}")
                        except Exception as e:
                            context.log.error(f"Failed to save output to {safe_filename}: {e}")
                    else:
                        context.log.info(f"  No displayable content found or error occurred for C:\\{remote_file_path}")

            except Exception as e:
                 # Handle case where TabState dir might exist but is inaccessible
                 if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                      context.log.info(f"  TabState directory not found or accessible for {username}: {notepad_dir_unc.replace('$', ':')}")
                 else:
                      context.log.error(f"  Error accessing TabState for {username} ({notepad_dir_unc.replace('$', ':')}): {e}")
                 context.log.debug(traceback.format_exc())


        if found_count == 0:
            context.log.display("No Notepad tab state files with parseable content found.")
        else:
             context.log.display(f"Finished processing. Found and parsed content from {found_count} file(s). Check logs and saved files in {output_dir}")
