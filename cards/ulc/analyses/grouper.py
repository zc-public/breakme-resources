#!/usr/bin/env python3

import re
import base64
from collections import Counter, defaultdict


def parse_fuzzing_results(file_path):
    """Parse the fuzzing results file into command prefixes and responses."""
    results = defaultdict(dict)
    response_counts = Counter()

    # Pattern to match lines like "AUTH-2B-NOCRC-F4-72: WytdIDAxIAo="
    pattern = re.compile(r'^(.+?)-([0-9A-F]+):\s*(.*)$')

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('(..)'):
                continue

            match = pattern.match(line)
            if match:
                prefix, value, response = match.groups()
                results[prefix][value] = response
                response_counts[response] += 1

    return results, response_counts


def decode_base64(encoded_string):
    """Decode a Base64 encoded string with better representation of binary data."""
    if not encoded_string:
        return "silent"
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        # Try to interpret as ASCII first
        try:
            ascii_text = decoded_bytes.decode('ascii', errors='strict')
            if all(c.isprintable() or c.isspace() for c in ascii_text):
                return ascii_text.strip()
        except:
            pass

        # Otherwise, return a hex representation
        return "0x" + decoded_bytes.hex()
    except:
        return encoded_string


def determine_default_response(response_counts):
    """Determine if the default response is silent or NAK."""
    silent_count = response_counts.get('', 0)
    nak_count = response_counts.get('WytdIDAwIAo=', 0)

    if silent_count > nak_count:
        return '', "silent"
    else:
        return 'WytdIDAwIAo=', "NAK"


def find_continuous_ranges(values, default_response):
    """Find continuous ranges of non-default responses."""
    # Convert hex values to integers for sorting
    int_values = []
    for hex_val, response in values.items():
        try:
            int_val = int(hex_val, 16)
            int_values.append((int_val, hex_val, response))
        except ValueError:
            print(f"Warning: Could not convert {hex_val} to integer")

    int_values.sort()

    # Group into ranges by response
    response_ranges = defaultdict(list)

    if not int_values:
        return response_ranges

    # Find continuous ranges for non-default responses
    i = 0
    while i < len(int_values):
        int_val, hex_val, response = int_values[i]

        # Skip default responses
        if response == default_response:
            i += 1
            continue

        # Find the end of the current range with the same response
        range_start_idx = i
        while (i + 1 < len(int_values) and
               int_values[i + 1][0] == int_values[i][0] + 1 and
               int_values[i + 1][2] == response):
            i += 1

        # Add this range
        start_hex = int_values[range_start_idx][1]
        end_hex = int_values[i][1]
        response_ranges[response].append((start_hex, end_hex))

        i += 1

    return response_ranges


def find_default_ranges(all_values, non_default_ranges, max_value=0xFF):
    """Find the ranges where the default response applies."""
    # Create a set of all positions from 0 to max_value
    all_positions = set(range(max_value + 1))

    # Remove positions with non-default responses
    for ranges in non_default_ranges.values():
        for start_hex, end_hex in ranges:
            start = int(start_hex, 16)
            end = int(end_hex, 16)
            all_positions -= set(range(start, end + 1))

    # Create continuous ranges from the remaining positions
    default_ranges = []
    if not all_positions:
        return default_ranges

    positions = sorted(all_positions)
    range_start = positions[0]
    prev = positions[0]

    for pos in positions[1:]:
        if pos > prev + 1:
            # End of continuous range
            default_ranges.append((format(range_start, '02X'), format(prev, '02X')))
            range_start = pos
        prev = pos

    # Add the last range
    default_ranges.append((format(range_start, '02X'), format(prev, '02X')))

    return default_ranges


def format_range(start, end):
    """Format a hex range as a string."""
    return f"{start}-{end}" if start != end else start


def format_response(response):
    """Format a response for display, with decoding if possible."""
    if response == '':
        return "silent"
    elif response == 'WytdIDAxIAo=':
        return "NAK (01)"
    elif response == 'WytdIDAwIAo=':
        return "NAK (00)"
    else:
        # Try to decode if it's Base64
        try:
            decoded = decode_base64(response)
            if decoded != response and decoded != "silent":
                return f"{decoded} ({response})"
            else:
                return response
        except:
            return response


def split_command_prefix(prefix):
    """Split a command prefix into its parts for grouping purposes."""
    parts = prefix.split('-')

    # Get main command and last part
    if len(parts) >= 2:
        main_parts = parts[:-1]
        last_part = parts[-1]
        return '-'.join(main_parts), last_part

    return prefix, ""


def group_command_prefixes(command_data, default_response):
    """Group command prefixes that have the same behavior."""
    # First, organize commands by their main part
    grouped_by_main = defaultdict(list)

    for prefix in command_data.keys():
        main_part, last_part = split_command_prefix(prefix)
        grouped_by_main[main_part].append((last_part, prefix))

    # Now, group prefixes with the same behavior
    grouped_commands = []

    for main_part, variants in grouped_by_main.items():
        # Sort variants by the last part
        variants.sort(key=lambda x: int(x[0], 16) if x[0] and
                      all(c in '0123456789ABCDEF' for c in x[0].upper()) else x[0])

        current_group = []
        current_behavior = None

        for last_part, full_prefix in variants:
            # Determine behavior for this prefix
            values = command_data[full_prefix]
            non_default_ranges = find_continuous_ranges(values, default_response)

            # Convert behavior to a hashable representation
            behavior_key = str(sorted([(resp, tuple(ranges)) for resp, ranges in non_default_ranges.items()]))

            if current_behavior is None:
                current_behavior = behavior_key
                current_group.append((last_part, full_prefix))
            elif behavior_key == current_behavior:
                current_group.append((last_part, full_prefix))
            else:
                # Add current group to results and start a new one
                grouped_commands.append((current_group, current_behavior))
                current_group = [(last_part, full_prefix)]
                current_behavior = behavior_key

        # Add the last group
        if current_group:
            grouped_commands.append((current_group, current_behavior))

    return grouped_commands


def create_prefix_range_name(group):
    """Create a name for a group of command prefixes."""
    if not group:
        return ""

    # If all prefixes share the same main part
    main_parts = [split_command_prefix(g[1])[0] for g in group]

    if all(part == main_parts[0] for part in main_parts):
        main_part = main_parts[0]
        # Get ranges of last parts
        last_parts = [g[0] for g in group]

        # If there's only one prefix in the group, just return it
        if len(last_parts) == 1:
            return group[0][1]

        # Try to create ranges
        ranges = []
        range_start = last_parts[0]
        prev_part = last_parts[0]

        try:
            for i in range(1, len(last_parts)):
                # Check if this is a continuation of the current range
                prev_val = int(prev_part, 16)
                curr_val = int(last_parts[i], 16)

                if curr_val != prev_val + 1:
                    # End of range
                    if range_start == prev_part:
                        ranges.append(range_start)
                    else:
                        ranges.append(f"{range_start}-{prev_part}")
                    range_start = last_parts[i]

                prev_part = last_parts[i]

            # Add the last range
            if range_start == prev_part:
                ranges.append(range_start)
            else:
                ranges.append(f"{range_start}-{prev_part}")

            return f"{main_part}-[{', '.join(ranges)}]"
        except ValueError:
            # Fall back if we can't convert to integers
            return f"{main_part}-[{', '.join(last_parts)}]"

    # Just list all the prefixes
    return ", ".join(g[1] for g in group)


def main(file_path):
    """Main function to analyze fuzzing results and create a range table."""
    print(f"Analyzing fuzzing results from: {file_path}")

    # Parse the input file
    command_data, response_counts = parse_fuzzing_results(file_path)

    # Determine the default response
    default_response, default_name = determine_default_response(response_counts)
    print(f"Default response determined to be: {default_name}")

    # Group command prefixes with the same behavior
    grouped_commands = group_command_prefixes(command_data, default_response)

    # Output table header
    print("\nCommand Ranges Summary:")
    print("-" * 80)

    # Process each group of command prefixes
    for group, _ in grouped_commands:
        group_name = create_prefix_range_name(group)
        print(f"\nCommand: {group_name}")

        # Use the first prefix in the group as the representative
        representative_prefix = group[0][1]
        values = command_data[representative_prefix]

        max_value = 0xFF
        if len(values) > 0:
            # If the values have certain patterns like 2-byte values, adjust max_value
            max_hex = max(values.keys(), key=lambda x: len(x))
            if len(max_hex) > 2:
                max_value = 0xFFFF if len(max_hex) <= 4 else 0xFFFFFF

        # Find non-default response ranges
        non_default_ranges = find_continuous_ranges(values, default_response)

        # Print non-default responses
        if non_default_ranges:
            print("  Non-default responses:")
            for response, ranges in sorted(non_default_ranges.items(), key=lambda x: x[1]):
                range_str = ", ".join(format_range(start, end) for start, end in ranges)
                resp_formatted = format_response(response)
                print(f"    {resp_formatted}: {range_str}")

        # Find and print default ranges
        default_ranges = find_default_ranges(values, non_default_ranges, max_value)
        range_str = ", ".join(format_range(start, end) for start, end in default_ranges)

        # If we have comprehensive coverage, simplify output
        if (len(default_ranges) == 1 and default_ranges[0][0] == '00' and default_ranges[0][1] == format(max_value, '02X')):
            print(f"  DEFAULT ({default_name}): Full range (00-{format(max_value, '02X')})")
        elif default_ranges:
            print(f"  DEFAULT ({default_name}): {range_str}")
        else:
            print(f"  No default ({default_name}) responses found")

    print("-" * 80)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = "fuzzing_results.txt"

    main(file_path)
