#!/usr/bin/env python3
"""Parse the log file and extract relevant statistics."""

import re
import statistics
import numpy as np
import matplotlib.pyplot as plt


def plot_data_with_gaussian(data, title, xlabel, discrete=False, quiet=False, interval=None):
    """Plot data with Gaussian distribution overlay."""
    if interval is not None:
        interval = (interval['min'], interval['max'])
    else:
        interval = (min(data), max(data))
    mean = statistics.mean(data)
    stdev = statistics.stdev(data) if len(data) > 1 else 0

    gaussian = None
    if not quiet:
        x = np.linspace(min(data), max(data), 1000)
        if stdev > 0:
            gaussian = (1 / (stdev * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x - mean) / stdev) ** 2)
            gaussian = gaussian * len(data) * (max(data) - min(data)) / 20  # Scale Gaussian to match event count
        else:
            gaussian = np.zeros_like(x)
    if discrete:
        # For discrete data, use bar plot instead of histogram
        unique_values, counts = np.unique(data, return_counts=True)
        plt.bar(unique_values, counts, alpha=0.6, color='blue')
        # Show all integer values in the range on the X axis
        plt.xticks(range(int(min(unique_values)), int(max(unique_values)) + 1))
        # Format Y axis to use only integers
        plt.gca().yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    else:
        plt.hist(data, bins=20, alpha=0.6, color='blue', range=interval)
        # Format Y axis to use only integers
        plt.gca().yaxis.set_major_locator(plt.MaxNLocator(integer=True))

    if gaussian is not None:
        # plt.plot(x, gaussian, color='red', label=f'Gaussian\nMean={mean:.2f}, Stdev={stdev:.2f}')
        plt.plot(x, gaussian, color='red', alpha=0, label=f'Average={mean:.2f}')
        if not quiet:
            plt.legend()
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel('Cards')
    # Format X axis if data values are large
    if max(data) > 1000:
        def format_large_ticks(x, _):
            return f"{int(x / 1000)}k" if x >= 1000 else str(int(x))
        plt.gca().xaxis.set_major_formatter(plt.FuncFormatter(format_large_ticks))


def parse_log_file(file_path, debug=False):
    """Parse the log file and extract relevant statistics."""
    results = []
    with open(file_path, "r") as file:
        block, tears, hd, total_auths, time_spent = None, None, None, None, None
        for line in file:
            block_match = re.search(r"Block\s+(\d+)\s+\(0x[0-9A-Fa-f]+\)", line)
            if block_match:
                block = int(block_match.group(1))
                if debug:
                    print(f"Block: {block}")
            tears_match = re.search(r"Tears:\s+\d+\*\d+ms\s+\+\s+(\d+)\*\d+ms", line)
            if tears_match:
                tears = int(tears_match.group(1))
                if debug:
                    print(f"Tears: {tears}")
            hd_match = re.search(r"HW=(\d+)", line)
            if hd_match:
                hd = int(hd_match.group(1))
                if debug:
                    print(f"HD: {hd}")
            auths_match = re.search(r"Total authentications:\s+(\d+)", line)
            if auths_match:
                total_auths = int(auths_match.group(1))
                if debug:
                    print(f"Authentications: {total_auths}")
            time_match = re.search(r"Time spent since start:\s+(\d+)\s+minutes\s+([\d.]+)\s+seconds", line)
            if time_match:
                minutes = int(time_match.group(1))
                seconds = float(time_match.group(2))
                time_spent = minutes * 60 + seconds
                if debug:
                    print(f"Time Spent: {time_spent:.2f} seconds")
            if "finished" in line:
                if block is not None:
                    if tears is not None and hd is not None and total_auths is not None and time_spent is not None:
                        results.append({
                            "Block": block,
                            "HD": hd,
                            "Authentications": total_auths,
                            "Time Spent": time_spent,
                            "Tears": tears
                        })
                    else:
                        results.append({
                            "Block": block,
                            "HD": 0,
                            "Authentications": 0,
                            "Time Spent": 0,
                            "Tears": 0
                        })
                block, tears, hd, total_auths, time_spent = None, None, None, None, None
    return results


def extract_block_data(parsed_data, blocks):
    """Extract data for specific blocks."""
    hd_values = []
    auths_values = []
    time_values = []
    tears_values = []
    for entry in parsed_data:
        if entry["Block"] in blocks:
            hd_values.append(entry["HD"])
            auths_values.append(entry["Authentications"])
            if entry["Block"] < 44:
                speed = 80
                time_values.append(entry["Authentications"] / speed)
            else:
                time_values.append(entry["Time Spent"])
            tears_values.append(entry["Tears"])
    return {
        "Blocks": blocks,
        "HD": hd_values,
        "Authentications": auths_values,
        "Time Spent": time_values,
        "Tears": tears_values
    }


def extract_global_xmin_xmax(all_blocks_data):
    """Extract global min and max values for each type of data."""
    global_xmin_xmax = {
        "HD": {"min": min(all_blocks_data["HD"]),
               "max": max(all_blocks_data["HD"])},
        "Tears": {"min": min(all_blocks_data["Tears"]),
                  "max": max(all_blocks_data["Tears"])},
        "Authentications": {"min": min(all_blocks_data["Authentications"]),
                            "max": max(all_blocks_data["Authentications"])},
        "Time Spent (seconds)": {"min": min(all_blocks_data["Time Spent"]),
                                 "max": max(all_blocks_data["Time Spent"])}
    }
    return global_xmin_xmax


def extract_global_ymin_ymax(parsed_data, blocks):
    """Extract global min and max values for the Y-axis (event counts)."""
    global_ymin_ymax = {
        "HD": {"min": 0, "max": 0},
        "Tears": {"min": 0, "max": 0},
        "Authentications": {"min": 0, "max": 0},
        "Time Spent (seconds)": {"min": 0, "max": 0}
    }
    # Note: not computing the mins at the moment...
    for block in blocks:
        block_data = extract_block_data(parsed_data, blocks=[block])
        global_ymin_ymax["HD"]["max"] = max(global_ymin_ymax["HD"]["max"],
                                            max(np.histogram(block_data["HD"], bins=20)[0]))
        global_ymin_ymax["Tears"]["max"] = max(global_ymin_ymax["Tears"]["max"],
                                               max(np.histogram(block_data["Tears"], bins=20)[0]))
        global_ymin_ymax["Authentications"]["max"] = max(global_ymin_ymax["Authentications"]["max"],
                                                         max(np.histogram(block_data["Authentications"], bins=20)[0]))
        global_ymin_ymax["Time Spent (seconds)"]["max"] = max(global_ymin_ymax["Time Spent (seconds)"]["max"],
                                                              max(np.histogram(block_data["Time Spent"], bins=20)[0]))

    return global_ymin_ymax


def print_stats(parsed_data, blocks):
    """Print statistics for the extracted data."""
    block_data = extract_block_data(parsed_data, blocks=blocks)
    stats = {
        "HD": {
            "mean": statistics.mean(block_data["HD"]),
            "stdev": statistics.stdev(block_data["HD"]) if len(block_data["HD"]) > 1 else 0
        },
        "Tears": {
            "mean": statistics.mean(block_data["Tears"]),
            "stdev": statistics.stdev(block_data["Tears"]) if len(block_data["Tears"]) > 1 else 0
        },
        "Authentications": {
            "mean": statistics.mean(block_data["Authentications"]),
            "stdev": statistics.stdev(block_data["Authentications"]) if len(block_data["Authentications"]) > 1 else 0
        },
        "Time Spent (seconds)": {
            "mean": statistics.mean(block_data["Time Spent"]),
            "stdev": statistics.stdev(block_data["Time Spent"]) if len(block_data["Time Spent"]) > 1 else 0
        }
    }
    print(f"Statistics over {len(block_data['HD'])} tests (Block(s): {block_data['Blocks']}):")
    for key, value in stats.items():
        print(f"{key:25}: Mean = {value['mean']:10.2f}, Standard Deviation = {value['stdev']:10.2f}")
    kps = stats['Authentications']['mean'] / stats['Time Spent (seconds)']['mean']
    print(f"Brute-force speed        : {kps:.2f} auths/s")


def plot_stats(parsed_data, blocks, title_suffix=""):
    """Plot statistics for the extracted data."""
    block_data = extract_block_data(parsed_data, blocks=blocks)
    hd_values = block_data["HD"]
    tears_values = block_data["Tears"]
    auths_values = block_data["Authentications"]
    time_values = block_data["Time Spent"]

    plt.figure(figsize=(10, 10))  # Increase figure height for more space between rows
    plt.subplot(2, 2, 1)
    plot_data_with_gaussian(hd_values, "", "Recovered Bits", discrete=True)
    plt.subplot(2, 2, 2)
    plot_data_with_gaussian(tears_values, "", "Tearing Operations", discrete=True)
    plt.subplot(2, 2, 3)
    plot_data_with_gaussian(auths_values, "", "Authentications")
    plt.subplot(2, 2, 4)
    plot_data_with_gaussian(time_values, "", "Time Spent (seconds)")
    plt.tight_layout(pad=3.0)
    return plt


def plot_stats_row(row_index, nblocks, block_data, global_xmin_xmax, global_ymin_ymax, title_suffix=""):
    """Plot statistics for the extracted data with consistent scales."""
    hd_values = block_data["HD"]
    tears_values = block_data["Tears"]
    auths_values = block_data["Authentications"]
    time_values = block_data["Time Spent"]

    plt.subplot(nblocks, 4, 1 + row_index * 4)
    plot_data_with_gaussian(hd_values, f"Hamming Distance (HD) {title_suffix}", "HD",
                            discrete=True, quiet=True, interval=global_xmin_xmax["HD"])
    plt.xlim(-0.5, global_xmin_xmax["HD"]["max"] + 0.5)
    plt.ylim(0, global_ymin_ymax["HD"]["max"]*1.1)

    plt.subplot(nblocks, 4, 2 + row_index * 4)
    plot_data_with_gaussian(tears_values, f"Tears {title_suffix}", "Tears",
                            quiet=True, interval=global_xmin_xmax["Tears"])
    plt.xlim(0, global_xmin_xmax["Tears"]["max"])
    plt.ylim(0, global_ymin_ymax["Tears"]["max"]*1.1)

    plt.subplot(nblocks, 4, 3 + row_index * 4)
    plot_data_with_gaussian(auths_values, f"Authentications {title_suffix}", "Authentications",
                            quiet=True, interval=global_xmin_xmax["Authentications"])
    plt.xlim(0, global_xmin_xmax["Authentications"]["max"])
    plt.ylim(0, global_ymin_ymax["Authentications"]["max"]*1.1)

    plt.subplot(nblocks, 4, 4 + row_index * 4)
    plot_data_with_gaussian(time_values, f"Time Spent {title_suffix}", "Time Spent (seconds)",
                            quiet=True, interval=global_xmin_xmax["Time Spent (seconds)"])
    plt.xlim(0, global_xmin_xmax["Time Spent (seconds)"]["max"])
    plt.ylim(0, global_ymin_ymax["Time Spent (seconds)"]["max"]*1.1)


def plot_stats_individual(parsed_data, blocks):
    """Plot statistics for individual blocks."""
    all_blocks_data = extract_block_data(parsed_data, blocks=blocks)
    global_xmin_xmax = extract_global_xmin_xmax(all_blocks_data)
    global_ymin_ymax = extract_global_ymin_ymax(parsed_data, blocks=blocks)
    plt.figure(figsize=(12, 2*len(blocks)))
    plt.rcParams.update({'font.size': 8})
    plt.subplots_adjust(hspace=1, wspace=0.5)  # Add more space between rows and columns
    for block in blocks:
        block_data = extract_block_data(parsed_data, blocks=[block])
        plot_stats_row(blocks.index(block), len(blocks), block_data,
                       global_xmin_xmax, global_ymin_ymax, title_suffix=f"(Block {block})")
    return plt
