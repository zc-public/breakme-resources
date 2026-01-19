#!/usr/bin/env python3

import sys
import json
import os
import numpy as np
from scipy.stats import skewnorm
import argparse
import matplotlib.pyplot as plt

f = 10

i_fibonacci = [0] * (1 << 16)
s_fibonacci = [0] * (1 << 16)


def initialize_fibonacci_mfc(start_x):
    global i_fibonacci, s_fibonacci
    x = start_x
    for i in range(1, 1 << 16):
        i_fibonacci[x] = i
        s_fibonacci[i] = x
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xffff


def initialize_fibonacci_ulcg(start_x):
    global i_fibonacci, s_fibonacci
    x = start_x
    x = (x << 15 | x >> 1) & 0xffff
    for i in range(0, 1 << 16):
        i_fibonacci[(x << 1 | x >> 15) & 0xffff] = i
        s_fibonacci[i] = (x << 1 | x >> 15) & 0xffff
        x = (x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15) & 0xffff


def nonce_distance_fibonacci(nt16from, nt16to):
    return (65535 + i_fibonacci[nt16to] - i_fibonacci[nt16from]) % 65535


def validate_nonce(nonce64):
    a = (nonce_distance_fibonacci((nonce64 >> (0*16)) & 0xFFFF, (nonce64 >> (1*16)) & 0xFFFF) == 16)
    b = (nonce_distance_fibonacci((nonce64 >> (1*16)) & 0xFFFF, (nonce64 >> (2*16)) & 0xFFFF) == 16)
    c = (nonce_distance_fibonacci((nonce64 >> (2*16)) & 0xFFFF, (nonce64 >> (3*16)) & 0xFFFF) == 16)
    return a and b and c


def next_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 65535:
        index = 1
    else:
        index += 1
    return s_fibonacci[index]


def prev_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 1:
        index = 65535
    else:
        index -= 1
    return s_fibonacci[index]


def index_of_nonce(nonce):
    return i_fibonacci[nonce & 0xFFFF]


def get_index(challenge):
    return i_fibonacci[int(challenge[:4], 16)]


def stats(jsonfile, max_index=1000, with_skew=False):
    with open(jsonfile, "r") as f:
        challenges = json.load(f)
    plain_challenges = challenges["challenges_0_sorted"]
    freqs = [0] * max_index
    smallest_index = max_index
    largest_index = 0
    for chal, freq in plain_challenges.items():
        i = get_index(chal)
        # assert index is in the first max_index
        if i >= max_index:
            if i >= 2 * max_index:
                print("Abnormal index:", i, chal[:4], chal)
                print("Update the max_index if needed")
            else:
                # we should update the start point of our index
                print("Abnormal index:", i, chal[:4], chal)
                print("Update the start point of index if needed")
        else:
            freqs[i] = freq
            if i < smallest_index:
                smallest_index = i
            if i > largest_index:
                largest_index = i

    population = []
    for i, freq in enumerate(freqs):
        population.extend([i] * freq)
    mean = np.mean(population)
    std_dev = np.std(population)
    x = np.linspace(0, max_index, max_index)
    if with_skew:
        # Fit a skewed normal distribution to the data
        skew, loc, scale = skewnorm.fit(population)
        p = skewnorm.pdf(x, skew, loc, scale)
    else:
        # Fit a normal distribution to the data
        mean, std_dev = np.mean(population), np.std(population)
        p = (1 / (std_dev * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x - mean) / std_dev) ** 2)
        skew = 0.0
        loc = mean
        scale = std_dev
    scaling_factor = np.mean(freqs) / np.mean(p)
    p *= scaling_factor
    max_index_skewed = np.argmax(p)
    print(f'{jsonfile:50s} Mean: {mean:.2f}, Std Dev: {std_dev:.2f}, Peak Index: {max_index_skewed}')
    if with_skew:
        print(f'{jsonfile:50s} Skew: {skew:.2f}, Loc: {loc:.2f}, Scale: {scale:.2f}')
    return freqs, x, p, smallest_index, largest_index, mean, std_dev, skew, max_index_skewed


def generate_wide_graph(jsonfile, stats_results, start_x, max_index=1000,
                        with_skew=False, gauss=True, really_max_index=65535):
    freqs, x, p, smallest_index, largest_index, mean, std_dev, skew, max_index_skewed = stats_results
    indices = list(range(max_index))
    # Set the regions to show
    region1_right_margin = 50
    region2_left_margin = 150 + 35
    region1 = (0, max_index + region1_right_margin)
    region1_size = region1[1] - region1[0]
    region2 = (really_max_index - region2_left_margin, really_max_index)
    region2_size = region2[1] - region2[0]
    dpi = 150  # Dots per inch
    fig, (ax1, ax2) = plt.subplots(1, 2, sharey=True, figsize=(1350 / dpi, 900 / dpi), dpi=dpi,
                                   gridspec_kw={'width_ratios': [region1_size, region2_size]})
    ax1.bar(indices[region1[0]:region1[1]], freqs[region1[0]:region1[1]], width=1, color='blue', alpha=0.6,
            label='Nonces count')
    ax2.bar(indices[region2[0]:region2[1]], freqs[region2[0]:region2[1]], width=1, color='blue', alpha=0.6)
    # Set limits
    ax1.set_xlim(region1)
    ax2.set_xlim(region2)
    # Remove spines for the "break" effect
    ax1.spines['right'].set_visible(False)
    ax2.spines['left'].set_visible(False)
    ax1.yaxis.tick_left()
    ax2.yaxis.tick_right()

    # Add diagonal lines to show the break
    d = .015  # size of diagonal lines
    kwargs = dict(transform=ax1.transAxes, color='k', clip_on=False)
    f = region2_size / region1_size
    ax1.plot([1-d*f, 1+d*f], [-d, +d], **kwargs)
    ax1.plot([1-d*f, 1+d*f], [1-d, 1+d], **kwargs)

    kwargs.update(transform=ax2.transAxes)
    ax2.plot([-d, +d], [-d, +d], **kwargs)
    ax2.plot([-d, +d], [1-d, 1+d], **kwargs)
    if gauss:
        ax1.plot(x, p, 'r', label='Skewed Gaussian fit' if with_skew else 'Gaussian fit')

    ax1.set_xlabel(' '*45 + f'LFSR16 Index (with LFSR16[1] = 0x{start_x:04X})')
    ax1.set_ylabel('Nonces at given index')

    # fig.suptitle(f'File: {os.path.basename(jsonfile)}', fontsize=10)

    ax1.xaxis.set_major_locator(plt.MultipleLocator(100))
    ax1.grid(which='major', axis='x', linestyle='-')
    ax2.xaxis.set_major_locator(plt.MultipleLocator(100))
    ax2.grid(which='major', axis='x', linestyle='-')
    ax1.axvspan(smallest_index, largest_index, color='lightgrey', alpha=0.3)
    handles, labels = ax1.get_legend_handles_labels()
    # Format legend title with aligned values using spaces
    legend_title = ()
    if gauss:
        if with_skew:
            legend_title = (
                f'Mode at:{max_index_skewed:6.0f}\n'
                f'Std Dev:{std_dev:6.0f}\n'
                f'Skew:{skew:11.2f}'
            )
        else:
            legend_title = (
                f'Mean at:{max_index_skewed:6.0f}\n'
                f'Std Dev:{std_dev:6.0f}'
            )
    fig.legend(handles, labels,
               title=legend_title,
               loc='upper right', bbox_to_anchor=(0.88, 0.85))

    plt.savefig(f'frequency_distribution_{os.path.basename(jsonfile)}{"_skew" if with_skew else ""}_wide.png',
                bbox_inches='tight')
    plt.savefig(f'frequency_distribution_{os.path.basename(jsonfile)}{"_skew" if with_skew else ""}_wide.pgf',
                bbox_inches='tight')


def generate_graphs(jsonfiles, stats_results, start_x, max_index=1000,
                    with_skew=False, gauss=True, title=True, grey=True):
    num_files = len(jsonfiles)
    cols = int(np.floor(np.sqrt(num_files)))
    rows = int(np.ceil(num_files / cols))
    dpi = 150 * f  # Dots per inch
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 1000 * f / dpi, rows * 750 * f / dpi), dpi=dpi)
    axes = axes.flatten() if num_files > 1 else [axes]

    for ax, stats_result in zip(axes, stats_results):
        freqs, x, p, smallest_index, largest_index, mean, std_dev, skew, max_index_skewed = stats_result
        indices = list(range(max_index))
        ax.bar(indices, freqs, width=1, color='blue', alpha=0.6, label='Nonces count')
        if gauss:
            ax.plot(x, p, 'r', label='Skewed Gaussian fit' if with_skew else 'Gaussian fit')
        ax.set_xlabel(f'LFSR16 Index (with LFSR16[1] = 0x{start_x:04X})')
        ax.set_ylabel('Nonces at given index')
        if title:
            ax.set_title(f'File: {os.path.basename(jsonfile)}', fontsize=10)
        ax.xaxis.set_major_locator(plt.MultipleLocator(100 if max_index < 4000 else 
                                                       1000 if max_index < 20000 else 10000))
        ax.grid(which='major', axis='x', linestyle='-')
        if grey:
            ax.axvspan(smallest_index, largest_index, color='lightgrey', alpha=0.3)
        if gauss:
            if with_skew:
                ax.legend(title=f'Mode at:   {max_index_skewed:.0f}\nStd Dev: {std_dev:.0f}\n'
                          f'Skew:      {skew:.2f}', loc='upper right')
            else:
                ax.legend(title=f'Mean at:   {max_index_skewed:.0f}\nStd Dev: {std_dev:.0f}', loc='upper right')
        ax.set_xlim(0, max_index)
        ax.set_xlim(0, max_index)

    # Hide any unused subplots
    for i in range(num_files, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout()
    if len(jsonfiles) == 1:
        plt.savefig(f'frequency_distribution_{os.path.basename(jsonfiles[0])}{"_skew" if with_skew else ""}.png',
                    bbox_inches='tight')
        plt.savefig(f'frequency_distribution_{os.path.basename(jsonfiles[0])}{"_skew" if with_skew else ""}.pgf',
                    bbox_inches='tight')
    else:
        plt.savefig('frequency_distribution_combined.png')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze frequency distribution of nonces.")
    parser.add_argument("-j", "--json", required=True, nargs="+",
                        help="Source JSON file(s) containing challenges.")
    parser.add_argument("-s", "--startx", type=lambda x: int(x, 0), required=True,
                        help="Start point of index (e.g., 0x2adb).")
    parser.add_argument("--ulcg", action="store_true",
                        help="Use ULCG LFSR.")
    parser.add_argument("--mfc", action="store_true",
                        help="Use MFC LFSR.")
    parser.add_argument("--skew", action="store_true",
                        help="Enable skewed Gaussian fitting.")
    parser.add_argument("-m", "--max", type=int, default=1000,
                        help="Maximum index value (default: 1000).")
    parser.add_argument("--wide", action="store_true",
                        help="Enable wide mode for graph.")
    parser.add_argument("--no-gauss", action="store_true",
                        help="Disable Gaussian fitting.")
    parser.add_argument("--no-title", action="store_true",
                        help="Disable titles on subplots.")
    parser.add_argument("--no-grey", action="store_true",
                        help="Disable grey highlighting of the smallest and largest indices.")
    parser.add_argument("--no-graph", action="store_true",
                        help="Disable graph generation.")
    args = parser.parse_args()

    if args.ulcg == args.mfc:
        print("Error: You must specify either --ulcg or --mfc, but not both.")
        sys.exit(1)

    if args.wide and len(args.json) > 1:
        print("Error: --wide can only be used with a single JSON file.")
        sys.exit(1)

    if args.ulcg:
        print("Using ULCG LFSR")
        initialize_fibonacci_ulcg(start_x=args.startx)
    else:
        print("Using MFC LFSR")
        initialize_fibonacci_mfc(start_x=args.startx)

    # print(f"0x{s_fibonacci[17172-300]:04x}")
    # exit()

    stats_results = []
    for jsonfile in args.json:
        freqs, x, p, smallest_index, largest_index, mean, std_dev, skew, max_index_skewed = stats(
            jsonfile, args.max, args.skew
        )
        stats_results.append((freqs, x, p, smallest_index, largest_index, mean, std_dev, skew, max_index_skewed))

    if args.no_graph:
        sys.exit(0)

    if args.wide:
        generate_wide_graph(args.json[0], stats_results[0], args.startx, args.max, args.skew, not args.no_gauss)
    else:
        generate_graphs(args.json, stats_results, args.startx, args.max,
                        args.skew, not args.no_gauss, not args.no_title, not args.no_grey)
