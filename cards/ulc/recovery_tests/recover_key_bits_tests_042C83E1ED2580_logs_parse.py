#!/usr/bin/env python3
"""Parse the log file and extract relevant statistics."""

from recover_key_bits_tests_log_parse import parse_log_file
from recover_key_bits_tests_log_parse import print_stats, plot_stats, plot_stats_individual

uid = "042C83E1ED2580"

for hw in [2]:
    parsed_data = parse_log_file(f"recover_key_bits_tests_{uid}_hw{hw}.log")
    blocks = range(44, 48)
    # Plot stats for all blocks
    print_stats(parsed_data, blocks)
    plt = plot_stats(parsed_data, blocks)
    plt.savefig(f"recover_key_bits_tests_{uid}_hw{hw}_graph_global.png")
    # Plot stats for each individual block
    plt = plot_stats_individual(parsed_data, blocks)
    plt.savefig(f"recover_key_bits_tests_{uid}_hw{hw}_graph_blocks.png")

for hw in [2, 3]:
    parsed_data = parse_log_file(f"recover_key_bits_tests_{uid}_rfu_hw{hw}.log")
    blocks = range(8, 12)
    # Plot stats for all blocks
    print_stats(parsed_data, blocks)
    plt = plot_stats(parsed_data, blocks)
    plt.savefig(f"recover_key_bits_tests_{uid}_rfu_hw{hw}_graph_global.png")
    # Plot stats for each individual block
    plt = plot_stats_individual(parsed_data, blocks)
    plt.savefig(f"recover_key_bits_tests_{uid}_rfu_hw{hw}_graph_blocks.png")
