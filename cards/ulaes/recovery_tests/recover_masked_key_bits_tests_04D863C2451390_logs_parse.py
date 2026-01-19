#!/usr/bin/env python3
"""Parse the log file and extract relevant statistics."""

from recover_masked_key_bits_tests_log_parse import parse_log_file
from recover_masked_key_bits_tests_log_parse import print_stats, plot_stats, plot_stats_individual

uid = "04D863C2451390"

for hw in [2, 3]:
    parsed_data = parse_log_file(f"recover_masked_key_bits_tests_{uid}_hw{hw}.log")
    blocks = range(48, 56)
    # "fast" blocks on Phil's card 043C67C2451390
    # blocks = [48, 51, 52, 55]
    # Plot stats for all blocks
    print_stats(parsed_data, blocks)
    plt = plot_stats(parsed_data, blocks)
    plt.savefig(f"recover_masked_key_bits_tests_{uid}_hw{hw}_graph_global.png")
    # Plot stats for each individual block
    plt = plot_stats_individual(parsed_data, blocks)
    plt.savefig(f"recover_masked_key_bits_tests_{uid}_hw{hw}_graph_blocks.png")

for hw in [2, 3]:
    parsed_data = parse_log_file(f"recover_masked_key_bits_tests_{uid}_rfu_hw{hw}.log")
    blocks = range(56, 60)
    # Plot stats for all blocks
    print_stats(parsed_data, blocks)
    plt = plot_stats(parsed_data, blocks)
    plt.savefig(f"recover_masked_key_bits_tests_{uid}_rfu_hw{hw}_graph_global.png")
    # Plot stats for each individual block
    plt = plot_stats_individual(parsed_data, blocks)
    plt.savefig(f"recover_masked_key_bits_tests_{uid}_rfu_hw{hw}_graph_blocks.png")
