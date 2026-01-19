#!/usr/bin/env python3
"""Parse the log file and extract relevant statistics."""

from recover_key_bits_tests_log_parse import parse_log_file
from recover_key_bits_tests_log_parse import print_stats, plot_stats


parsed_data = parse_log_file("recover_key_bits_tests_fast_combined_hw2.log")
blocks = range(44, 48)

print_stats(parsed_data, blocks)
plt = plot_stats(parsed_data, blocks)
plt.savefig("recover_key_bits_tests_fast_combined_hw2_graph_global.png", bbox_inches='tight')
# Save the plot as a PGFPlots-compatible file
plt.savefig("recover_key_bits_tests_fast_combined_hw2_graph_global.pgf", bbox_inches='tight')
plt.show()
