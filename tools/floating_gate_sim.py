#!/usr/bin/env python3
"""
Floating Gate Charge Decay Simulator with Mask Calculation
Simulates the charge decay of a multi-bit floating gate memory cell.
Each gate decays at its own random rate based on physical properties.
Calculates a mask of identified bits.
"""

import matplotlib.pyplot as plt
import matplotlib.animation as animation
import numpy as np
import sys
import argparse


class FloatingGateSimulator:
    DECAY_MODELS = {
        358: (0.101, 0.157),   # %/tear  (slowest, fastest)
        355: (0.073, 0.103),
        351: (0.0338, 0.0557),
        350: (0.0334, 0.0437),
        347: (0.0120, 0.0278),
        345: (0.0112, 0.0202),
    }

    def __init__(self, bit_values, num_gates=None, target_hw=2):
        """
        Initialize the floating gate simulator.

        Args:
            bit_values: String of binary bits (e.g., "1"*84)
            num_gates: Expected number of gates (if None, uses length of bit_values)
            target_hw: Target hamming weight to tear down to (default: 2)
        """
        if num_gates is None:
            num_gates = len(bit_values)

        if len(bit_values) != num_gates or not all(b in '01' for b in bit_values):
            raise ValueError(f"Bit values must be exactly {num_gates} binary digits (0 or 1)")

        self.num_gates = num_gates
        self.bit_values = [int(b) for b in bit_values]
        self.target_hw = target_hw

        # Initialize charge levels: 1 = 100%, 0 = 0%
        self.charge_levels = np.array([100.0 if b == 1 else 0.0 for b in self.bit_values])

        # Random decay rates for each gate (percent per time unit)
        # All gates get decay rates, even those starting at 0
        np.random.seed()
        low, high = self.DECAY_MODELS[347]
        self.decay_rates = np.array([
            np.random.uniform(low*20, high*20)  # Run it faster (* 20)
            for _ in self.bit_values
        ])

        self.threshold = 50.0
        self.paused = False
        self.tear_count = 0

        # State tracking for target HW and second phase
        self.hw_target_reached = False
        self.hw_target_tear_count = 0
        self.hw_target_one_bits = []
        self.hw_target_zero_bits = []
        self.second_phase = False
        self.second_phase_target = 0

        # Mask calculation
        self.mask = ['?'] * self.num_gates

        # Validate initial hamming weight vs target
        initial_hw = self.hamming_weight()
        if initial_hw <= self.target_hw:
            raise ValueError(f"Initial Hamming weight ({initial_hw}) must be greater than target HW ({self.target_hw})."
                             " Tearing can only decrease charge, not increase it.")

        print("Initial bit pattern:", ''.join(map(str, self.bit_values)))
        print(f"Initial Hamming weight: {initial_hw}, Target HW: {self.target_hw}")
        print("Charge loss per tear event (% per tear):")
        for i, rate in enumerate(self.decay_rates):
            print(f"  Gate {i}: {rate:.3f}%")

    def hamming_weight(self):
        """Calculate current Hamming weight (number of bits above threshold)"""
        return np.sum(self.charge_levels > self.threshold)

    def calculate_mask(self):
        """
        Calculate mask based on both phases:
        - '1': bit was 1 at target HW (reliable high bit - holds charge well)
        - '0': bit was 0 at target HW but is 1 after phase 2 (unreliable - doesn't hold charge well)
        - '?': unknown (bit was 0 in both phases)
        """
        phase2_one_bits = [i for i in range(self.num_gates)
                           if self.charge_levels[i] > self.threshold]

        for i in range(self.num_gates):
            if i in self.hw_target_one_bits:
                # Bit was 1 at target HW - reliable
                self.mask[i] = '1'
            elif i in self.hw_target_zero_bits and i in phase2_one_bits:
                # Bit was 0 at target HW but 1 after phase 2 - unreliable
                self.mask[i] = '0'
            else:
                # Unknown - bit was 0 in both phases
                self.mask[i] = '?'

        return ''.join(self.mask)

    def update(self, frame):
        """Update function for animation - each call represents a tear event"""
        if self.paused:
            return

        # Each frame represents one tear event
        # Reduce charge by the fixed decay rate for each gate
        # Ensure charge never goes below 0
        self.charge_levels = np.maximum(0.0, self.charge_levels - self.decay_rates)
        self.tear_count += 1

        # Check Hamming weight
        hw = self.hamming_weight()

        # First phase: tearing until target HW is reached (or passed)
        if not self.hw_target_reached and hw <= self.target_hw:
            self.hw_target_reached = True
            self.hw_target_tear_count = self.tear_count

            # Log all 1 bits (gates above threshold)
            self.hw_target_one_bits = [i for i in range(self.num_gates)
                                       if self.charge_levels[i] > self.threshold]

            # Log all 0 bits (gates below threshold)
            self.hw_target_zero_bits = [i for i in range(self.num_gates)
                                        if self.charge_levels[i] <= self.threshold]
            print(f"\n*** TARGET HW={self.target_hw} REACHED (actual HW={hw}) ***")
            print(f"Tear events to reach target: {self.hw_target_tear_count}")
            print(f"1 bits (gates above threshold): {self.hw_target_one_bits}")
            print(f"0 bits (gates below threshold): {self.hw_target_zero_bits}")
            print(f"Current charge levels: {self.charge_levels}")
            print(f"Current bit pattern: {''.join(['1' if c > self.threshold else '0' for c in self.charge_levels])}")

            # Refill all gates to 100%
            print("\n*** REFILLING ALL GATES TO 100% ***")
            self.charge_levels = np.full(self.num_gates, 100.0)

            # Enter second phase
            self.second_phase = True
            self.second_phase_target = self.tear_count + self.hw_target_tear_count
            print(f"Starting second tear phase, will tear {self.hw_target_tear_count} more times")
            print(f"Target tear count: {self.second_phase_target}")

        # Second phase: tear the same number of times as it took to reach target HW
        elif self.second_phase and self.tear_count >= self.second_phase_target:
            self.paused = True

            # Calculate mask
            mask = self.calculate_mask()

            phase2_one_bits = [i for i in range(self.num_gates)
                               if self.charge_levels[i] > self.threshold]
            phase2_zero_bits = [i for i in range(self.num_gates)
                                if self.charge_levels[i] <= self.threshold]

            # Identify the 0 bits in mask (unreliable bits)
            unreliable_bits = [i for i in range(self.num_gates)
                               if i in self.hw_target_zero_bits and i in phase2_one_bits]

            print("\n*** SIMULATION PAUSED ***")
            print(f"Second phase completed after {self.tear_count} total tear events")
            print(f"({self.hw_target_tear_count} tears in first phase + "
                  f"{self.hw_target_tear_count} tears in second phase)")
            print("\nPhase 2 Results:")
            print(f"1 bits after phase 2: {phase2_one_bits}")
            print(f"0 bits after phase 2: {phase2_zero_bits}")
            print("\nMask Calculation:")
            print(f"Bits marked as '1' (reliable - were 1 at HW={self.target_hw}): {self.hw_target_one_bits}")
            print(f"Bits marked as '0' (unreliable - were 0 at HW={self.target_hw}, "
                  f"but 1 after phase 2): {unreliable_bits}")
            print("Bits marked as '?' (unknown - were 0 in both phases)")
            print(f"\n{'='*60}")
            print(f"MASK VALUE: {mask}")
            print(f"{'='*60}")
            print(f"\nFinal Hamming weight: {hw}")
            print(f"Final charge levels: {self.charge_levels}")
            print(f"Final bit pattern: {''.join(['1' if c > self.threshold else '0' for c in self.charge_levels])}")

    def animate(self):
        """Create and run the animation"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8))
        fig.suptitle(f'Floating Gate Charge Decay - EEPROM Tearing Simulation with Mask ({self.num_gates} bits)',
                     fontsize=14, fontweight='bold')

        # Color map for bars
        colors = ['#2ecc71' if b == 1 else '#95a5a6' for b in self.bit_values]

        # Create text object for status - will be updated each frame to avoid artifacts
        status_text_obj = fig.text(0.5, 0.02, '', ha='center', fontsize=10,
                                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        def animate_frame(frame):
            self.update(frame)

            # Clear axes
            ax1.clear()
            ax2.clear()

            # Plot 1: Bar chart of charge levels
            bars = ax1.bar(range(self.num_gates), self.charge_levels, color=colors,
                           edgecolor='none', linewidth=0, alpha=0.8, width=1.0)

            # Color bars based on current state
            # Orange for weak bits (within ±1% of threshold)
            weak_bit_margin = 1.0
            for i, bar in enumerate(bars):
                charge = self.charge_levels[i]
                if abs(charge - self.threshold) <= weak_bit_margin:
                    bar.set_color('#ff8c00')  # Orange for weak bit (±1% of threshold)
                elif charge > self.threshold:
                    bar.set_color('#2ecc71')  # Green for above threshold
                else:
                    bar.set_color('#e74c3c')  # Red for below threshold

            # Add threshold line and weak bit zone
            ax1.axhline(y=self.threshold, color='orange', linestyle='--',
                        linewidth=2, label='Threshold (50%)')
            ax1.axhspan(self.threshold - weak_bit_margin, self.threshold + weak_bit_margin,
                        color='orange', alpha=0.1, label='Weak Bit Zone (±1%)')

            # Add reference lines
            ax1.axhline(y=0, color='gray', linestyle='-', linewidth=0.5, alpha=0.3)
            ax1.axhline(y=100, color='gray', linestyle='-', linewidth=0.5, alpha=0.3)

            # Labels and formatting
            ax1.set_xlabel('Gate Number', fontsize=12)
            ax1.set_ylabel('Charge Level (%)', fontsize=12)
            ax1.set_ylim(-5, 105)
            ax1.set_xlim(-1, self.num_gates)
            # Show only every 10th gate label
            tick_positions = list(range(0, self.num_gates, 10))
            ax1.set_xticks(tick_positions)
            ax1.set_xticklabels([f'{i}' for i in tick_positions], fontsize=9)
            ax1.legend(loc='upper right', fontsize=10)
            ax1.grid(axis='y', alpha=0.3)

            # Plot 2: Time series of charge levels (stepwise for discrete tear events)
            if not hasattr(self, 'history_tears'):
                self.history_tears = []
                self.history_charges = [[] for _ in range(self.num_gates)]

            self.history_tears.append(self.tear_count)
            for i in range(self.num_gates):
                self.history_charges[i].append(self.charge_levels[i])

            # Only plot a sample of gates to avoid cluttering
            # Find all gates that started with charge
            gates_with_charge = [i for i in range(self.num_gates) if self.bit_values[i] == 1]

            # Sample up to 10 gates evenly distributed
            if len(gates_with_charge) > 10:
                step = len(gates_with_charge) // 10
                sampled_gates = gates_with_charge[::step][:10]
            else:
                sampled_gates = gates_with_charge

            # Plot the sampled gates
            for i in sampled_gates:
                ax2.step(self.history_tears, self.history_charges[i],
                         label=f'Gate {i}', linewidth=1.5, where='post', alpha=0.8)

            ax2.axhline(y=self.threshold, color='orange', linestyle='--',
                        linewidth=2, label='Threshold')
            ax2.set_xlabel('Tear Events', fontsize=12)
            ax2.set_ylabel('Charge Level (%)', fontsize=12)
            ax2.set_ylim(-5, 105)
            ax2.legend(loc='upper right', ncol=3, fontsize=9)
            ax2.grid(alpha=0.3)

            # Status text
            hw = self.hamming_weight()
            weak_bits = np.sum(np.abs(self.charge_levels - self.threshold) <= 1.0)

            # Determine phase
            if self.second_phase:
                phase_text = 'PHASE 2 (Refilled & Tearing: '
                phase_text += f'{self.tear_count - self.hw_target_tear_count}/{self.hw_target_tear_count})'
            elif self.hw_target_reached:
                phase_text = 'TRANSITION (Refilling...)'
            else:
                phase_text = f'PHASE 1 (Tearing to HW={self.target_hw})'

            # Build status text - truncate bit pattern if too long
            bit_pattern = "".join(["1" if c > self.threshold else "0" for c in self.charge_levels])
            if len(bit_pattern) > 40:
                bit_pattern_display = f"{bit_pattern[:20]}...{bit_pattern[-20:]}"
            else:
                bit_pattern_display = bit_pattern

            status_text = f'{phase_text} | Tears: {self.tear_count} | HW: {hw} | Weak: {weak_bits}'
            if self.paused:
                mask_str = ''.join(self.mask)
                if len(mask_str) > 40:
                    mask_display = f"{mask_str[:20]}...{mask_str[-20:]}"
                else:
                    mask_display = mask_str
                status_text += f' | MASK: {mask_display} | *** PAUSED ***'

            # Update text object instead of creating new one (prevents artifacts)
            status_text_obj.set_text(status_text)

            plt.tight_layout(rect=[0, 0.04, 1, 0.97])

        # Create animation - each frame is one tear event
        anim = animation.FuncAnimation(fig, animate_frame, interval=200, 
                                       cache_frame_data=False, repeat=False)

        plt.show()


def main():
    parser = argparse.ArgumentParser(
        description='Simulate floating gate charge decay for a multi-bit memory cell with mask calculation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 84 bits - all 1s, tear to HW=2 (default)
  python floating_gate_sim8.py $(python3 -c \
    "print('1'*84)")

  # 84 bits - alternating pattern
  python floating_gate_sim8.py $(python3 -c \
    "print('10'*42)")

  # 84 bits - random
  python floating_gate_sim8.py $(python3 -c \
    "import random; print(''.join(random.choice('01') for _ in range(84)))")

  # 128 bits - random, tear to HW=3
  python floating_gate_sim8.py -n 128 --target-hw 3 $(python3 -c \
    "import random; print(''.join(random.choice('01') for _ in range(128)))")

  # 84 bits - random, tear to HW=5
  python floating_gate_sim8.py --target-hw 5 $(python3 -c \
    "import random; print(''.join(random.choice('01') for _ in range(84)))")
        """)

    parser.add_argument('bits', type=str, help='Binary value (string of 0s and 1s)')
    parser.add_argument('-n', '--num-gates', type=int, default=None,
                        help='Expected number of gates (default: auto-detect from bit string length)')
    parser.add_argument('--target-hw', type=int, default=2,
                        help='Target Hamming weight to tear down to (must be less than initial HW, default: 2)')

    args = parser.parse_args()

    try:
        simulator = FloatingGateSimulator(args.bits, num_gates=args.num_gates, target_hw=args.target_hw)
        simulator.animate()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSimulation interrupted by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
