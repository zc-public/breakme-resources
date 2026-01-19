#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import pm3


def read_block(p, block):
    """Read a block and return the formatted block data as int."""
    p.console(f'hf mfu rdbl -b {block} --force')
    for line in p.grabbed_output.split('\n'):
        if f"{block}/0x{block:02X}" in line:
            # Extract the block data from the line
            parts = line.split('|')
            if len(parts) >= 2:
                data = parts[1].strip()
                data_int = int(data.replace(" ", ""), 16)
                return data_int
    return None


def tearoff(p, block, delay, data=0x00000000):
    if not hasattr(tearoff, "_last_delay") or tearoff._last_delay != delay:
        p.console(f'hw tearoff --delay {delay}', capture=False)
        tearoff._last_delay = delay
    p.console('hw tearoff --on', capture=False)
    p.console(f'hf 14a raw -sc a2{block:02x}{data:08x}', capture=False)
    data = read_block(p, block)
    assert data is not None
    return data


def hamming_weight(n):
    """Compute the Hamming weight (number of set bits) of an integer."""
    return bin(n).count('1')


def test_tearoff(p, init=0xa5a5a5a5, block=16, step1delay=420, step2delay=380, max_iterations=25, data=0x00000000):
    p.console('hw tearoff --off', capture=False)
    p.console(f'hf mfu wrbl -b {block} -d {init:08x} --force')
    for line in p.grabbed_output.split('\n'):
        if "Block" in line:
            init_bytes = f"{init:08X}"
            formatted_init = " ".join([init_bytes[i:i+2] for i in range(0, 8, 2)])
            assert formatted_init in line, f"Expected {formatted_init} in output, got: {line}"
    p.console(f'hf mfu rdbl -b {block} --force')
    for line in p.grabbed_output.split('\n'):
        if f"{block}/0x{block:02x}" in line:
            init_bytes = f"{init:08X}"
            formatted_init = " ".join([init_bytes[i:i+2] for i in range(0, 8, 2)])
            assert formatted_init in line, f"Expected {formatted_init} in output, got: {line}"

    prev_hw = hamming_weight(init)
    for n in range(1, max_iterations + 1):
        data = tearoff(p, block, step1delay if n == 1 else step2delay, data)
        hw = hamming_weight(data)
        if hw <= 3 and hw != prev_hw:
            print(f"Block {block:2} data after tearoff {n:2} [{step2delay}]: {data:08X} HW={hw:02d}")
        if hw <= 2:
            break
        prev_hw = hw
    else:
        print(f"Block {block:2} data after tearoff {n:2} [{step2delay}]: "
              f"{data:08X} HW={hw:02d} - no low HW<=2 found yet")
    p.console(f'hf 14a raw -sc a2{block:02x}{data:08x}', capture=False)


if __name__ == "__main__":
    p = pm3.pm3()
    init = 0xa5a5a5a5

    # bstart, bstop, step1delay, step2delay = 4, 16, 420, 380
    # print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, "
    #       f"step1delay={step1delay}, step2delay={step2delay}")
    # for block in range(bstart, bstop + 1):
    #     test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)

    # bstart, bstop, step1delay, step2delay = 16, 39, 457, 412
    # print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, "
    #       f"step1delay={step1delay}, step2delay={step2delay}")
    # for block in range(bstart, bstop + 1):
    #     test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)

    # 43 and 44 unwritable? write is ok but content does not change
    # bstart, bstop, step1delay, step2delay = 43, 44, 420, 380
    # print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, "
    #       f"step1delay={step1delay}, step2delay={step2delay}")
    # for block in range(bstart, bstop + 1):
    #     test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)

    # 46 seems to be writable only once, then it cannot be changed, even not like OTP bits
    # bstart, bstop, step1delay, step2delay = 46, 46, 1600, 250
    # print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, "
    #       f"step1delay={step1delay}, step2delay={step2delay}")
    # for block in range(bstart, bstop + 1):
    #     test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)

    # 47 is writable and tearable with delays way shorter
    # bstart, bstop, step1delay, step2delay = 47, 47, 260, 250
    # print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, "
    #       f"step1delay={step1delay}, step2delay={step2delay}")
    # for block in range(bstart, bstop + 1):
    #     test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)

    bstart, bstop, step1delay, step2delay = 56, 59, 260, 250
    print(f"Testing blocks {bstart:2}-{bstop:2} with initial value 0x{init:08X}, step1delay={step1delay}, step2delay={step2delay}")
    for block in range(bstart, bstop + 1):
        test_tearoff(p, init=init, block=block, step1delay=step1delay, step2delay=step2delay)
