#!/usr/bin/env python3

def swap_mifare_key(key_hex):
    """
    Swaps the endianness of a MIFARE Ultralight C key.
    Input should be a string of 32 hex characters (16 bytes).
    Returns the swapped key as a hex string.
    """
    # Validate input length
    if len(key_hex) != 32:
        raise ValueError("Key must be exactly 32 hex characters (16 bytes)")

    # Convert to uppercase and validate hex characters
    key_hex = key_hex.upper()
    if not all(c in '0123456789ABCDEF' for c in key_hex):
        raise ValueError("Key must contain only valid hex characters")

    # Split into 4-byte blocks
    blocks = [
        key_hex[0:8],    # Block 1
        key_hex[8:16],   # Block 2
        key_hex[16:24],  # Block 3
        key_hex[24:32]   # Block 4
    ]

    # Reverse bytes within each block
    reversed_blocks = []
    for block in blocks:
        # Split into pairs of hex chars (bytes) and reverse their order
        bytes_in_block = [block[i:i+2] for i in range(0, 8, 2)]
        reversed_block = ''.join(bytes_in_block[::-1])
        reversed_blocks.append(reversed_block)

    # Arrange blocks in the specified order: block2, block1, block4, block3
    result = reversed_blocks[1] + reversed_blocks[0] + reversed_blocks[3] + reversed_blocks[2]

    return result


def run_tests():
    """
    Simple unit test for the key swapping function.
    """
    # Test case 1: "BREAKMEIFYOUCAN!"
    #test_key = "425245414B4D454946594F5543414E21"
    #expected = "49454D4B41455242214E4143554F5946"
    #test_key = "CA7A9C26167E7A9670EA40649CEC64DE"
    #expected = "967A7E16269C7ACADE64EC9C6440EA70"
    test_key = "DC36E08C5862945ED228281414BA30DA"
    expected = "13371337133713371337133713371337"

    try:
        result = swap_mifare_key(test_key)
        assert result == expected, f"\nExpected: {expected}\nGot: {result}"
        print("Test passed!")
        print(f"Input key:  {test_key}")
        print(f"Swapped key: {result}")
    except AssertionError as e:
        print("Test failed!", e)
    except Exception as e:
        print("Error:", str(e))


if __name__ == "__main__":
    run_tests()
