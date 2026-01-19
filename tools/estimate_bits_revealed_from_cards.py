#!/usr/bin/env python3

import mpmath as mp
import random


def binom_real(n, m):
    """Calculate the binomial coefficient C(n, m) for real m using gamma function."""
    # To be use instead of math.comb to work on floats
    # C(x, y) = Γ(x + 1) / (Γ(y + 1) Γ(x − y + 1))
    return float(mp.gamma(n+1)/(mp.gamma(m+1)*mp.gamma(n-m+1)))


def expected_unique_cards(n=14, cards_per_draw=3, num_draws=6):
    """Estimate the expected number of unique cards revealed
    when drawing `cards_per_draw` cards from a total of `n` cards, over `num_draws` draws.

    Args:
        n (int): Total number of unique cards.
        cards_per_draw (int): Number of cards drawn in each draw.
        num_draws (int): Total number of draws.
    Returns:
        float: Expected number of unique cards revealed.
    """
    # Probability a specific card is not drawn in one draw
    p_not_in_one_draw = binom_real(n-1, cards_per_draw) / binom_real(n, cards_per_draw)
    # Probability not drawn in any of the num_draws
    p_never_drawn = p_not_in_one_draw ** num_draws
    # So expected number of cards seen at least once:
    expected = n * (1 - p_never_drawn)
    return expected


def simulate_unique_cards(n=14, cards_per_draw=3, num_draws=6, trials=100_000):
    """Monte Carlo simulation to estimate the expected number of unique cards revealed."""
    results = []
    deck = list(range(n))
    for _ in range(trials):
        revealed = set()
        for _ in range(num_draws):
            revealed.update(random.sample(deck, cards_per_draw))
        results.append(len(revealed))
    return sum(results) / len(results)


for n, k, d in [
     (14, 3, 6), (14, 3, 7),
     (14, 2, 10),
     (14, 1.55, 13), (14, 1.55, 14),
     (16, 3, 8),
     (16, 2, 12), (16, 2, 13)
     ]:
    E = expected_unique_cards(n, k, d)
    print(f"E({n:2}, {k:2}, {d:2}): {E:5.2f}, remains: {n - E:5.2f} bits to find")
    # print("Monte Carlo estimate:", simulate_unique_cards(n, k, d))
