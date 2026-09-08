"""
DNS Feature Analyzer for DGA & DNS Tunneling Extraction (FR3).
"""

import math
from collections import Counter
from typing import Dict, Any, List

class DNSAnalyzer:
    def __init__(self, ngram_n: int = 3):
        self.ngram_n = ngram_n

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy of string (bits per symbol)."""
        if not text:
            return 0.0
        prob = [float(count) / len(text) for count in Counter(text).values()]
        return -sum(p * math.log2(p) for p in prob)

    def calculate_ngram_score(self, domain: str) -> float:
        """
        Calculates character n-gram irregularity score.
        Higher score indicates non-human / random string generation.
        """
        clean_domain = domain.split('.')[0].lower()
        if len(clean_domain) < self.ngram_n:
            return 0.0
        
        # Simple vowel-to-consonant ratio anomaly & digit ratio metric
        digits = sum(1 for c in clean_domain if c.isdigit())
        consonants = sum(1 for c in clean_domain if c.isalpha() and c not in 'aeiou')
        vowels = sum(1 for c in clean_domain if c in 'aeiou')
        
        digit_ratio = digits / len(clean_domain)
        consonant_vowel_ratio = consonants / max(1, vowels)
        
        score = (digit_ratio * 2.0) + (0.5 if consonant_vowel_ratio > 3.5 else 0.0)
        return min(1.0, round(score, 4))

    def analyze_queries(self, queries: List[str]) -> Dict[str, Any]:
        """Analyzes a list of DNS domain names from a flow."""
        if not queries:
            return {
                "dns_query_count": 0,
                "dns_mean_entropy": 0.0,
                "dns_max_entropy": 0.0,
                "dns_mean_length": 0.0,
                "dns_ngram_score": 0.0,
                "dns_tunneling_flag": False
            }

        entropies = [self.calculate_shannon_entropy(q) for q in queries]
        lengths = [len(q) for q in queries]
        ngram_scores = [self.calculate_ngram_score(q) for q in queries]

        mean_entropy = round(sum(entropies) / len(entropies), 4)
        max_entropy = round(max(entropies), 4)
        mean_length = round(sum(lengths) / len(lengths), 2)
        mean_ngram = round(sum(ngram_scores) / len(ngram_scores), 4)

        # Tunneling heuristic: High max entropy (>3.8), long domain (>35 chars), or high n-gram randomness score
        tunneling_flag = (max_entropy > 3.85 and mean_length > 25) or mean_ngram > 0.60 or mean_length > 45

        return {
            "dns_query_count": len(queries),
            "dns_mean_entropy": mean_entropy,
            "dns_max_entropy": max_entropy,
            "dns_mean_length": mean_length,
            "dns_ngram_score": mean_ngram,
            "dns_tunneling_flag": tunneling_flag
        }
