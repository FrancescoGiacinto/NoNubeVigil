from enum import Enum


class Severity(Enum):
    """
    Five-level severity scale aligned with CVSS and common SAST tools.

    Ordering is intentional — higher ordinal = higher severity.
    Used for sorting, filtering, and color coding in CLIFormatter.
    """
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value

    def __le__(self, other: "Severity") -> bool:
        return self.value <= other.value

    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value

    def __ge__(self, other: "Severity") -> bool:
        return self.value >= other.value

    @property
    def color(self) -> str:
        """ANSI color code for CLIFormatter."""
        return {
            Severity.INFO:     "\033[36m",   # cyan
            Severity.LOW:      "\033[34m",   # blue
            Severity.MEDIUM:   "\033[33m",   # yellow
            Severity.HIGH:     "\033[31m",   # red
            Severity.CRITICAL: "\033[35m",   # magenta
        }[self]

    @property
    def label(self) -> str:
        """Fixed-width label for aligned terminal output."""
        return f"{self.name:<8}"