"""Transformers for the text MVP.

Transformers are explicit, verifiable operation sets: they turn
matched spans into replacements. Policy decides what to do; transformers only
execute. The registry applies a whole DisclosurePlan right-to-left so span
offsets stay valid.
"""

from .base import TokenRegistry, Transformer, TransformOutcome
from .dates import DateTransformer
from .registry import (
    DEFAULT_TRANSFORMERS,
    TransformerRegistry,
    apply_plan,
)
from .text import TextTransformer

__all__ = [
    "TokenRegistry",
    "TransformOutcome",
    "Transformer",
    "DateTransformer",
    "TextTransformer",
    "DEFAULT_TRANSFORMERS",
    "TransformerRegistry",
    "apply_plan",
]
