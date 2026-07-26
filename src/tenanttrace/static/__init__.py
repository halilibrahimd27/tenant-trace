"""Static engine — per-language, generates hypotheses for the prober.

Parses source; never imports or executes it. AST plus intraprocedural dataflow
only — no symbolic execution, no whole-program analysis.

Everything this engine emits is `suspected` until the prober confirms it.
"""
