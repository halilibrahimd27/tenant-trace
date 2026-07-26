"""Joins the two engines.

Maps a static hypothesis to the endpoints that reach it, hands those to the
prober as targeted probes, and merges the results:

    static + confirmed -> correlated   (ranked highest)
    probe only         -> confirmed
    static only        -> suspected
"""
