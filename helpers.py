# Bridge to your original helpers if present
def parse_signal(msg: str):
    try:
        import falcon_trade_copier as orig
        if hasattr(orig, 'parse_signal'):
            return orig.parse_signal(msg)
    except Exception:
        pass
    # Fallback simple parse
    import re
    m = re.search(r'([A-Z]{3,6})\s+(BUY|SELL)', msg.upper())
    if m:
        return {"symbol": m.group(1), "order_type": m.group(2)}
    return None
