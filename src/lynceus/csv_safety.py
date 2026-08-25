"""Spreadsheet-safety for every CSV this product exports.

⛔ One definition, because there is now more than one CSV surface. The
web UI's /alerts.csv and /watchlist.csv exports have neutralised formula
cells since the CSP work; the case-file bundle is the second exporter,
and a payload the UI refuses to hand an operator must not be handed to a
journalist instead. A second copy of this logic is a second thing to
remember, and the failure is silent in exactly the place nobody looks.
"""

from __future__ import annotations

#: The four characters that flag a CSV cell as a formula to Excel, Google
#: Sheets, and LibreOffice Calc when the CSV is opened. The CSV standard does
#: not require these to be quoted, so ``csv.QUOTE_MINIMAL`` emits them verbatim
#: and the spreadsheet interprets the cell as a formula on open — CWE-1236.
_CSV_FORMULA_PREFIXES: frozenset[str] = frozenset(("=", "+", "-", "@"))


def csv_safe_cell(value) -> str:
    """Neutralise CSV formula injection at the leading character.

    ⛔ **Cells whose first character is one of ``=``, ``+``, ``-`` or ``@``
    are RUN AS FORMULAS by Excel, Google Sheets and LibreOffice Calc when
    the export is opened.** Measured against an unmodified
    ``/alerts.csv`` / ``/watchlist.csv``: a message of ``=2+3`` or a
    watchlist description of ``=HYPERLINK("http://...","Click")`` was
    written verbatim, with no quoting, because ``csv.QUOTE_MINIMAL`` only
    quotes on a delimiter, line-break or quote-character and none of the
    four prefixes trigger any of those. The watchlist description column
    is the worst case — the Argus importer populates it from
    externally-controlled CSV/JSON, so a malicious export or rule could
    plant a payload that fires when an operator opens the file.

    A leading single quote (U+0027) is the spreadsheet convention for
    "treat this as a text literal": Excel and Sheets hide the quote and
    display the rest as a string, and the cell survives a round-trip
    through the csv module's own quoting rules without further mutation.
    Non-string inputs are stringified first so numeric / boolean cells
    that happen to be formatted as a string get the same treatment.

    ⚠️ ``None`` stays ``""`` — that is the file's NULL stand-in, set at
    the writer sites, and leading with a quote there would silently turn
    every empty column into a literal apostrophe in the export. Empty
    cells are not formula cells.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text

