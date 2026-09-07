from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from datetime import datetime


def generate_pdf_report(
    file_path,
    wallet_address,
    chain,
    transactions,
    connected_wallets,
    max_hop,
    abnormal_alerts,
    vasp_results,
    risk_score,
    risk_level,
    patterns
):
    """
    Generate a professional CryptoShield PDF investigation report.
    """

    # ========================================================
    # PDF DOCUMENT
    # ========================================================

    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CryptoShieldTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=21,
        leading=25,
        spaceAfter=5
    )

    subtitle_style = ParagraphStyle(
        "CryptoShieldSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=14,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=7
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        spaceAfter=5
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=7,
        leading=10
    )

    # ========================================================
    # STORY
    # ========================================================

    story = []

    # ========================================================
    # HEADER
    # ========================================================

    story.append(
        Paragraph(
            "CRYPTO SHIELD",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Blockchain Fraud Intelligence System",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "INVESTIGATION REPORT",
            heading_style
        )
    )

    # ========================================================
    # INVESTIGATION SUMMARY
    # ========================================================

    summary_data = [
        [
            "Generated On",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ],
        [
            "Blockchain",
            str(chain)
        ],
        [
            "Reported Wallet",
            str(wallet_address)
        ],
        [
            "Transactions Analyzed",
            str(len(transactions))
        ],
        [
            "Connected Wallets",
            str(len(connected_wallets))
        ],
        [
            "Maximum Hop",
            str(max_hop)
        ],
        [
            "Risk Score",
            f"{risk_score}/100"
        ],
        [
            "Risk Level",
            str(risk_level)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            55 * mm,
            120 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(summary_table)

    story.append(Spacer(1, 8))

    # ========================================================
    # 1. DETECTED PATTERNS
    # ========================================================

    story.append(
        Paragraph(
            "1. DETECTED PATTERNS",
            heading_style
        )
    )

    if patterns:

        for pattern in patterns:

            story.append(
                Paragraph(
                    f"• {pattern}",
                    body_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No major predefined patterns detected.",
                body_style
            )
        )

    # ========================================================
    # 2. ABNORMAL TRANSACTIONS
    # ========================================================

    story.append(
        Paragraph(
            "2. ABNORMAL TRANSACTIONS",
            heading_style
        )
    )

    if abnormal_alerts:

        alert_data = [
            [
                "Transaction",
                "Score",
                "Reason"
            ]
        ]

        for alert in abnormal_alerts:

            tx_hash = str(
                alert.get(
                    "hash",
                    "Unknown"
                )
            )

            score = str(
                alert.get(
                    "score",
                    0
                )
            )

            reason = str(
                alert.get(
                    "reason",
                    "Abnormal activity"
                )
            )

            alert_data.append(
                [
                    tx_hash[:35],
                    score,
                    reason[:55]
                ]
            )

        alert_table = Table(
            alert_data,
            colWidths=[
                65 * mm,
                20 * mm,
                90 * mm
            ],
            repeatRows=1
        )

        alert_table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )
            ])
        )

        story.append(alert_table)

    else:

        story.append(
            Paragraph(
                "No abnormal transactions detected.",
                body_style
            )
        )

    # ========================================================
    # 3. FUND FLOW EVIDENCE
    # ========================================================

    story.append(
        Paragraph(
            "3. FUND FLOW EVIDENCE",
            heading_style
        )
    )

    tx_data = [
        [
            "From",
            "To",
            "Value",
            "Asset",
            "Transaction"
        ]
    ]

    # Limit PDF table to 100 rows so very large wallets
    # do not create an unnecessarily huge report.

    for tx in transactions[:100]:

        sender = str(
            tx.get(
                "from",
                ""
            )
        )

        receiver = str(
            tx.get(
                "to",
                ""
            )
        )

        value = str(
            tx.get(
                "value",
                0
            )
        )

        asset = str(
            tx.get(
                "asset",
                "ETH"
            )
        )

        tx_hash = str(
            tx.get(
                "hash",
                ""
            )
        )

        tx_data.append(
            [
                sender[:14],
                receiver[:14],
                value[:12],
                asset[:8],
                tx_hash[:20]
            ]
        )

    tx_table = Table(
        tx_data,
        colWidths=[
            35 * mm,
            35 * mm,
            20 * mm,
            20 * mm,
            60 * mm
        ],
        repeatRows=1
    )

    tx_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.3,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                6.5
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                3
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                3
            )
        ])
    )

    story.append(tx_table)

    if len(transactions) > 100:

        story.append(
            Spacer(1, 5)
        )

        story.append(
            Paragraph(
                f"Showing first 100 transactions in the PDF. "
                f"Total transactions analyzed: {len(transactions)}.",
                small_style
            )
        )

    # ========================================================
    # 4. POTENTIAL VASP ASSOCIATION
    # ========================================================

    story.append(
        Paragraph(
            "4. POTENTIAL VASP ASSOCIATION",
            heading_style
        )
    )

    if vasp_results:

        vasp_data = [
            [
                "Name",
                "Type",
                "Address",
                "Confidence"
            ]
        ]

        for vasp in vasp_results:

            vasp_data.append(
                [
                    str(
                        vasp.get(
                            "name",
                            "Unknown"
                        )
                    ),
                    str(
                        vasp.get(
                            "type",
                            "Unknown"
                        )
                    ),
                    str(
                        vasp.get(
                            "address",
                            "Unknown"
                        )
                    )[:28],
                    str(
                        vasp.get(
                            "confidence",
                            "Unknown"
                        )
                    )
                ]
            )

        vasp_table = Table(
            vasp_data,
            colWidths=[
                40 * mm,
                35 * mm,
                60 * mm,
                40 * mm
            ],
            repeatRows=1
        )

        vasp_table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )
            ])
        )

        story.append(vasp_table)

    else:

        story.append(
            Paragraph(
                "No potential VASP association identified.",
                body_style
            )
        )

    story.append(
        Spacer(1, 5)
    )

    story.append(
        Paragraph(
            "VASP association is based on available registry "
            "matches and should be independently verified.",
            small_style
        )
    )

    # ========================================================
    # 5. INVESTIGATION CONCLUSION
    # ========================================================

    story.append(
        Paragraph(
            "5. INVESTIGATION CONCLUSION",
            heading_style
        )
    )

    conclusion = (
        "CryptoShield reconstructed the available transaction flow "
        f"from the reported wallet on the {chain} blockchain. "
        f"The analysis covered {len(transactions)} transactions, "
        f"{len(connected_wallets)} connected wallets, and up to "
        f"{max_hop} hops. The resulting analytical risk score is "
        f"{risk_score}/100 ({risk_level})."
    )

    story.append(
        Paragraph(
            conclusion,
            body_style
        )
    )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Spacer(1, 10)
    )

    disclaimer = (
        "<b>IMPORTANT DISCLAIMER:</b> "
        "This report provides analytical intelligence only. "
        "A risk score or suspicious pattern does not establish "
        "criminal activity or identify a person as guilty. "
        "Further investigation and independent verification "
        "are required."
    )

    story.append(
        Paragraph(
            disclaimer,
            small_style
        )
    )

    # ========================================================
    # FOOTER
    # ========================================================

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "CRYPTO SHIELD — INVESTIGATION INTELLIGENCE",
            subtitle_style
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    doc.build(story)
