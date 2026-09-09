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


def safe_str(value, default=""):
    if value is None:
        return default
    return str(value)


def short_address(address, start=12, end=8):
    address = safe_str(address)

    if len(address) <= start + end + 3:
        return address

    return f"{address[:start]}...{address[-end:]}"


def short_hash(tx_hash, length=25):
    tx_hash = safe_str(tx_hash)

    if len(tx_hash) <= length:
        return tx_hash

    return tx_hash[:length] + "..."


def format_number(value, decimals=6):
    try:
        return f"{float(value):,.{decimals}f}"
    except Exception:
        return safe_str(value, "0")


def get_risk_color(risk_level):
    level = safe_str(risk_level).upper()

    if level == "HIGH":
        return colors.HexColor("#C62828")

    if level == "MEDIUM":
        return colors.HexColor("#EF6C00")

    return colors.HexColor("#2E7D32")


def add_page_number(canvas, document):
    canvas.saveState()

    width, height = A4

    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(
        15 * mm,
        height - 10 * mm,
        "CRYPTO SHIELD"
    )

    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(
        width - 15 * mm,
        height - 10 * mm,
        "Blockchain Fraud Intelligence"
    )

    canvas.setStrokeColor(colors.lightgrey)

    canvas.line(
        15 * mm,
        12 * mm,
        width - 15 * mm,
        12 * mm
    )

    canvas.setFont("Helvetica", 7)

    canvas.drawString(
        15 * mm,
        7 * mm,
        "CryptoShield - Investigation Intelligence"
    )

    canvas.drawRightString(
        width - 15 * mm,
        7 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


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

    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="CryptoShield Investigation Report",
        author="CryptoShield"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CryptoShieldTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=27,
        spaceAfter=5
    )

    subtitle_style = ParagraphStyle(
        "CryptoShieldSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.grey,
        spaceAfter=15
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        spaceBefore=12,
        spaceAfter=7
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        spaceAfter=5
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=10,
        textColor=colors.grey
    )

    table_style = ParagraphStyle(
        "TableText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9
    )

    story = []

    # ---------------------------------------------------------
    # TITLE
    # ---------------------------------------------------------

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "CRYPTO SHIELD",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Blockchain Fraud Intelligence & Investigation System",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "INVESTIGATION REPORT",
            section_style
        )
    )

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    summary_data = [
        [
            Paragraph("Generated On", table_header_style),
            Paragraph(generated_time, table_style)
        ],
        [
            Paragraph("Blockchain", table_header_style),
            Paragraph(safe_str(chain), table_style)
        ],
        [
            Paragraph("Reported Suspect Wallet", table_header_style),
            Paragraph(safe_str(wallet_address), table_style)
        ],
        [
            Paragraph("Transactions Analyzed", table_header_style),
            Paragraph(str(len(transactions)), table_style)
        ],
        [
            Paragraph("Connected Wallets", table_header_style),
            Paragraph(str(len(connected_wallets)), table_style)
        ],
        [
            Paragraph("Maximum Tracing Hop", table_header_style),
            Paragraph(str(max_hop), table_style)
        ],
        [
            Paragraph("Analytical Risk Score", table_header_style),
            Paragraph(f"{risk_score}/100", table_style)
        ],
        [
            Paragraph("Risk Level", table_header_style),
            Paragraph(
                safe_str(risk_level).upper(),
                table_style
            )
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[55 * mm, 120 * mm]
    )

    summary_table.setStyle(
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
                (0, -1),
                colors.HexColor("#EEEEEE")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
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

    # ---------------------------------------------------------
    # RISK
    # ---------------------------------------------------------

    risk_color = get_risk_color(risk_level)

    risk_value_style = ParagraphStyle(
        "RiskValue",
        parent=body_style,
        fontSize=16,
        textColor=risk_color,
        alignment=TA_CENTER
    )

    risk_table = Table(
        [
            [
                Paragraph(
                    "<b>ANALYTICAL RISK ASSESSMENT</b>",
                    body_style
                )
            ],
            [
                Paragraph(
                    f"<b>{risk_score}/100 - "
                    f"{safe_str(risk_level).upper()}</b>",
                    risk_value_style
                )
            ],
            [
                Paragraph(
                    "This score represents analytical indicators "
                    "observed in the available blockchain data. "
                    "It does not establish criminal activity.",
                    small_style
                )
            ]
        ],
        colWidths=[175 * mm]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1.5,
                risk_color
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F8F8F8")
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(risk_table)

    # ---------------------------------------------------------
    # PATTERNS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "1. DETECTED FRAUD-LINKED BEHAVIOUR",
            section_style
        )
    )

    if patterns:

        for pattern in patterns:

            if isinstance(pattern, dict):

                name = safe_str(
                    pattern.get(
                        "pattern",
                        pattern.get(
                            "name",
                            "Suspicious Pattern"
                        )
                    )
                )

                description = safe_str(
                    pattern.get(
                        "description",
                        pattern.get(
                            "reason",
                            ""
                        )
                    )
                )

                confidence = safe_str(
                    pattern.get(
                        "confidence",
                        ""
                    )
                )

                text = f"<b>{name}</b>"

                if description:
                    text += f"<br/>{description}"

                if confidence:
                    text += (
                        f"<br/><b>Confidence:</b> "
                        f"{confidence}"
                    )

                story.append(
                    Paragraph(
                        f"• {text}",
                        body_style
                    )
                )

            else:

                story.append(
                    Paragraph(
                        f"• {safe_str(pattern)}",
                        body_style
                    )
                )

    else:

        story.append(
            Paragraph(
                "No major predefined suspicious behaviour "
                "patterns were detected.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # ABNORMAL TRANSACTIONS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "2. ABNORMAL TRANSACTIONS",
            section_style
        )
    )

    if abnormal_alerts:

        alert_data = [
            [
                Paragraph("Transaction", table_header_style),
                Paragraph("Score", table_header_style),
                Paragraph("Reason", table_header_style)
            ]
        ]

        for alert in abnormal_alerts[:50]:

            tx_hash = short_hash(
                alert.get("hash", "Unknown")
            )

            score = safe_str(
                alert.get("score", 0)
            )

            reason = safe_str(
                alert.get(
                    "reason",
                    "Abnormal activity"
                )
            )

            alert_data.append(
                [
                    Paragraph(tx_hash, table_style),
                    Paragraph(score, table_style),
                    Paragraph(reason, table_style)
                ]
            )

        alert_table = Table(
            alert_data,
            colWidths=[
                60 * mm,
                20 * mm,
                95 * mm
            ],
            repeatRows=1
        )

        alert_table.setStyle(
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
                    colors.HexColor("#EEEEEE")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
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

        if len(abnormal_alerts) > 50:

            story.append(
                Paragraph(
                    f"Showing first 50 abnormal transactions "
                    f"out of {len(abnormal_alerts)} detected alerts.",
                    small_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No abnormal transactions detected.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # TRANSACTION DNA
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "3. TRANSACTION DNA",
            section_style
        )
    )

    native_count = 0
    token_count = 0
    native_volume = 0
    token_volume = 0

    for tx in transactions:

        tx_type = safe_str(
            tx.get("type", "native")
        ).lower()

        try:
            value = float(
                tx.get("value", 0)
            )
        except Exception:
            value = 0

        if tx_type == "token":

            token_count += 1
            token_volume += value

        else:

            native_count += 1
            native_volume += value

    dna_data = [
        [
            Paragraph("Metric", table_header_style),
            Paragraph("Value", table_header_style)
        ],
        [
            Paragraph("Total Transactions", table_style),
            Paragraph(str(len(transactions)), table_style)
        ],
        [
            Paragraph("Native Transactions", table_style),
            Paragraph(str(native_count), table_style)
        ],
        [
            Paragraph("Token Transactions", table_style),
            Paragraph(str(token_count), table_style)
        ],
        [
            Paragraph("Native Volume", table_style),
            Paragraph(
                format_number(native_volume),
                table_style
            )
        ],
        [
            Paragraph("Token Volume", table_style),
            Paragraph(
                format_number(token_volume),
                table_style
            )
        ]
    ]

    dna_table = Table(
        dna_data,
        colWidths=[80 * mm, 95 * mm],
        repeatRows=1
    )

    dna_table.setStyle(
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
                colors.HexColor("#EEEEEE")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(dna_table)

    # ---------------------------------------------------------
    # FUND FLOW
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "4. FUND FLOW EVIDENCE",
            section_style
        )
    )

    if transactions:

        tx_data = [
            [
                Paragraph("From", table_header_style),
                Paragraph("To", table_header_style),
                Paragraph("Value", table_header_style),
                Paragraph("Asset", table_header_style),
                Paragraph("Transaction", table_header_style)
            ]
        ]

        for tx in transactions[:100]:

            sender = short_address(
                tx.get("from", "")
            )

            receiver = short_address(
                tx.get("to", "")
            )

            value = format_number(
                tx.get("value", 0)
            )

            asset = safe_str(
                tx.get("asset", "ETH")
            )

            tx_hash = short_hash(
                tx.get("hash", ""),
                20
            )

            tx_data.append(
                [
                    Paragraph(sender, table_style),
                    Paragraph(receiver, table_style),
                    Paragraph(value, table_style),
                    Paragraph(asset, table_style),
                    Paragraph(tx_hash, table_style)
                ]
            )

        tx_table = Table(
            tx_data,
            colWidths=[
                35 * mm,
                35 * mm,
                25 * mm,
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
                    0.25,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#EEEEEE")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    3
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    3
                )
            ])
        )

        story.append(tx_table)

        if len(transactions) > 100:

            story.append(
                Paragraph(
                    f"Showing first 100 transactions. "
                    f"Total analyzed: {len(transactions)}.",
                    small_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No transaction evidence was available.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # CONNECTED WALLETS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "5. CONNECTED WALLET INTELLIGENCE",
            section_style
        )
    )

    if connected_wallets:

        wallet_data = [
            [
                Paragraph("Wallet", table_header_style),
                Paragraph(
                    "Tracing Context",
                    table_header_style
                )
            ]
        ]

        for wallet in connected_wallets[:100]:

            wallet_data.append(
                [
                    Paragraph(
                        safe_str(wallet),
                        table_style
                    ),
                    Paragraph(
                        "Connected through blockchain "
                        "transaction analysis",
                        table_style
                    )
                ]
            )

        wallet_table = Table(
            wallet_data,
            colWidths=[85 * mm, 90 * mm],
            repeatRows=1
        )

        wallet_table.setStyle(
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
                    colors.HexColor("#EEEEEE")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )

        story.append(wallet_table)

    else:

        story.append(
            Paragraph(
                "No connected wallets were identified.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # VASP
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "6. POTENTIAL VASP / EXCHANGE ASSOCIATION",
            section_style
        )
    )

    if vasp_results:

        vasp_data = [
            [
                Paragraph("Name", table_header_style),
                Paragraph("Type", table_header_style),
                Paragraph("Address", table_header_style),
                Paragraph("Confidence", table_header_style)
            ]
        ]

        for vasp in vasp_results:

            vasp_data.append(
                [
                    Paragraph(
                        safe_str(
                            vasp.get(
                                "name",
                                "Unknown"
                            )
                        ),
                        table_style
                    ),
                    Paragraph(
                        safe_str(
                            vasp.get(
                                "type",
                                "Unknown"
                            )
                        ),
                        table_style
                    ),
                    Paragraph(
                        short_address(
                            vasp.get(
                                "address",
                                "Unknown"
                            )
                        ),
                        table_style
                    ),
                    Paragraph(
                        safe_str(
                            vasp.get(
                                "confidence",
                                "Potential association"
                            )
                        ),
                        table_style
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
                    colors.HexColor("#EEEEEE")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )

        story.append(vasp_table)

    else:

        story.append(
            Paragraph(
                "No potential VASP association was identified "
                "from the available registry data.",
                body_style
            )
        )

    story.append(
        Paragraph(
            "<b>Note:</b> VASP/exchange association is based "
            "on available address-label information. "
            "It represents a potential association and does "
            "not prove wallet ownership.",
            small_style
        )
    )

    # ---------------------------------------------------------
    # FINDINGS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "7. INVESTIGATION FINDINGS",
            section_style
        )
    )

    findings = [
        f"The reported wallet was analyzed on the "
        f"{safe_str(chain)} blockchain.",

        f"A total of {len(transactions)} transactions "
        f"were analyzed.",

        f"{len(connected_wallets)} connected wallets "
        f"were identified within the configured "
        f"tracing scope.",

        f"The maximum tracing depth used was "
        f"{max_hop} hop(s).",

        f"The analytical risk score was "
        f"{risk_score}/100 with a "
        f"{safe_str(risk_level).upper()} risk level.",

        f"{len(abnormal_alerts)} abnormal transaction "
        f"alert(s) were generated.",

        f"{len(patterns)} suspicious behaviour "
        f"pattern(s) were identified.",

        f"{len(vasp_results)} potential VASP association(s) "
        f"were identified."
    ]

    for finding in findings:

        story.append(
            Paragraph(
                f"• {finding}",
                body_style
            )
        )

    # ---------------------------------------------------------
    # CONCLUSION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "8. INVESTIGATION CONCLUSION",
            section_style
        )
    )

    conclusion = (
        "CryptoShield reconstructed the available blockchain "
        "transaction flow from the victim-reported suspect "
        "wallet. The analysis covered "
        f"{len(transactions)} transactions, "
        f"{len(connected_wallets)} connected wallets, "
        f"and up to {max_hop} tracing hops on the "
        f"{safe_str(chain)} blockchain. The resulting "
        f"analytical risk assessment was {risk_score}/100 "
        f"({safe_str(risk_level).upper()}). The findings "
        "provide blockchain-based investigation intelligence "
        "that can be used for further verification and "
        "investigative action."
    )

    story.append(
        Paragraph(
            conclusion,
            body_style
        )
    )

    # ---------------------------------------------------------
    # METHODOLOGY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "9. ANALYSIS METHODOLOGY",
            section_style
        )
    )

    methodology = [
        "Blockchain transaction data was collected for "
        "the reported wallet.",

        "Connected wallets were reconstructed through "
        "multi-hop transaction tracing.",

        "Transaction behaviour was analyzed using "
        "transaction-level and network-level indicators.",

        "Abnormal transaction indicators were evaluated "
        "using predefined analytical rules.",

        "Suspicious fund-flow patterns such as splitting, "
        "consolidation, rapid movement and multi-hop "
        "activity were evaluated.",

        "An explainable analytical risk score was calculated "
        "from multiple behavioural indicators.",

        "Available address-label information was used to "
        "identify potential VASP or exchange associations.",

        "The resulting evidence was compiled into an "
        "investigation-oriented report."
    ]

    for item in methodology:

        story.append(
            Paragraph(
                f"• {item}",
                body_style
            )
        )

    # ---------------------------------------------------------
    # DISCLAIMER
    # ---------------------------------------------------------

    disclaimer_table = Table(
        [
            [
                Paragraph(
                    "<b>IMPORTANT DISCLAIMER</b>",
                    body_style
                )
            ],
            [
                Paragraph(
                    "CryptoShield provides analytical blockchain "
                    "intelligence only. A high risk score, "
                    "suspicious transaction pattern, abnormal "
                    "activity indicator, or potential VASP "
                    "association does not establish criminal "
                    "activity, identify a person as guilty, "
                    "or prove ownership of a cryptocurrency "
                    "wallet. All findings should be independently "
                    "verified by authorized investigators and "
                    "supported by additional evidence.",
                    small_style
                )
            ]
        ],
        colWidths=[175 * mm]
    )

    disclaimer_table.setStyle(
        TableStyle([
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F5F5F5")
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(Spacer(1, 10))
    story.append(disclaimer_table)

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "CRYPTO SHIELD - BLOCKCHAIN FRAUD INTELLIGENCE",
            subtitle_style
        )
    )

    # ---------------------------------------------------------
    # BUILD PDF
    # ---------------------------------------------------------

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    return file_path
