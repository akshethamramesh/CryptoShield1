from datetime import datetime


def generate_report(
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
    report = []

    report.append("=" * 70)
    report.append("                 CRYPTO SHIELD")
    report.append("          BLOCKCHAIN FRAUD INTELLIGENCE")
    report.append("=" * 70)

    report.append("")
    report.append("INVESTIGATION REPORT")
    report.append("-" * 70)

    report.append(f"Generated On     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Blockchain       : {chain}")
    report.append(f"Reported Wallet  : {wallet_address}")

    report.append("")
    report.append("1. INVESTIGATION SUMMARY")
    report.append("-" * 70)

    report.append(f"Transactions Analyzed : {len(transactions)}")
    report.append(f"Connected Wallets     : {len(connected_wallets)}")
    report.append(f"Maximum Hop           : {max_hop}")

    report.append("")
    report.append("2. RISK ASSESSMENT")
    report.append("-" * 70)

    report.append(f"Risk Score            : {risk_score}/100")
    report.append(f"Risk Level            : {risk_level}")

    report.append("")
    report.append("3. DETECTED PATTERNS")
    report.append("-" * 70)

    if patterns:
        for pattern in patterns:
            report.append(f"- {pattern}")
    else:
        report.append("- No major patterns detected")

    report.append("")
    report.append("4. ABNORMAL TRANSACTIONS")
    report.append("-" * 70)

    if abnormal_alerts:
        for alert in abnormal_alerts:
            tx_hash = alert.get("hash", "Unknown")
            reason = alert.get("reason", "Abnormal activity")
            score = alert.get("score", 0)

            report.append(
                f"- Transaction: {tx_hash} | "
                f"Score: {score} | "
                f"Reason: {reason}"
            )
    else:
        report.append("- No abnormal transactions detected")

    report.append("")
    report.append("5. POTENTIAL VASP ASSOCIATION")
    report.append("-" * 70)

    if vasp_results:
        for vasp in vasp_results:
            report.append(f"Name       : {vasp.get('name', 'Unknown')}")
            report.append(f"Type       : {vasp.get('type', 'Unknown')}")
            report.append(f"Address    : {vasp.get('address', 'Unknown')}")
            report.append(f"Confidence : {vasp.get('confidence', 'Unknown')}")
            report.append("")
    else:
        report.append("- No potential VASP association identified")

    report.append("")
    report.append("6. INVESTIGATION CONCLUSION")
    report.append("-" * 70)

    report.append(
        "CryptoShield reconstructed the available transaction flow "
        "from the reported wallet and analyzed transaction behavior "
        "for predefined risk indicators."
    )

    report.append("")
    report.append("IMPORTANT DISCLAIMER")
    report.append("-" * 70)

    report.append(
        "This report provides analytical intelligence only. "
        "A risk score or suspicious pattern does not establish "
        "criminal activity or identify a person as guilty. "
        "Further investigation and independent verification are required."
    )

    report.append("")
    report.append("=" * 70)
    report.append("        CRYPTO SHIELD - INVESTIGATION INTELLIGENCE")
    report.append("=" * 70)

    return "\n".join(report)
