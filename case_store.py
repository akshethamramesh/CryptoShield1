import sqlite3
import json
from datetime import datetime
from pathlib import Path


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = BASE_DIR / "cryptoshield_cases.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    conn = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            case_id TEXT UNIQUE NOT NULL,

            wallet_address TEXT NOT NULL,

            chain TEXT NOT NULL,

            traced_value REAL DEFAULT 0,

            risk_score INTEGER DEFAULT 0,

            risk_level TEXT DEFAULT 'LOW',

            max_hop INTEGER DEFAULT 2,

            final_destinations TEXT,

            important_wallets TEXT,

            hop_paths TEXT,

            created_at TEXT NOT NULL

        )
    """)

    conn.commit()

    conn.close()


# ============================================================
# GENERATE CASE ID
# ============================================================

def generate_case_id():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) AS count FROM cases"
    )

    result = cursor.fetchone()

    count = result["count"] + 1

    conn.close()

    return f"CS-{count:03d}"


# ============================================================
# SAVE CASE
# ============================================================

def save_case(
    wallet_address,
    chain,
    traced_value=0,
    risk_score=0,
    risk_level="LOW",
    max_hop=2,
    final_destinations=None,
    important_wallets=None,
    hop_paths=None
):

    init_database()

    case_id = generate_case_id()

    timestamp = datetime.now().isoformat(
        timespec="seconds"
    )

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO cases (
            case_id,
            wallet_address,
            chain,
            traced_value,
            risk_score,
            risk_level,
            max_hop,
            final_destinations,
            important_wallets,
            hop_paths,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            case_id,

            wallet_address.lower(),

            chain,

            traced_value,

            risk_score,

            risk_level,

            max_hop,

            json.dumps(
                final_destinations or []
            ),

            json.dumps(
                important_wallets or []
            ),

            json.dumps(
                hop_paths or []
            ),

            timestamp
        )
    )

    conn.commit()

    conn.close()

    return case_id


# ============================================================
# GET ALL CASES
# ============================================================

def get_all_cases():

    init_database()

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM cases
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    cases = []

    for row in rows:

        case = dict(row)

        case["final_destinations"] = json.loads(
            case["final_destinations"] or "[]"
        )

        case["important_wallets"] = json.loads(
            case["important_wallets"] or "[]"
        )

        case["hop_paths"] = json.loads(
            case["hop_paths"] or "[]"
        )

        cases.append(case)

    return cases


# ============================================================
# GET CASE BY ID
# ============================================================

def get_case(case_id):

    init_database()

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM cases
        WHERE case_id = ?
        """,
        (case_id,)
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    case = dict(row)

    case["final_destinations"] = json.loads(
        case["final_destinations"] or "[]"
    )

    case["important_wallets"] = json.loads(
        case["important_wallets"] or "[]"
    )

    case["hop_paths"] = json.loads(
        case["hop_paths"] or "[]"
    )

    return case


# ============================================================
# GET OTHER CASES
# ============================================================

def get_other_cases(current_case_id=None):

    cases = get_all_cases()

    if current_case_id:

        cases = [
            case
            for case in cases
            if case["case_id"] != current_case_id
        ]

    return cases


# ============================================================
# DELETE ALL CASES
# USE ONLY FOR DEMO RESET
# ============================================================

def clear_all_cases():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM cases"
    )

    conn.commit()

    conn.close()
