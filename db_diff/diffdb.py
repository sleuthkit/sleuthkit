# Requires python3

import re
import sqlite3
import subprocess
import shutil
import os
import codecs
import datetime
import sys
from typing import Callable, Dict, Union, List
import time
import psycopg2
import psycopg2.extras
import socket
import csv
import argparse
from datetime import datetime


def convert_to_raw_text(db_file):
    raw_text = ""
    # Connect to the database
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Fetch all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    # Iterate over each table and fetch all rows
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT * FROM {table_name};")
        rows = cursor.fetchall()
        # Convert rows to raw text
        for row in rows:
            row_text = "|".join(str(cell) for cell in row)
            raw_text += f"{table_name}|{row_text}\n"
    # Close the database connection
    cursor.close()
    conn.close()

    return raw_text


def split_text(raw_text):
    lines = raw_text.splitlines()
    return lines


def write_different_entries(entries, file_path):
    with open(file_path, 'a') as file:
        file.write(entries + '\n')


def compare_databases(db_file1, db_file2):
    # Convert both databases to raw text
    raw_text1 = convert_to_raw_text(db_file1)
    raw_text2 = convert_to_raw_text(db_file2)
    # Compare the raw text for differences
    differences = ""
    fail = False
    if raw_text1 != raw_text2:
        print("Differences found!")
        entries1 = split_text(raw_text1)
        entries2 = split_text(raw_text2)
        for i in range(len(entries1)):
            if entries1[i] != entries2[i]:
                print(f"Entry {i + 1} is different.")
                differences = f"{differences} \n {entries1[i]}  | {entries2[i]}\n\n"
                fail = True
    else:
        print("Databases are identical")
    if fail:
        current_datetime = datetime.now()
        current_datetime_string = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")
        write_different_entries(differences, f'{current_datetime_string}-diff.txt')


def run_tsk_db_diff(script_path, db_file1, db_file2):

    if '.py' not in script_path:
        script_path = script_path + "/tskdbdiff.py"
    else:
        print(f'Script file was passed {script_path}')
    command = [
        'python', script_path,
        db_file2, db_file1
    ]
    try:
        # Run the command
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        # Handle any errors that occurred during execution
        print(f"Command execution failed with error code {e.returncode}.")


def main():
    # Define the command-line arguments
    parser = argparse.ArgumentParser(description='Compare two files.')
    parser.add_argument('file1', help='Path to the first file')
    parser.add_argument('file2', help='Path to the second file')
    args = parser.parse_args()

    # Get the file paths from the command-line arguments
    file1_path = args.file1
    file2_path = args.file2

    # Compare the databases
    compare_databases(file1_path, file2_path)
    sys.exit(0)


if __name__ == "__main__":
    if sys.hexversion < 0x03000000:
        print("Python 3 required")
        sys.exit(1)

    main()
