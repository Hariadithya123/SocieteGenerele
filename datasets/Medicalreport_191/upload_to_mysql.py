import pandas as pd
from sqlalchemy import create_engine
import pymysql

# MySQL connection details
username = 'root'
from urllib.parse import quote_plus
password = quote_plus('Baala@1975')
host = 'localhost'
database = 'medical_lab_db'

print("Connecting to MySQL server to create database...")
try:
    # Use raw pymysql to create database
    conn = pymysql.connect(host=host, user=username, password='Baala@1975')
    with conn.cursor() as cursor:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
    conn.commit()
    conn.close()
    print(f"Database '{database}' ensured.")
except Exception as e:
    print(f"Error creating database: {e}")

print("Connecting to database and reading Excel file...")

# Now connect to the specific database
engine = create_engine(f'mysql+pymysql://{username}:{password}@{host}/{database}')

file_path = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Generated_Final_V2_15000_All.xlsx'
xl = pd.ExcelFile(file_path)

for sheet in xl.sheet_names:
    print(f"Uploading sheet: {sheet}...")
    df = pd.read_excel(file_path, sheet_name=sheet)
    
    # Format table name (lowercase, replace spaces with underscores)
    table_name = sheet.lower().replace(' ', '_')
    
    # Upload to MySQL
    df.to_sql(name=table_name, con=engine, if_exists='replace', index=False)
    print(f"Successfully uploaded {len(df)} rows to table '{table_name}'.")

print("All data successfully uploaded to MySQL!")
