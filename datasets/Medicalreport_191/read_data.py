import pandas as pd

try:
    file_path = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Primary Dummy Data collection.xlsx'
    xl = pd.ExcelFile(file_path)
    print("Sheet names:", xl.sheet_names)
    
    for sheet in xl.sheet_names:
        df = pd.read_excel(file_path, sheet_name=sheet)
        print(f"\nSheet: {sheet}")
        print("Columns:", df.columns.tolist())
        print("Head:")
        print(df.head(2))
except Exception as e:
    print("Error:", e)
