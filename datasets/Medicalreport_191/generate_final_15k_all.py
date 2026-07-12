import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

print("Generating final exactly 15,000 rows for all 4 sheets (fixing rejection statuses)...")

num_rows = 15000

departments = ['Cardiology', 'Neurology', 'Pathology', 'Radiology', 'Hematology', 'Oncology']
tests = {
    'Cardiology': ['ECG', 'Echocardiogram', 'Stress Test'],
    'Neurology': ['EEG', 'MRI Brain', 'CT Scan Head'],
    'Pathology': ['Biopsy', 'Blood Culture', 'Urine Analysis'],
    'Radiology': ['X-Ray Chest', 'MRI Spine', 'Ultrasound Abdomen'],
    'Hematology': ['Complete Blood Count', 'Lipid Panel', 'Hemoglobin A1C'],
    'Oncology': ['Tumor Marker', 'PET Scan', 'Bone Marrow Aspiration']
}
statuses = ['Completed', 'Pending', 'In Progress', 'Delayed']
rejection_reasons = ['Hemolysis', 'Insufficient Sample', 'Clotted Sample', 'Improper Labeling', 'Contamination']
equipment_names = [f"Analyzer {i}" for i in range(1, 21)]

start_date = datetime(2024, 1, 1, 8, 0, 0)

sample_data = []
equipment_data = []
reagent_data = []
rejection_data = []

for i in range(num_rows):
    sample_id = f"S{i+1:05d}"
    patient_name = f"Patient_{i+1}"
    dept = random.choice(departments)
    test = random.choice(tests[dept])
    
    # 1. Sample ID data
    collection_time = start_date + timedelta(days=random.randint(0, 500), hours=random.randint(0, 10), minutes=random.randint(0, 59))
    processing_start = collection_time + timedelta(minutes=random.randint(10, 120))
    processing_end = processing_start + timedelta(minutes=random.randint(30, 1440))
    
    status = random.choices(statuses, weights=[0.8, 0.05, 0.1, 0.05])[0]
    
    report_release = pd.NaT
    if status == 'Completed':
        report_release = processing_end + timedelta(minutes=random.randint(10, 300))
    elif status == 'Delayed':
        report_release = processing_end + timedelta(minutes=random.randint(1440, 5000))
        
    sample_data.append([
        sample_id, patient_name, dept, test,
        collection_time.strftime('%Y-%m-%d %H:%M:%S'),
        processing_start.strftime('%Y-%m-%d %H:%M:%S'),
        processing_end.strftime('%Y-%m-%d %H:%M:%S'),
        report_release.strftime('%Y-%m-%d %H:%M:%S') if pd.notnull(report_release) else None,
        status
    ])

    # 2. Equipment ID data
    eq_id = f"EQ{random.randint(1, 20):03d}"
    eq_name = equipment_names[int(eq_id[2:]) - 1]
    failure = random.choices(['NO', 'YES'], weights=[0.95, 0.05])[0]
    downtime = random.randint(10, 120) if failure == 'YES' else 0
    fail_reason = 'Calibration Error' if failure == 'YES' else None
    
    equipment_data.append([
        eq_id, eq_name, sample_id, 
        processing_start.strftime('%Y-%m-%d %H:%M:%S'),
        processing_end.strftime('%Y-%m-%d %H:%M:%S'),
        downtime, failure, fail_reason
    ])

    # 3. Reagent ID data
    reagent_id = f"R{i+1:05d}"
    reagent_name = f"{test} Reagent"
    stock = random.randint(50, 500)
    usage = random.randint(5, 50)
    recorder = usage * 2
    stock_status = 'AVAILABLE' if stock > recorder else 'LOW'
    restock_date = (collection_time + timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d')
    
    reagent_data.append([
        reagent_id, reagent_name, test, stock, usage, recorder, restock_date, stock_status
    ])

    # 4. Rejection ID data
    # FIX: Incorporate ACCEPTED and REJECTED logically.
    rejection_id = f"RJ{i+1:05d}"
    # Rejection review date is usually right after collection
    review_date = collection_time + timedelta(minutes=random.randint(5, 60))
    
    # Randomly assign ACCEPTED or REJECTED for the sample review process.
    rej_status = random.choices(['ACCEPTED', 'REJECTED'], weights=[0.85, 0.15])[0]
    
    if rej_status == 'ACCEPTED':
        reason = None
    else:
        reason = random.choice(rejection_reasons)
        
    rejection_data.append([
        rejection_id, sample_id, patient_name, dept, test,
        review_date.strftime('%Y-%m-%d %H:%M:%S'),
        reason, rej_status
    ])

# Create DataFrames
df_sample = pd.DataFrame(sample_data, columns=['SAMPLE  ID', 'PATIENT NAME', 'DEPARTMENT', 'TEST NAME', 'COLLECTION TIME', 'PROCESSING START TIME', 'PROCESSING END TIME', 'REPORT RELEASE TIME', 'STATUS'])
df_equip = pd.DataFrame(equipment_data, columns=['EQUIPMENT ID', 'EQUIPMENT NAME', 'SAMPLE ID', 'START TIME', 'END TIME', 'DOWN TIME (MIN)', 'FAILURE STATUS', 'FAILURE REASON'])
df_reagent = pd.DataFrame(reagent_data, columns=[' REAGENT ID', 'REAGENT  NAME', 'TEST NAME', 'CURRENT STOCK', 'DAILY USAGE', 'RECORDER LEVEL', 'RESTOCK DATE', 'STOCK STATUS'])
df_reject = pd.DataFrame(rejection_data, columns=['REJECTION ID', 'SAMPLE ID', 'PATIENT NAME', 'DEPARTMENT', 'TEST NAME', 'DATE', 'REJECTION REASON', 'STATUS'])

output_file = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Generated_Final_15000_All.xlsx'

with pd.ExcelWriter(output_file) as writer:
    df_sample.to_excel(writer, sheet_name='Sample ID', index=False)
    df_equip.to_excel(writer, sheet_name='Equipment ID', index=False)
    df_reagent.to_excel(writer, sheet_name='Reagent ID', index=False)
    df_reject.to_excel(writer, sheet_name='Rejection ID', index=False)

print(f"Data generation complete! Saved to {output_file}")
