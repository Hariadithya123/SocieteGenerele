import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

print("Generating full dummy data across 4 sheets...")

num_samples = 15000

# Sheet 1: Sample ID
departments = ['Cardiology', 'Neurology', 'Pathology', 'Radiology', 'Hematology', 'Oncology']
tests = {
    'Cardiology': ['ECG', 'Echocardiogram', 'Stress Test'],
    'Neurology': ['EEG', 'MRI Brain', 'CT Scan Head'],
    'Pathology': ['Biopsy', 'Blood Culture', 'Urine Analysis'],
    'Radiology': ['X-Ray Chest', 'MRI Spine', 'Ultrasound Abdomen'],
    'Hematology': ['Complete Blood Count', 'Lipid Panel', 'Hemoglobin A1C'],
    'Oncology': ['Tumor Marker', 'PET Scan', 'Bone Marrow Aspiration']
}
statuses = ['Completed', 'Pending', 'In Progress', 'Delayed', 'Rejected']

start_date = datetime(2025, 1, 1, 8, 0, 0)
sample_data = []
rejection_data = []
equipment_data = []

rejection_reasons = ['Hemolysis', 'Insufficient Sample', 'Clotted Sample', 'Improper Labeling', 'Contamination']
equipments = [f"EQ{i:03d}" for i in range(1, 21)]
equipment_names = [f"Analyzer {i}" for i in range(1, 21)]

rejection_id_counter = 1

for i in range(num_samples):
    sample_id = f"S{i+1:05d}"
    patient_name = f"Patient_{i+1}"
    dept = random.choice(departments)
    test = random.choice(tests[dept])
    
    collection_time = start_date + timedelta(days=random.randint(0, 365), hours=random.randint(0, 8), minutes=random.randint(0, 59))
    processing_start = collection_time + timedelta(minutes=random.randint(10, 120))
    processing_end = processing_start + timedelta(minutes=random.randint(30, 1440))
    
    status = random.choices(statuses, weights=[0.8, 0.05, 0.08, 0.05, 0.02])[0]
    
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

    # Sheet 2: Equipment ID
    eq_idx = random.randint(0, 19)
    eq_id = equipments[eq_idx]
    eq_name = equipment_names[eq_idx]
    failure = random.choices(['NO', 'YES'], weights=[0.98, 0.02])[0]
    downtime = random.randint(10, 120) if failure == 'YES' else 0
    fail_reason = 'Calibration Error' if failure == 'YES' else None
    
    equipment_data.append([
        eq_id, eq_name, sample_id, 
        processing_start.strftime('%Y-%m-%d %H:%M:%S'),
        processing_end.strftime('%Y-%m-%d %H:%M:%S'),
        downtime, failure, fail_reason
    ])

    # Sheet 4: Rejection ID
    if status == 'Rejected':
        rejection_id = f"RJ{rejection_id_counter:04d}"
        rejection_id_counter += 1
        reason = random.choice(rejection_reasons)
        rejection_data.append([
            rejection_id, sample_id, patient_name, dept, test,
            collection_time.strftime('%Y-%m-%d %H:%M:%S'),
            reason, 'REJECTED'
        ])

# Sheet 3: Reagent ID
reagent_data = []
for i, (dept, test_list) in enumerate(tests.items()):
    for j, test in enumerate(test_list):
        reagent_id = f"R{i*10+j+1:03d}"
        reagent_name = f"{test} Reagent"
        stock = random.randint(100, 1000)
        usage = random.randint(10, 100)
        recorder = usage * 2
        stock_status = 'AVAILABLE' if stock > recorder else 'LOW'
        restock_date = (start_date + timedelta(days=random.randint(0, 365))).strftime('%Y-%m-%d')
        
        reagent_data.append([
            reagent_id, reagent_name, test, stock, usage, recorder, restock_date, stock_status
        ])

# Create DataFrames
df_sample = pd.DataFrame(sample_data, columns=['SAMPLE  ID', 'PATIENT NAME', 'DEPARTMENT', 'TEST NAME', 'COLLECTION TIME', 'PROCESSING START TIME', 'PROCESSING END TIME', 'REPORT RELEASE TIME', 'STATUS'])
df_equip = pd.DataFrame(equipment_data, columns=['EQUIPMENT ID', 'EQUIPMENT NAME', 'SAMPLE ID', 'START TIME', 'END TIME', 'DOWN TIME (MIN)', 'FAILURE STATUS', 'FAILURE REASON'])
df_reagent = pd.DataFrame(reagent_data, columns=[' REAGENT ID', 'REAGENT  NAME', 'TEST NAME', 'CURRENT STOCK', 'DAILY USAGE', 'RECORDER LEVEL', 'RESTOCK DATE', 'STOCK STATUS'])
df_reject = pd.DataFrame(rejection_data, columns=['REJECTION ID', 'SAMPLE ID', 'PATIENT NAME', 'DEPARTMENT', 'TEST NAME', 'DATE', 'REJECTION REASON', 'STATUS'])

output_file = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Generated_Full_Dummy_Data.xlsx'

with pd.ExcelWriter(output_file) as writer:
    df_sample.to_excel(writer, sheet_name='Sample ID', index=False)
    df_equip.to_excel(writer, sheet_name='Equipment ID', index=False)
    df_reagent.to_excel(writer, sheet_name='Reagent ID', index=False)
    df_reject.to_excel(writer, sheet_name='Rejection ID', index=False)

print(f"Data generation complete! Saved to {output_file}")
