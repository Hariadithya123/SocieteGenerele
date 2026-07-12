import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

print("Generating dummy data...")

num_rows = 15000

# Sample data attributes
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

# Start date for random generation
start_date = datetime(2025, 1, 1, 8, 0, 0)

data = []
for i in range(num_rows):
    sample_id = f"S{i+1:05d}"
    patient_name = f"Patient_{i+1}"
    dept = random.choice(departments)
    test = random.choice(tests[dept])
    
    # Collection Time: Random time within a year
    collection_time = start_date + timedelta(days=random.randint(0, 365), hours=random.randint(0, 8), minutes=random.randint(0, 59))
    
    # Processing Start Time: Usually 10 mins to 2 hours after collection
    processing_start = collection_time + timedelta(minutes=random.randint(10, 120))
    
    # Processing End Time: Usually 30 mins to 24 hours after start
    processing_end = processing_start + timedelta(minutes=random.randint(30, 1440))
    
    status = random.choices(statuses, weights=[0.8, 0.05, 0.1, 0.05])[0]
    
    if status == 'Completed':
        # Report Release Time: 10 mins to 5 hours after end
        report_release = processing_end + timedelta(minutes=random.randint(10, 300))
    elif status == 'Delayed':
        # Significant delay in release
        report_release = processing_end + timedelta(minutes=random.randint(1440, 5000))
    else:
        # Not released yet
        report_release = pd.NaT

    data.append([
        sample_id, patient_name, dept, test,
        collection_time.strftime('%Y-%m-%d %H:%M:%S'),
        processing_start.strftime('%Y-%m-%d %H:%M:%S'),
        processing_end.strftime('%Y-%m-%d %H:%M:%S'),
        report_release.strftime('%Y-%m-%d %H:%M:%S') if pd.notnull(report_release) else None,
        status
    ])

df = pd.DataFrame(data, columns=[
    'SAMPLE  ID', 'PATIENT NAME', 'DEPARTMENT', 'TEST NAME', 
    'COLLECTION TIME', 'PROCESSING START TIME', 'PROCESSING END TIME', 
    'REPORT RELEASE TIME', 'STATUS'
])

output_file = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Generated_Dummy_Data_15000.xlsx'
df.to_excel(output_file, index=False)

print(f"Data generation complete! Saved to {output_file}")
print("Shape:", df.shape)
print("Head:")
print(df.head())
