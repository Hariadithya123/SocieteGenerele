import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_absolute_error, r2_score
import joblib
from urllib.parse import quote_plus

# Database Connection
username = 'root'
password = quote_plus('Baala@1975')
host = 'localhost'
database = 'medical_lab_db'

print("Connecting to database to load data...")
engine = create_engine(f'mysql+pymysql://{username}:{password}@{host}/{database}')

# Load sample data
query = "SELECT * FROM sample_id WHERE STATUS IN ('Completed', 'Delayed')"
df = pd.read_sql(query, engine)

print(f"Loaded {len(df)} completed/delayed samples for training.")

# Data Preprocessing
df['COLLECTION TIME'] = pd.to_datetime(df['COLLECTION TIME'])
df['REPORT RELEASE TIME'] = pd.to_datetime(df['REPORT RELEASE TIME'])

# Calculate Target: Total Turnaround Time in minutes (from collection to release)
df['TAT_minutes'] = (df['REPORT RELEASE TIME'] - df['COLLECTION TIME']).dt.total_seconds() / 60.0

# Extract Features
df['collection_hour'] = df['COLLECTION TIME'].dt.hour
df['collection_dayofweek'] = df['COLLECTION TIME'].dt.dayofweek

# Define features and target
X = df[['DEPARTMENT', 'TEST NAME', 'collection_hour', 'collection_dayofweek']]
y = df['TAT_minutes']

print("Training Machine Learning Model (Random Forest Regressor)...")

# Define preprocessing for categorical features
categorical_features = ['DEPARTMENT', 'TEST NAME']
categorical_transformer = OneHotEncoder(handle_unknown='ignore')

preprocessor = ColumnTransformer(
    transformers=[
        ('cat', categorical_transformer, categorical_features)
    ], remainder='passthrough')

# Create a pipeline with preprocessing and model
model = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('regressor', RandomForestRegressor(n_estimators=100, random_state=42))
])

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Fit the model
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
mae = mean_absolute_error(y_test, y_pred)
r2 = r2_score(y_test, y_pred)

print(f"Model Training Complete!")
print(f"Mean Absolute Error: {mae:.2f} minutes")
print(f"R2 Score: {r2:.2f}")

# Save the model
model_filename = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/tat_prediction_model.pkl'
joblib.dump(model, model_filename)
print(f"Model saved successfully to {model_filename}")

# Example Prediction
print("\n--- Example Prediction ---")
sample_input = pd.DataFrame({
    'DEPARTMENT': ['Hematology'],
    'TEST NAME': ['Complete Blood Count'],
    'collection_hour': [9], # 9 AM
    'collection_dayofweek': [0] # Monday
})
predicted_tat = model.predict(sample_input)[0]
print(f"Predicted Turnaround Time for a Complete Blood Count (Hematology) at 9 AM on Monday: {predicted_tat:.2f} minutes")
