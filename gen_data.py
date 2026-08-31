import pandas as pd
import random
from datetime import datetime, timedelta
import csv

# Define possible values
user_roles = ['employee', 'manager', 'admin']
departments = ['IT', 'HR', 'Finance', 'Operations']

# Function to generate random timestamp within a range
def random_timestamp(start_date, end_date):
    time_delta = end_date - start_date
    random_seconds = random.randint(0, int(time_delta.total_seconds()))
    return start_date + timedelta(seconds=random_seconds)

# Generate data
data = []
start_date = datetime(2025, 3, 1)
end_date = datetime(2025, 3, 31)

for _ in range(7000):
    user_role = random.choice(user_roles)
    department = random.choice(departments)
    years_of_service = round(random.uniform(0.0, 10.0), 1)
    access_time = random_timestamp(start_date, end_date)
    access_attempts = random.randint(1, 10)
    last_login_time = access_time - timedelta(hours=random.randint(0, 48))
    login_frequency = round(random.uniform(0.1, 5.0), 1)

    # Logic for access_granted
    access_hour = access_time.hour
    time_diff_hours = (access_time - last_login_time).total_seconds() / 3600

    if user_role == 'admin':
        access_granted = 1
    elif access_attempts > 6:
        access_granted = 0
    elif 9 <= access_hour <= 17 and access_attempts <= 3 and 0.5 <= login_frequency <= 2.0:
        access_granted = 1
    elif department == 'IT' and years_of_service > 5 and access_attempts < 5:
        access_granted = 1
    elif access_hour < 9 or access_hour > 17 and user_role != 'admin' and department != 'IT':
        access_granted = 0
    elif login_frequency > 2.5 and access_attempts > 4:
        access_granted = 0
    elif time_diff_hours > 24 and access_attempts > 3:
        access_granted = 0
    else:
        access_granted = random.choice([0, 1])  # Edge cases

    data.append([
        user_role, department, years_of_service,
        access_time.strftime('%Y-%m-%d %H:%M:%S'),
        access_attempts,
        last_login_time.strftime('%Y-%m-%d %H:%M:%S'),
        login_frequency, access_granted
    ])

# Create DataFrame
df = pd.DataFrame(data, columns=[
    'user_role', 'department', 'years_of_service', 'access_time',
    'access_attempts', 'last_login_time', 'login_frequency', 'access_granted'
])

# Save to CSV
df.to_csv('access_data.csv', index=False, quoting=csv.QUOTE_ALL)
print("Generated 1000 rows and saved to 'access_data.csv'")